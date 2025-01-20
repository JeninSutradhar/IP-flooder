mod cli;
mod constants;
mod packet_builders;
mod packet_generator;
mod protocol;

use colored::*;
use constants::*;
use log::{error, LevelFilter};
use packet_generator::PacketGenerator;
use protocol::ProtocolType;
use simplelog::*;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn print_banner() {
    println!("{}", r#"
╔══════════════════════════════════════════╗
║             IP FLOODER v1.0              ║
║         github.com/jeninsutradhar        ║
╚══════════════════════════════════════════╝"#.cyan());
}

fn prompt_input(prompt: &str, default: &str) -> String {
    let mut input = String::new();
    print!("{} {}: ", prompt.green(), format!("(default: {})", default).dimmed());
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    
    let input = input.trim();
    if input.is_empty() {
        default.to_string()
        } else {
        input.to_string()
    }
}

fn prompt_advanced_options() -> (bool, bool, bool, bool, bool, Option<String>) {
    println!("\n{}", "Advanced Options:".bold().blue());
    println!("╔════════════════════════════════════════════╗");
    
    let fragment_packets = prompt_input("Enable packet fragmentation? (y/N)", "n")
        .to_lowercase()
        .starts_with('y');
    
    let spoof_ttl = prompt_input("Enable TTL spoofing? (y/N)", "n")
        .to_lowercase()
        .starts_with('y');
    
    let rotate_ports = prompt_input("Enable port rotation? (y/N)", "n")
        .to_lowercase()
        .starts_with('y');
    
    let rotate_ips = prompt_input("Enable IP rotation? (y/N)", "n")
        .to_lowercase()
        .starts_with('y');
    
    let decoy_scan = prompt_input("Enable decoy scanning? (y/N)", "n")
        .to_lowercase()
        .starts_with('y');
    
    let ip_range = if rotate_ips {
        Some(prompt_input("IP rotation range (start_ip-end_ip)", ""))
    } else {
        None
    };

    println!("╚════════════════════════════════════════════╝");
    
    (fragment_packets, spoof_ttl, rotate_ports, rotate_ips, decoy_scan, ip_range)
}

fn get_common_ports() -> Vec<u16> {
    let default_ports = vec![80, 443, 53, 25, 110, 143, 993, 995];
    let custom_ports = prompt_input(
        "Enter custom ports (comma-separated) or press Enter for defaults",
        "80,443,53,25,110,143,993,995"
    );

    if custom_ports.trim().is_empty() {
        default_ports
    } else {
        custom_ports
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    }
}

fn main() {
    // Fix logger initialization
    if let Err(e) = TermLogger::init(
        LevelFilter::Info,
        Config::default(),  // Use default config instead
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ) {
        eprintln!("{}", format!("Logger initialization failed: {}", e).red());
        return;
    }

    print_banner();

    loop {
        println!("\n{}", "Available commands:".bold());
        println!("  {} - Send packets", "s".green());
        println!("  {} - Exit program", "e".red());
        
        print!("\n{}", "ip_flooder> ".green().bold());
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            error!("Failed to read command");
            continue;
        }

        match input.trim().to_lowercase().as_str() {
            "e" | "exit" => {
                println!("{}", "Exiting IP Flooder...".yellow());
                break;
            }
            "s" | "send" => {
                println!("\n{}", "Basic Configuration:".bold().green());
                println!("╔════════════════════════════════════════════╗");
                
                let source_ip = prompt_input("Source IP", "127.0.0.1");
                let target_ip = prompt_input("Target IP", "127.0.0.1");
                let protocol = prompt_input("Protocol (icmp/tcp/udp/arp/raw)", "icmp");
                let payload = prompt_input("Payload (default: Hello, this is a spoofed packet!)", "Hello, this is a spoofed packet!");
                let ttl = prompt_input("TTL (default: 64)", "64");
                let randomize = prompt_input("Randomize Source Ports (default: false, options: true or false)", "false");
                let rate_limit_ms = prompt_input("Rate Limit (default: 10)", "10");
                let pcap_file = prompt_input("Pcap File (optional)", "");
                let tcp_flags = prompt_input("TCP Flags (optional, default: SYN. Example: SYN,ACK,URG)", "");
                let icmp_type = prompt_input("ICMP Type (optional, default: 8)", "");
                let udp_dest_port = prompt_input("UDP Destination Port (optional, default: 53)", "");
                let timeout = prompt_input("Timeout (optional, in seconds)", "");
                let burst_size = prompt_input("Burst Size (optional, default: 0, to turn off burst)", "");
                let delay = prompt_input("Delay (optional, in ms)", "");
                let amplifier_server = prompt_input("Amplifier Server IP (optional)", "");
                let randomize_source = prompt_input("Randomize Source (optional, options: true or false)", "false");
                let randomize_delay = prompt_input("Randomize Delay (optional, options: true or false)", "false");

                // Improved error handling for IP parsing
                let source_ip = match Ipv4Addr::from_str(&source_ip) {
                    Ok(ip) => ip,
                    Err(_) => {
                        error!("Invalid source IP format. Using default: 127.0.0.1");
                        Ipv4Addr::new(127, 0, 0, 1)
                    }
                };

                let target_ip = match Ipv4Addr::from_str(&target_ip) {
                    Ok(ip) => ip,
                    Err(_) => {
                        error!("Invalid target IP format. Using default: 127.0.0.1");
                        Ipv4Addr::new(127, 0, 0, 1)
                    }
                };

                // Fix protocol parsing
                let protocol = match ProtocolType::from_str(&protocol) {
                    Ok(p) => p,
                    Err(_) => {
                        error!("Invalid protocol. Using default: ICMP");
                        ProtocolType::ICMP
                    }
                };

                // Fix payload handling
                let payload = if protocol == ProtocolType::ARP {
                    String::new()
                } else {
                    payload.trim().to_string()
                };

                // Fix numeric parsing
                let ttl = ttl.trim().parse().unwrap_or(DEFAULT_TTL);
                let randomize = randomize.trim().parse().unwrap_or(false);
                let rate_limit_ms = rate_limit_ms.trim().parse().unwrap_or(DEFAULT_RATE_LIMIT);

                // Fix optional values
                let pcap_file = if pcap_file.trim().is_empty() {
                    None
                } else {
                    Some(pcap_file.trim().to_string())
                };

                let tcp_flags = if tcp_flags.trim().is_empty() {
                    0
                } else {
                    PacketGenerator::parse_tcp_flags(tcp_flags.trim())
                };

                let icmp_type = icmp_type.trim().parse::<u8>().ok();
                let udp_dest_port = udp_dest_port.trim().parse::<u16>().ok();
                let timeout = timeout.trim().parse::<u64>().ok();
                let burst_size = burst_size.trim().parse::<usize>().ok();
                let delay = delay.trim().parse::<u64>().ok();
                
                let amplifier_server = if amplifier_server.trim().is_empty() {
                    None
                } else {
                    Ipv4Addr::from_str(amplifier_server.trim()).ok()
                };

                let randomize_source = randomize_source.trim().parse().unwrap_or(false);
                let randomize_delay = randomize_delay.trim().parse().unwrap_or(false);

                // Add advanced options prompt
                let (fragment_packets, spoof_ttl, rotate_ports, rotate_ips, decoy_scan, ip_range) = 
                    prompt_advanced_options();

                let common_ports = if rotate_ports {
                    get_common_ports()
                } else {
                    Vec::new()
                };

                let ip_rotation_range = if let Some(range) = ip_range {
                    if range.contains('-') {
                        let parts: Vec<&str> = range.split('-').collect();
                        if parts.len() == 2 {
                            match (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<Ipv4Addr>()) {
                                (Ok(start), Ok(end)) => Some((start, end)),
                                _ => None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Create configuration summary
                println!("\n{}", "Configuration Summary:".bold());
                println!("╔═══════════════════╦════════════════════╗");
                println!("║ Basic Settings    ║ Advanced Settings  ║");
                println!("╠═══════════════════╬════════════════════╣");
                println!("║ Source IP: {}     ║ Fragmentation: {} ║", 
                    source_ip.to_string().green(), 
                    if fragment_packets { "ON".green() } else { "OFF".red() }
                );
                println!("║ Target IP: {}     ║ TTL Spoofing: {}  ║", 
                    target_ip.to_string().green(),
                    if spoof_ttl { "ON".green() } else { "OFF".red() }
                );
                println!("║ Protocol: {}      ║ Port Rotation: {} ║", 
                    protocol.to_string().green(),
                    if rotate_ports { "ON".green() } else { "OFF".red() }
                );
                println!("╚═══════════════════╩════════════════════╝");

                // Create packet generator with all options
                let packet_generator = PacketGenerator::new(
                    source_ip,
                    target_ip,
                    protocol,
                    payload.into_bytes(),
                    ttl,
                    randomize,
                    rate_limit_ms,
                    pcap_file,
                    tcp_flags,
                    icmp_type.unwrap_or(8),
                    udp_dest_port.unwrap_or(DEFAULT_PORT),
                    burst_size.unwrap_or(0),
                    delay.unwrap_or(0),
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
                );

                println!("\n{}", "Starting attack...".bold().yellow());
                packet_generator.start_packet_flood(timeout);
                std::thread::park();
            }
            _ => {
                println!("{}", "Invalid command. Use 's' to send or 'e' to exit.".red());
            }
        }
    }
}
