use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
    
    #[arg(long, help = "Enable packet fragmentation")]
    fragment_packets: bool,
    
    #[arg(long, help = "Randomize TTL values")]
    spoof_ttl: bool,
    
    #[arg(long, help = "Rotate source ports")]
    rotate_ports: bool,
    
    #[arg(long, help = "Enable IP rotation")]
    rotate_ips: bool,
    
    #[arg(long, help = "Send decoy packets")]
    decoy_scan: bool,
    
    #[arg(long, help = "IP range for rotation (format: start_ip-end_ip)")]
    ip_rotation_range: Option<String>,
    
    #[arg(long, help = "Enable port knocking sequence")]
    port_knock: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Send {
        #[arg(short = 's', long, default_value = "127.0.0.1", help = "Source IP address")]
        source_ip: String,
        
        #[arg(short = 't', long, default_value = "127.0.0.1", help = "Target IP address")]
        target_ip: String,
        
        #[arg(short = 'r', long, default_value = "icmp", help = "Protocol to use (icmp, tcp, udp, arp)")]
        protocol: String,
        
        #[arg(short = 'p', long, default_value = "Hello, this is a spoofed packet!", help = "Payload to send")]
        payload: String,
        
        #[arg(long, default_value_t = 64, help = "Time-to-live for IP packets")]
        ttl: u8,
        
        #[arg(long, default_value_t = false, help = "Randomize source ports for TCP and UDP packets")]
        randomize: bool,
        
        #[arg(long, default_value_t = 10, help = "Rate limit in milliseconds")]
        rate_limit_ms: u64,
        
        #[arg(long, help = "Save generated packets to pcap file")]
        pcap_file: Option<String>,
        
        #[arg(long, help = "TCP flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)")]
        tcp_flags: Option<String>,
        
        #[arg(long, help = "ICMP type (EchoRequest = 8, EchoReply = 0)")]
        icmp_type: Option<u8>,
        
        #[arg(long, help = "UDP destination port")]
        udp_dest_port: Option<u16>,
        
        #[arg(long, help = "Timeout for packet sending in seconds")]
        timeout: Option<u64>,
        
        #[arg(long, help = "Number of packets in burst")]
        burst_size: Option<usize>,
        
        #[arg(long, help = "Delay between bursts in ms")]
        delay: Option<u64>,
        
        #[arg(long, help = "Set a public server to be the amplifier")]
        amplifier_server: Option<String>,
        
        #[arg(long, help = "Set to true to randomize the source ip")]
        randomize_source: bool,
        
        #[arg(long, help = "Set to true to randomize the delay")]
        randomize_delay: bool,
    },
} 