use pnet::packet::ip::IpNextHeaderProtocol;

pub mod arp;
pub mod icmp;
pub mod raw;
pub mod tcp;
pub mod udp;

pub use arp::ArpPacketBuilder;
pub use icmp::IcmpPacketBuilder;
pub use raw::RawPacketBuilder;
pub use tcp::TcpPacketBuilder;
pub use udp::UdpPacketBuilder;

pub trait PacketBuilder {
    const HEADER_SIZE: usize;
    
    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize;
    
    // Keep old methods for compatibility
    fn build_ip_header(&self, buffer: &mut [u8], protocol: IpNextHeaderProtocol, total_len: u16);
    fn build_packet(&self, buffer: &mut [u8]) -> usize;
} 