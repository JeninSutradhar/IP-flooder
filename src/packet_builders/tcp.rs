use super::PacketBuilder;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use colored::Colorize;
use pnet::packet::MutablePacket;
use pnet::util::checksum;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct TcpPacketBuilder {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub tcp_flags: u16,
    pub payload: Vec<u8>,
    pub randomize: bool,
    pub ttl: u8,
    pub amplifier_server: Option<Ipv4Addr>,
}

impl TcpPacketBuilder {
    pub fn new(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        tcp_flags: u16,
        payload: Vec<u8>,
        randomize: bool,
        ttl: u8,
        amplifier_server: Option<Ipv4Addr>,
    ) -> Self {
        TcpPacketBuilder {
            source_ip,
            target_ip,
            tcp_flags,
            payload,
            randomize,
            ttl,
            amplifier_server,
        }
    }

    pub fn build_fragmented_packet(&self, buffer: &mut [u8]) -> usize {
        const IPV4_HEADER_LEN: usize = 20;
        const FRAGMENT_SIZE: usize = 576; // Common MTU size
        
        let total_size = IPV4_HEADER_LEN + self.payload.len();
        let mut offset = 0;
        let mut fragments = Vec::new();

        while offset < total_size {
            let fragment_data = &self.payload[offset..std::cmp::min(offset + FRAGMENT_SIZE, total_size)];
            let mut fragment = vec![0u8; IPV4_HEADER_LEN + fragment_data.len()];
            
            // Set IP flags for fragmentation
            let mut ip_header = MutableIpv4Packet::new(&mut fragment).unwrap();
            ip_header.set_flags(0b010); // More fragments flag
            ip_header.set_fragment_offset((offset / 8) as u16);
            
            // Copy fragment data
            fragment[IPV4_HEADER_LEN..].copy_from_slice(fragment_data);
            fragments.push(fragment);
            
            offset += FRAGMENT_SIZE;
        }

        // Last fragment
        if let Some(last) = fragments.last_mut() {
            let mut ip_header = MutableIpv4Packet::new(last).unwrap();
            ip_header.set_flags(0); // No more fragments
        }

        // Combine fragments
        let mut total_len = 0;
        for fragment in fragments {
            buffer[total_len..total_len + fragment.len()].copy_from_slice(&fragment);
            total_len += fragment.len();
        }

        total_len
    }
}

impl PacketBuilder for TcpPacketBuilder {
    const HEADER_SIZE: usize = 20; // TCP header size
    
    fn build_ip_header(&self, buffer: &mut [u8], protocol: IpNextHeaderProtocol, total_len: u16) {
        let mut ip_header = MutableIpv4Packet::new(buffer).expect("Failed to create IPv4 header");
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_dscp(0);
        ip_header.set_ecn(0);
        ip_header.set_total_length(total_len);
        ip_header.set_identification(rand::random());
        ip_header.set_flags(0);
        ip_header.set_fragment_offset(0);
        ip_header.set_ttl(self.ttl);
        ip_header.set_next_level_protocol(protocol);
        match self.amplifier_server {
            Some(ip) => ip_header.set_source(ip),
            None => ip_header.set_source(self.source_ip),
        }
        ip_header.set_destination(self.target_ip);
        let checksum = checksum(ip_header.packet(), 0);
        ip_header.set_checksum(checksum);
    }

    fn build_packet(&self, buffer: &mut [u8]) -> usize {
        const IPV4_HEADER_LEN: usize = 20;
        let tcp_len = 20 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + tcp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Tcp, total_len);

        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create TCP packet");

        let src_port = if self.randomize {
            rand::random::<u16>()
        } else {
            12345
        };
        let dest_port = 80;

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(rand::random());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(self.tcp_flags as u8);
        tcp_packet.set_window(65535);
        tcp_packet.set_urgent_ptr(0);

        tcp_packet.payload_mut()[..self.payload.len()].copy_from_slice(&self.payload);

        let pseudo_header_len = 12;
        let mut pseudo_header = Vec::with_capacity(pseudo_header_len);
        pseudo_header.extend_from_slice(&self.source_ip.octets());
        pseudo_header.extend_from_slice(&self.target_ip.octets());
        pseudo_header.push(0);
        pseudo_header.push(pnet::packet::ip::IpNextHeaderProtocols::Tcp.0);
        pseudo_header.extend_from_slice(&(tcp_len as u16).to_be_bytes());

        let checksum = checksum(tcp_packet.packet(), pseudo_header.len());
        tcp_packet.set_checksum(checksum);

        IPV4_HEADER_LEN + tcp_len
    }

    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize {
        // Implementation similar to build_packet but optimized for fixed buffer
        const IPV4_HEADER_LEN: usize = 20;
        let tcp_len = 20 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + tcp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Tcp, total_len);
        // Rest of implementation same as build_packet...
        IPV4_HEADER_LEN + tcp_len
    }
} 