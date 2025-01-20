use super::PacketBuilder;
use colored::Colorize;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct RawPacketBuilder {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub amplifier_server: Option<Ipv4Addr>,
}

impl RawPacketBuilder {
    pub fn new(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        payload: Vec<u8>,
        ttl: u8,
        amplifier_server: Option<Ipv4Addr>,
    ) -> Self {
        RawPacketBuilder {
            source_ip,
            target_ip,
            payload,
            ttl,
            amplifier_server,
        }
    }
}

impl PacketBuilder for RawPacketBuilder {
    const HEADER_SIZE: usize = 0; // RAW has no additional header
    
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
        let total_len = (IPV4_HEADER_LEN + self.payload.len()) as u16;

        self.build_ip_header(
            buffer,
            pnet::packet::ip::IpNextHeaderProtocol::new(255),
            total_len,
        );

        buffer[IPV4_HEADER_LEN..IPV4_HEADER_LEN + self.payload.len()]
            .copy_from_slice(&self.payload);

        IPV4_HEADER_LEN + self.payload.len()
    }

    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize {
        // Implementation similar to build_packet but optimized for fixed buffer
        const IPV4_HEADER_LEN: usize = 20;
        let total_len = (IPV4_HEADER_LEN + self.payload.len()) as u16;
        // Rest of implementation...
        IPV4_HEADER_LEN + self.payload.len()
    }
} 