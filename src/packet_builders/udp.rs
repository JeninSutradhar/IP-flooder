use super::PacketBuilder;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use pnet::packet::MutablePacket;
use pnet::util::checksum;
use colored::Colorize;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct UdpPacketBuilder {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub payload: Vec<u8>,
    pub randomize: bool,
    pub udp_dest_port: u16,
    pub ttl: u8,
    pub amplifier_server: Option<Ipv4Addr>,
}

impl UdpPacketBuilder {
    pub fn new(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        udp_dest_port: u16,
        payload: Vec<u8>,
        randomize: bool,
        ttl: u8,
        amplifier_server: Option<Ipv4Addr>,
    ) -> Self {
        UdpPacketBuilder {
            source_ip,
            target_ip,
            udp_dest_port,
            payload,
            randomize,
            ttl,
            amplifier_server,
        }
    }
}

impl PacketBuilder for UdpPacketBuilder {
    const HEADER_SIZE: usize = 8; // UDP header size
    
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
        let udp_len = 8 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + udp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Udp, total_len);

        let mut udp_packet = MutableUdpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create UDP packet");

        let src_port = if self.randomize {
            rand::random::<u16>()
        } else {
            12345
        };

        udp_packet.set_source(src_port);
        udp_packet.set_destination(self.udp_dest_port);
        udp_packet.set_length(udp_len as u16);

        udp_packet.payload_mut()[..self.payload.len()].copy_from_slice(&self.payload);

        let pseudo_header_len = 12;
        let mut pseudo_header = Vec::with_capacity(pseudo_header_len);
        pseudo_header.extend_from_slice(&self.source_ip.octets());
        pseudo_header.extend_from_slice(&self.target_ip.octets());
        pseudo_header.push(0);
        pseudo_header.push(pnet::packet::ip::IpNextHeaderProtocols::Udp.0);
        pseudo_header.extend_from_slice(&(udp_len as u16).to_be_bytes());

        let checksum = checksum(udp_packet.packet(), pseudo_header.len());
        udp_packet.set_checksum(checksum);

        IPV4_HEADER_LEN + udp_len
    }

    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize {
        // Implementation similar to build_packet but optimized for fixed buffer
        const IPV4_HEADER_LEN: usize = 20;
        let udp_len = 8 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + udp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Udp, total_len);

        let mut udp_packet = MutableUdpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create UDP packet");

        let src_port = if self.randomize {
            rand::random::<u16>()
        } else {
            12345
        };

        udp_packet.set_source(src_port);
        udp_packet.set_destination(self.udp_dest_port);
        udp_packet.set_length(udp_len as u16);

        udp_packet.payload_mut()[..self.payload.len()].copy_from_slice(&self.payload);

        let pseudo_header_len = 12;
        let mut pseudo_header = Vec::with_capacity(pseudo_header_len);
        pseudo_header.extend_from_slice(&self.source_ip.octets());
        pseudo_header.extend_from_slice(&self.target_ip.octets());
        pseudo_header.push(0);
        pseudo_header.push(pnet::packet::ip::IpNextHeaderProtocols::Udp.0);
        pseudo_header.extend_from_slice(&(udp_len as u16).to_be_bytes());

        let checksum = checksum(udp_packet.packet(), pseudo_header.len());
        udp_packet.set_checksum(checksum);

        IPV4_HEADER_LEN + udp_len
    }
} 