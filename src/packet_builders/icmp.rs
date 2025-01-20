use super::PacketBuilder;
use pnet::packet::icmp::{echo_reply::MutableEchoReplyPacket, echo_request::MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::packet::MutablePacket;
use pnet::util::checksum;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct IcmpPacketBuilder {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub icmp_type: u8,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub amplifier_server: Option<Ipv4Addr>,
}

impl IcmpPacketBuilder {
    pub fn new(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        icmp_type: u8,
        payload: Vec<u8>,
        ttl: u8,
        amplifier_server: Option<Ipv4Addr>,
    ) -> Self {
        IcmpPacketBuilder {
            source_ip,
            target_ip,
            icmp_type,
            payload,
            ttl,
            amplifier_server,
        }
    }
}

impl PacketBuilder for IcmpPacketBuilder {
    const HEADER_SIZE: usize = 8; // ICMP header size
    
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
        let icmp_len = 8 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + icmp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Icmp, total_len);

        let mut icmp_packet = MutableIcmpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create ICMP packet");
        icmp_packet.set_icmp_type(IcmpType(self.icmp_type));
        icmp_packet.set_icmp_code(IcmpCode(0));

        match self.icmp_type {
            0 => {
                let mut echo_reply = MutableEchoReplyPacket::new(icmp_packet.packet_mut()).unwrap();
                echo_reply.set_identifier(rand::random());
                echo_reply.set_sequence_number(1);
            }
            8 => {
                let mut echo_request = MutableEchoRequestPacket::new(icmp_packet.packet_mut()).unwrap();
                echo_request.set_identifier(rand::random());
                echo_request.set_sequence_number(1);
            }
            _ => {}
        }

        icmp_packet.payload_mut()[..self.payload.len()].copy_from_slice(&self.payload);
        let checksum = checksum(icmp_packet.packet(), 0);
        icmp_packet.set_checksum(checksum);

        IPV4_HEADER_LEN + icmp_len
    }

    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize {
        const IPV4_HEADER_LEN: usize = 20;
        let icmp_len = 8 + self.payload.len();
        let total_len = (IPV4_HEADER_LEN + icmp_len) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Icmp, total_len);

        let mut icmp_packet = MutableIcmpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create ICMP packet");
            
        icmp_packet.set_icmp_type(IcmpType(self.icmp_type));
        icmp_packet.set_icmp_code(IcmpCode(0));

        match self.icmp_type {
            0 => {
                let mut echo_reply = MutableEchoReplyPacket::new(icmp_packet.packet_mut()).unwrap();
                echo_reply.set_identifier(rand::random());
                echo_reply.set_sequence_number(1);
            }
            8 => {
                let mut echo_request = MutableEchoRequestPacket::new(icmp_packet.packet_mut()).unwrap();
                echo_request.set_identifier(rand::random());
                echo_request.set_sequence_number(1);
            }
            _ => {}
        }

        icmp_packet.payload_mut()[..self.payload.len()].copy_from_slice(&self.payload);
        let checksum = checksum(icmp_packet.packet(), 0);
        icmp_packet.set_checksum(checksum);

        IPV4_HEADER_LEN + icmp_len
    }
} 