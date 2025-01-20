use super::PacketBuilder;
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpOperation, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct ArpPacketBuilder {
    pub source_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub ttl: u8,
}

impl ArpPacketBuilder {
    pub fn new(source_ip: Ipv4Addr, target_ip: Ipv4Addr, ttl: u8) -> Self {
        ArpPacketBuilder {
            source_ip,
            target_ip,
            ttl,
        }
    }
}

impl PacketBuilder for ArpPacketBuilder {
    const HEADER_SIZE: usize = 28; // ARP header size
    
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
        ip_header.set_source(self.source_ip);
        ip_header.set_destination(self.target_ip);
        let checksum = checksum(ip_header.packet(), 0);
        ip_header.set_checksum(checksum);
    }

    fn build_packet(&self, buffer: &mut [u8]) -> usize {
        const IPV4_HEADER_LEN: usize = 20;
        const ARP_PACKET_LEN: usize = 28;
        let total_len = (IPV4_HEADER_LEN + ARP_PACKET_LEN) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Hopopt, total_len);

        let mut arp_packet = MutableArpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create ARP packet");

        let target_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let source_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperation::new(1));
        arp_packet.set_sender_hw_addr(MacAddr::new(
            source_mac[0],
            source_mac[1],
            source_mac[2],
            source_mac[3],
            source_mac[4],
            source_mac[5],
        ));
        arp_packet.set_sender_proto_addr(self.source_ip);
        arp_packet.set_target_hw_addr(MacAddr::new(
            target_mac[0],
            target_mac[1],
            target_mac[2],
            target_mac[3],
            target_mac[4],
            target_mac[5],
        ));
        arp_packet.set_target_proto_addr(self.target_ip);

        IPV4_HEADER_LEN + ARP_PACKET_LEN
    }

    fn build_packet_optimized(&self, buffer: &mut [u8; 65535]) -> usize {
        // Similar to build_packet but optimized for fixed buffer
        const IPV4_HEADER_LEN: usize = 20;
        const ARP_PACKET_LEN: usize = 28;
        let total_len = (IPV4_HEADER_LEN + ARP_PACKET_LEN) as u16;

        self.build_ip_header(buffer, pnet::packet::ip::IpNextHeaderProtocols::Hopopt, total_len);

        let mut arp_packet = MutableArpPacket::new(&mut buffer[IPV4_HEADER_LEN..])
            .expect("Failed to create ARP packet");

        // Rest of the implementation same as build_packet
        let target_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let source_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperation::new(1));
        arp_packet.set_sender_hw_addr(MacAddr::new(
            source_mac[0], source_mac[1], source_mac[2],
            source_mac[3], source_mac[4], source_mac[5],
        ));
        arp_packet.set_sender_proto_addr(self.source_ip);
        arp_packet.set_target_hw_addr(MacAddr::new(
            target_mac[0], target_mac[1], target_mac[2],
            target_mac[3], target_mac[4], target_mac[5],
        ));
        arp_packet.set_target_proto_addr(self.target_ip);

        IPV4_HEADER_LEN + ARP_PACKET_LEN
    }
} 