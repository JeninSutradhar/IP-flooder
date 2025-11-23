use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum FlooderError {
    SocketError(std::io::Error),
    PacketBuildError(String),
    PermissionDenied,
    InvalidProtocol(String),
    InvalidAddress(String),
    PcapError(String),
}

impl fmt::Display for FlooderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FlooderError::SocketError(e) => write!(f, "Socket error: {}", e),
            FlooderError::PacketBuildError(msg) => write!(f, "Packet build error: {}", msg),
            FlooderError::PermissionDenied => write!(f, "Permission denied. Please run with sudo"),
            FlooderError::InvalidProtocol(p) => write!(f, "Invalid protocol: {}", p),
            FlooderError::InvalidAddress(addr) => write!(f, "Invalid address: {}", addr),
            FlooderError::PcapError(msg) => write!(f, "PCAP Error: {}", msg),
        }
    }
}

impl Error for FlooderError {} 
