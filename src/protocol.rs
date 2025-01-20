use std::str::FromStr;
use std::fmt;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ProtocolType {
    ICMP,
    TCP,
    UDP,
    ARP,
    RAW,
}

impl FromStr for ProtocolType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "icmp" => Ok(ProtocolType::ICMP),
            "tcp" => Ok(ProtocolType::TCP),
            "udp" => Ok(ProtocolType::UDP),
            "arp" => Ok(ProtocolType::ARP),
            "raw" => Ok(ProtocolType::RAW),
            _ => Err(()),
        }
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)  // Uses the Debug implementation
    }
} 