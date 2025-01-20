# Rust IP Flooder

<p align="center">
  <img src="assets/banner.webp" alt="IP Flooder Banner" width="600"/>
</p>

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/security-testing%20only-red.svg)](https://github.com/your-username/ip_flooder)

A high-performance, customizable network packet generator and testing tool written in Rust. Designed for network stress testing, security assessments, and protocol analysis.

> ⚠️ **Disclaimer**: This tool is for educational and testing purposes only. Use only on networks you own or have explicit permission to test.

## Features

- 🚀 High-performance packet generation
  - Multi-threaded architecture for maximum throughput
  - Configurable rate limiting and burst control
  - Optimized memory usage and zero-copy packet building
  - Hardware acceleration support where available

- 🔄 Comprehensive protocol support
  - TCP with customizable flags and options
  - UDP for stateless flooding
  - ICMP with various message types
  - Raw IP packet crafting
  - IPv4 support (IPv6 for future implementation)

- 🛡️ Advanced firewall evasion techniques
  - Packet fragmentation with customizable MTU
  - TTL manipulation and randomization
  - Source port rotation and randomization
  - IP address rotation and spoofing
  - Decoy scanning with multiple source IPs
  - Port knocking sequences

- 📊 Detailed monitoring and analysis
  - Real-time packet statistics and counters
  - Bandwidth utilization tracking
  - Response analysis and latency measurement
  - Failed packet detection
  - Interactive progress visualization

- 💾 Comprehensive packet capture
  - PCAP file generation and saving
  - Wireshark-compatible output
  - Custom packet filtering options
  - Timestamped packet records
  - Response packet capture

- 🎯 Fine-grained packet customization
  - Custom packet payloads and sizes
  - Protocol-specific header manipulation
  - Checksum calculation and verification
  - Time-to-live (TTL) control

- 🔧 Advanced configuration capabilities
  - Command-line interface (CLI)
  - Logging and debugging options

## Installation

### Prerequisites
- Rust 1.70 or higher
- Root/Administrator privileges
- Linux/Unix-based system

### Quick Start
#### Clone the repository
```
git clone https://github.com/jeninsutradhar/ip_flooder.git
```
```
cd ip_flooder
```
#### Build the project
````
cargo build --release
````
#### Run with sudo (required for raw sockets)
```
sudo ./target/release/ip_flooder
```


## Command Line Interface (CLI)

The tool provides an interactive CLI with two main commands:
- `s` or `send` - Start packet generation
- `e` or `exit` - Exit the program

### Basic Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| Source IP | Source IP address | 127.0.0.1 |
| Target IP | Target IP address | 127.0.0.1 |
| Protocol | ICMP, TCP, UDP, ARP | ICMP |
| TTL | Time to Live | 64 |
| Rate Limit | Packets per second | 10ms |
| Payload | Custom packet payload | "Hello..." |

### Advanced Features

#### Firewall Evasion Options
- Packet Fragmentation
- TTL Spoofing
- Port Rotation
- IP Rotation
- Decoy Scanning

#### Protocol-Specific Features

**TCP Options:**
### SYN Flood example
- Source IP: 192.168.1.100
- Protocol: tcp
- TCP Flags: SYN

**UDP Options:**
### UDP Flood example
- Protocol: udp
- UDP Port: 53
- Randomize: true

**ICMP Options:**
### ICMP Flood example
- Protocol: icmp
- ICMP Type: 8 (Echo Request)

## ## Advanced Usage

### Port Knocking Sequence
```
Enable port knocking: y
Knock Sequence: 7000,8000,9000
```
### IP Rotation Range
```
Enable IP rotation: y
IP Range: 192.168.1.1-192.168.1.254
```
### Custom Port Rotation
```
Enable port rotation: y
Ports: 80,443,8080,8443
```

## Performance Optimization

For maximum performance:

1. System Settings:
#### Increase system limits
```
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

2. Network Card Tuning:
#### Optimize network interface
```
sudo ethtool -C eth0 rx-usecs 0
sudo ethtool -C eth0 tx-usecs 0
```

## Detailed Configuration Guide

### Command Line Arguments (clap)

```bash
USAGE:
    ip_flooder [FLAGS] [OPTIONS] <COMMAND>

FLAGS:
    -h, --help              Prints help information
    -V, --version           Prints version information
    -v, --verbose          Enable verbose output
    -q, --quiet            Suppress all output except errors
    
OPTIONS:
    --config <FILE>        Use custom configuration file
    --log-level <LEVEL>    Set log level (debug|info|warn|error) [default: info]
    --output <FILE>        Write output to file
```

### Protocol-Specific Configuration

#### TCP Options
```bash
--tcp-flags <FLAGS>    Comma-separated list of TCP flags
                      Available flags: SYN,ACK,FIN,RST,PSH,URG,ECE,CWR
                      Example: --tcp-flags SYN,ACK

--tcp-window <SIZE>   TCP window size [default: 65535]
--tcp-mss <SIZE>      TCP maximum segment size
--tcp-urgent <PTR>    TCP urgent pointer
```

Example TCP SYN flood:
```bash
ip_flooder send \
    --source-ip 192.168.1.100 \
    --target-ip 192.168.1.1 \
    --protocol tcp \
    --tcp-flags SYN \
    --rate-limit 1000 \
    --rotate-ports
```

#### UDP Options
```bash
--udp-dest-port <PORT>     Destination port [default: 53]
--udp-payload-size <SIZE>  UDP payload size [default: 512]
--udp-checksum            Enable UDP checksum calculation
```

Example UDP flood with port rotation:
```bash
ip_flooder send \
    --protocol udp \
    --rotate-ports \
    --common-ports 53,123,161,1900 \
    --payload-size 1400
```

#### ICMP Options
```bash
--icmp-type <TYPE>     ICMP message type [default: 8]
                      Common types:
                      0 = Echo Reply
                      8 = Echo Request
                      3 = Destination Unreachable
                      11 = Time Exceeded

--icmp-code <CODE>    ICMP message code [default: 0]
```

Example ICMP flood with TTL spoofing:
```bash
ip_flooder send \
    --protocol icmp \
    --icmp-type 8 \
    --spoof-ttl \
    --fragment-packets
```

### Advanced Features Explained

#### Rate Limiting System
The rate limiting system works on three levels:

1. **Packet Level**
```bash
--rate-limit <MS>     Delay between packets in milliseconds
                     Lower = faster, but may overwhelm system
                     Recommended: 1-10ms for high-speed networks
```

2. **Burst Mode**
```bash
--burst-size <NUM>    Number of packets to send in each burst
--burst-delay <MS>    Delay between bursts in milliseconds
```

3. **Adaptive Rate**
```bash
--adaptive-rate       Automatically adjust rate based on system capacity
--max-rate <PPS>     Maximum packets per second
```

#### IP Rotation System

Three rotation modes available:

1. **Range-based Rotation**
```bash
--ip-rotation-range 192.168.1.1-192.168.1.254
Method: Sequential or Random (specified with --random-rotation)
```

2. **CIDR Block Rotation**
```bash
--ip-rotation-cidr 192.168.1.0/24
Covers entire subnet automatically
```

3. **List-based Rotation**
```bash
--ip-rotation-list file.txt
Format: One IP per line in file
```

#### Port Knocking Sequences

Port knocking can use different protocols for each knock:

```bash
# TCP Knock Sequence
--knock-sequence tcp:1234,udp:5678,tcp:9012

# With timing controls
--knock-delay 100    # Milliseconds between knocks
--knock-timeout 5000 # Maximum sequence time
```

Example complex knock sequence:
```bash
ip_flooder knock \
    --sequence tcp:7000,udp:8000,icmp:9000 \
    --knock-delay 200 \
    --retry-count 3
```

### Performance Tuning

#### System Optimization

1. **Network Stack Tuning**
```bash
# Increase socket buffer sizes
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216

# Increase maximum backlog
sudo sysctl -w net.core.netdev_max_backlog=250000

# Increase TCP limits
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=3240000
sudo sysctl -w net.ipv4.tcp_max_tw_buckets=1440000
```

2. **Process Priority**
```bash
# Run with higher priority
sudo nice -n -20 ./target/release/ip_flooder

# Set CPU affinity
taskset -c 0,1 ./target/release/ip_flooder
```

#### Memory Usage Optimization

```bash
# Configure memory limits
--buffer-size <SIZE>     Set packet buffer size
--max-memory <SIZE>      Set maximum memory usage
--prealloc-buffers       Pre-allocate packet buffers
```

### Real-world Examples

1. **Basic Network Stress Test**
```bash
sudo ./ip_flooder send \
    --target-ip 192.168.1.1 \
    --protocol tcp \
    --tcp-flags SYN \
    --rate-limit 1000 \
    --duration 60
```

2. **Advanced Evasion Test**
```bash
sudo ./ip_flooder send \
    --target-ip 192.168.1.1 \
    --rotate-ips \
    --ip-rotation-range 192.168.0.1-192.168.0.254 \
    --fragment-packets \
    --spoof-ttl \
    --rotate-ports \
    --protocol tcp \
    --tcp-flags SYN,ACK
```

3. **Mixed Protocol Flood**
```bash
sudo ./ip_flooder send \
    --target-ip 192.168.1.1 \
    --protocol mixed \
    --mixed-ratio "tcp=40,udp=40,icmp=20" \
    --rate-limit 100
```


## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```
   Error: Permission denied (os error 13)
   Solution: Run with sudo
   ```

2. **Socket Creation Failed**
   ```
   Error: Address already in use
   Solution: Wait for socket timeout or use different source port
   ```

3. **Rate Limiting**
   ```
   Error: Resource temporarily unavailable
   Solution: Decrease packet rate or increase system limits
   ```

### FAQ

**Q: Why am I getting "Operation not permitted"?**
- A: The tool requires root privileges. Run with `sudo`.

**Q: How to capture packets for analysis?**
- A: Enable PCAP output with the `--pcap-file` option.

**Q: What's the recommended rate limit?**
- A: Start with 10ms and adjust based on your network capacity.

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [pnet](https://github.com/libpnet/libpnet) - Low-level networking
- [clap](https://github.com/clap-rs/clap) - Command line argument parsing
- [colored](https://github.com/mackwic/colored) - Terminal colors

## Author

Jenin Sutradhar
- Email: jeninsutradhar@gmail.com
- GitHub: [@jenin-sutradhar](https://github.com/jenin-sutradhar)

---

<p align="center">
Made with ❤️ in Rust
</p>
