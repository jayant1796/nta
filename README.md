# Network Traffic Analyzer (NTA)

A powerful Python-based tool for capturing and analyzing network traffic in real-time. The **Network Traffic Analyzer (NTA)** allows you to capture packets on a specific network interface, apply protocol filters, and save the captured traffic for later analysis in `.pcap` format.

## Features

- **Real-time Packet Capture**: Capture packets from any network interface.
- **Protocol Filtering**: Filter captured traffic by protocols (e.g., TCP, UDP, HTTP).
- **Save Captures**: Store captured packets in `.pcap` format for future use.
- **Network Interface Discovery**: List available network interfaces on the system.
- **Packet Analysis**: Analyze saved `.pcap` files to extract packet-level information.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)

---

## Installation

### Prerequisites

- **Python 3.x** is required to run this project.
- The required Python libraries are listed in the `requirements.txt` file.

### Installing Dependencies

To install the necessary dependencies, run the following command:

      bash
      pip install -r requirements.txt

## Dependencies

The main dependencies include:

- **pyshark**: A Python wrapper for tshark, used for packet analysis.
- **psutil**: Provides access to system and network interface details.
- **scapy**: A powerful packet manipulation tool.

## Usage

The NTA tool provides several command-line options to capture packets, filter traffic, and analyze network interfaces.

### Command-Line Options

| Option                   | Description                                                  |
|--------------------------|--------------------------------------------------------------|
| `-i`, `--interface`      | Specify the network interface for capturing packets.         |
| `-p`, `--protocol`       | Filter packets by protocol (e.g., `tcp`, `udp`, `http`).     |
| `-c`, `--count`          | Number of packets to capture (default: 100).                 |
| `-o`, `--output`         | File to save captured packets (default: `captured_packets.pcap`). |
| `--list-interfaces`      | Display available network interfaces.                        |

### Basic Commands

1. **List Network Interfaces**:
   ```bash
   python3 nta.py --list-interfaces

2. Capture Packets on a specific interface, filter by protocol, and save to a .pcap file:

    ```bash
   python3 nta.py -i <interface> -p <protocol> -c <count> -o <output_file.pcap>
3. Analyze Captured Packets from a .pcap file:

   ```bash
   python3 nta.py --analyze <pcap_file>
