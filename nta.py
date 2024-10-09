import argparse
import logging
import pyshark
import psutil
from scapy.all import sniff, wrpcap

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketAnalyzer:
    def __init__(self):
        self.captured_packets = []

    def packet_callback(self, packet):
        self.captured_packets.append(packet)
        print(packet.summary())

    def capture_packets(self, interface="eth0", count=100, filter=""):
        logging.info(f"Starting packet capture on {interface} with filter {filter}")
        try:
            packets = sniff(iface=interface, count=count, filter=filter, prn=self.packet_callback)
            wrpcap("captured_packets.pcap", packets)
            logging.info(f"Packet capture complete. {len(packets)} packets captured.")
        except Exception as e:
            logging.error(f"Error capturing packets: {e}")

    def analyze_packets(self, pcap_file):
        try:
            cap = pyshark.FileCapture(pcap_file)
            for packet in cap:
                print(f"Packet: {packet}")
                print(f"Source: {packet.ip.src}, Destination: {packet.ip.dst}")
        except Exception as e:
            logging.error(f"Error analyzing packets: {e}")

    def list_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                print(f"Interface: {interface}")
                for addr in addrs:
                    print(f"  Address: {addr.address}")
        except Exception as e:
            logging.error(f"Error listing network interfaces: {e}")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer Tool")

    parser.add_argument('-i', '--interface', type=str, help="Network interface to capture packets from")
    parser.add_argument('-p', '--protocol', type=str, help="Protocol to filter (e.g., tcp, udp, http)")
    parser.add_argument('-c', '--count', type=int, default=100, help="Number of packets to capture")
    parser.add_argument('-o', '--output', type=str, default="captured_packets.pcap", help="Output file for captured packets")
    parser.add_argument('--list-interfaces', action='store_true', help="List available network interfaces")

    args = parser.parse_args()

    analyzer = PacketAnalyzer()

    if args.list_interfaces:
        logging.info("Listing Network Interfaces:")
        analyzer.list_network_interfaces()
        return

    if args.interface and args.protocol and args.count:
        logging.info(f"Capturing Packets on Interface: {args.interface}, Protocol: {args.protocol}, Count: {args.count}")
        analyzer.capture_packets(interface=args.interface, count=args.count, filter=args.protocol)
        logging.info(f"Packets captured and saved to {args.output}")

    logging.info("Execution complete. Here are the results:")
    total_packets = len(analyzer.captured_packets)
    protocols = set(packet.payload.name for packet in analyzer.captured_packets)
    logging.info(f"Total Packets Captured: {total_packets}")
    logging.info(f"Protocols Analyzed: {', '.join(protocols)}")

if __name__ == "__main__":
    main()
