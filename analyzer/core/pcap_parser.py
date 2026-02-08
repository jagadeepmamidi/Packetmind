"""
PCAP Parser - Your first packet analyzer!

This module teaches you how network packets are structured by parsing
PCAP files and extracting protocol information.

Learning objectives:
- Understand how packets are layered (Ethernet → IP → TCP/UDP → Application)
- See real TCP handshakes (SYN, SYN-ACK, ACK)
- Parse DNS queries and HTTP requests
- Extract source/destination IPs and ports
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
from typing import Dict, List, Any
from pathlib import Path
import json


class PacketParser:
    """Parse PCAP files and extract meaningful information"""
    
    def __init__(self, pcap_file: str):
        """
        Initialize parser with a PCAP file
        
        Args:
            pcap_file: Path to .pcap file
        """
        self.pcap_file = Path(pcap_file)
        self.packets = None
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'dns_queries': 0,
            'http_requests': 0,
            'unique_ips': set(),
            'unique_ports': set()
        }
    
    def load(self):
        """Load PCAP file into memory"""
        print(f"📂 Loading PCAP file: {self.pcap_file}")
        self.packets = rdpcap(str(self.pcap_file))
        self.stats['total_packets'] = len(self.packets)
        print(f"✅ Loaded {self.stats['total_packets']} packets")
    
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """
        Analyze a single packet and extract information
        
        This is where you learn how packets are structured!
        """
        info = {
            'layers': [],
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'payload_size': 0,
            'flags': None
        }
        
        # Layer 3: IP (Internet Protocol)
        if IP in packet:
            info['layers'].append('IP')
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto  # 6=TCP, 17=UDP
            
            # Track unique IPs
            self.stats['unique_ips'].add(packet[IP].src)
            self.stats['unique_ips'].add(packet[IP].dst)
        
        # Layer 4: TCP (Transmission Control Protocol)
        if TCP in packet:
            info['layers'].append('TCP')
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = self._parse_tcp_flags(packet[TCP])
            
            self.stats['tcp_packets'] += 1
            self.stats['unique_ports'].add(packet[TCP].sport)
            self.stats['unique_ports'].add(packet[TCP].dport)
            
            # Check for HTTP (port 80 or 8080)
            if packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080]:
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                        info['layers'].append('HTTP')
                        info['http_method'] = payload.split()[0]
                        self.stats['http_requests'] += 1
        
        # Layer 4: UDP (User Datagram Protocol)
        if UDP in packet:
            info['layers'].append('UDP')
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            
            self.stats['udp_packets'] += 1
            self.stats['unique_ports'].add(packet[UDP].sport)
            self.stats['unique_ports'].add(packet[UDP].dport)
        
        # Layer 7: DNS (Domain Name System)
        if DNS in packet:
            info['layers'].append('DNS')
            
            # DNS Query
            if DNSQR in packet:
                info['dns_query'] = packet[DNSQR].qname.decode('utf-8')
                self.stats['dns_queries'] += 1
            
            # DNS Response
            if DNSRR in packet:
                info['dns_response'] = packet[DNSRR].rdata
        
        # Payload size
        if Raw in packet:
            info['payload_size'] = len(packet[Raw].load)
        
        return info
    
    def _parse_tcp_flags(self, tcp_layer) -> str:
        """
        Parse TCP flags into human-readable format
        
        TCP Flags (the cool part!):
        - S (SYN): Start connection
        - A (ACK): Acknowledge
        - F (FIN): Finish connection
        - R (RST): Reset connection
        - P (PSH): Push data immediately
        """
        flags = []
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.U: flags.append('URG')
        
        return '|'.join(flags) if flags else 'NONE'
    
    def analyze_all(self) -> List[Dict[str, Any]]:
        """Analyze all packets in the PCAP file"""
        if self.packets is None:
            self.load()
        
        print(f"\n🔍 Analyzing {len(self.packets)} packets...\n")
        
        results = []
        for i, packet in enumerate(self.packets, 1):
            info = self.analyze_packet(packet)
            info['packet_num'] = i
            results.append(info)
            
            # Print first 10 packets for learning
            if i <= 10:
                self._print_packet_info(info)
        
        return results
    
    def _print_packet_info(self, info: Dict[str, Any]):
        """Pretty print packet information"""
        layers = ' → '.join(info['layers'])
        print(f"Packet #{info['packet_num']}: {layers}")
        
        if info['src_ip']:
            print(f"  📍 {info['src_ip']}:{info['src_port']} → {info['dst_ip']}:{info['dst_port']}")
        
        if info['flags']:
            print(f"  🚩 TCP Flags: {info['flags']}")
        
        if 'dns_query' in info:
            print(f"  🌐 DNS Query: {info['dns_query']}")
        
        if 'http_method' in info:
            print(f"  🌍 HTTP {info['http_method']} request")
        
        if info['payload_size'] > 0:
            print(f"  📦 Payload: {info['payload_size']} bytes")
        
        print()
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("📊 PCAP ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Packets:     {self.stats['total_packets']}")
        print(f"TCP Packets:       {self.stats['tcp_packets']}")
        print(f"UDP Packets:       {self.stats['udp_packets']}")
        print(f"DNS Queries:       {self.stats['dns_queries']}")
        print(f"HTTP Requests:     {self.stats['http_requests']}")
        print(f"Unique IPs:        {len(self.stats['unique_ips'])}")
        print(f"Unique Ports:      {len(self.stats['unique_ports'])}")
        print("="*60)
        
        # Show top 5 IPs
        if self.stats['unique_ips']:
            print("\n🌐 Top IPs:")
            for ip in list(self.stats['unique_ips'])[:5]:
                print(f"  - {ip}")
    
    def export_json(self, output_file: str, results: List[Dict[str, Any]]):
        """Export results to JSON"""
        # Convert sets to lists for JSON serialization
        stats_copy = self.stats.copy()
        stats_copy['unique_ips'] = list(stats_copy['unique_ips'])
        stats_copy['unique_ports'] = list(stats_copy['unique_ports'])
        
        output = {
            'pcap_file': str(self.pcap_file),
            'stats': stats_copy,
            'packets': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results exported to: {output_file}")


def main():
    """
    Example usage - this is what you'll run!
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_parser.py <pcap_file>")
        print("\nExample:")
        print("  python pcap_parser.py /data/samples/capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Create parser
    parser = PacketParser(pcap_file)
    
    # Analyze packets
    results = parser.analyze_all()
    
    # Print summary
    parser.print_summary()
    
    # Export to JSON
    output_file = pcap_file.replace('.pcap', '_analysis.json')
    parser.export_json(output_file, results)


if __name__ == '__main__':
    main()
