"""
Test script to demonstrate the PCAP parser

This script creates a sample PCAP file with various packet types
so you can see how the parser works!
"""

from scapy.all import *
import os


def create_sample_pcap():
    """
    Create a sample PCAP file with different packet types
    
    This teaches you how packets are constructed!
    """
    packets = []
    
    print("🔨 Creating sample network traffic...\n")
    
    # 1. TCP Three-Way Handshake (SYN → SYN-ACK → ACK)
    print("1️⃣  Creating TCP handshake (the famous SYN-SYN/ACK-ACK)")
    
    # SYN: Client initiates connection
    syn = IP(src="192.168.1.100", dst="93.184.216.34") / \
          TCP(sport=54321, dport=80, flags="S", seq=1000)
    packets.append(syn)
    
    # SYN-ACK: Server responds
    syn_ack = IP(src="93.184.216.34", dst="192.168.1.100") / \
              TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001)
    packets.append(syn_ack)
    
    # ACK: Client acknowledges
    ack = IP(src="192.168.1.100", dst="93.184.216.34") / \
          TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    # 2. HTTP GET Request
    print("2️⃣  Creating HTTP GET request")
    http_request = IP(src="192.168.1.100", dst="93.184.216.34") / \
                   TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=2001) / \
                   Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(http_request)
    
    # 3. DNS Query
    print("3️⃣  Creating DNS query for google.com")
    dns_query = IP(src="192.168.1.100", dst="8.8.8.8") / \
                UDP(sport=53210, dport=53) / \
                DNS(rd=1, qd=DNSQR(qname="google.com"))
    packets.append(dns_query)
    
    # 4. DNS Response
    print("4️⃣  Creating DNS response")
    dns_response = IP(src="8.8.8.8", dst="192.168.1.100") / \
                   UDP(sport=53, dport=53210) / \
                   DNS(qr=1, qd=DNSQR(qname="google.com"), 
                       an=DNSRR(rrname="google.com", rdata="142.250.185.46"))
    packets.append(dns_response)
    
    # 5. HTTPS Traffic (encrypted, port 443)
    print("5️⃣  Creating HTTPS traffic (encrypted)")
    https = IP(src="192.168.1.100", dst="142.250.185.46") / \
            TCP(sport=54322, dport=443, flags="PA", seq=3000, ack=4000) / \
            Raw(load=b"\x16\x03\x01\x00\x05")  # TLS handshake bytes
    packets.append(https)
    
    # 6. UDP Traffic (non-DNS)
    print("6️⃣  Creating generic UDP packet")
    udp_packet = IP(src="192.168.1.100", dst="192.168.1.1") / \
                 UDP(sport=12345, dport=54321) / \
                 Raw(load=b"Hello UDP!")
    packets.append(udp_packet)
    
    # 7. TCP FIN (connection close)
    print("7️⃣  Creating TCP FIN (closing connection)")
    fin = IP(src="192.168.1.100", dst="93.184.216.34") / \
          TCP(sport=54321, dport=80, flags="FA", seq=1100, ack=2001)
    packets.append(fin)
    
    # 8. ICMP Ping
    print("8️⃣  Creating ICMP ping")
    ping = IP(src="192.168.1.100", dst="8.8.8.8") / ICMP(type=8, code=0)
    packets.append(ping)
    
    return packets


def main():
    """Create sample PCAP and analyze it"""
    
    # Create output directory
    output_dir = "data/samples"
    os.makedirs(output_dir, exist_ok=True)
    
    # Create sample packets
    packets = create_sample_pcap()
    
    # Save to PCAP file
    pcap_file = f"{output_dir}/sample_traffic.pcap"
    wrpcap(pcap_file, packets)
    
    print(f"\n✅ Created sample PCAP: {pcap_file}")
    print(f"📦 Total packets: {len(packets)}")
    print("\n" + "="*60)
    print("🎯 Now run the parser to analyze these packets:")
    print("="*60)
    print(f"\nInside Docker container:")
    print(f"  python3 analyzer/core/pcap_parser.py {pcap_file}")
    print("\nOr on Windows (if Scapy installed):")
    print(f"  python analyzer\\core\\pcap_parser.py {pcap_file}")
    print("\n" + "="*60)


if __name__ == '__main__':
    main()
