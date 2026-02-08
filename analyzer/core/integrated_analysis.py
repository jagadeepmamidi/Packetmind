"""
Integrated Analysis Demo

This script demonstrates the complete analysis pipeline:
1. Parse PCAP file
2. Build traffic baseline
3. Detect entropy anomalies
4. Flag suspicious activity

This shows how all the pieces work together!
"""

import sys
from pathlib import Path

# Import our modules
from pcap_parser import PacketParser
from baseline_profiler import TrafficBaseline
from entropy_detector import EntropyAnalyzer


def run_full_analysis(pcap_file: str):
    """
    Run complete analysis pipeline
    
    This is the "PacketMind AI" in action!
    """
    print("="*70)
    print("🧠 PACKETMIND AI - INTEGRATED ANALYSIS")
    print("="*70)
    print()
    
    # Step 1: Parse PCAP
    print("STEP 1: Parsing PCAP file")
    print("-" * 70)
    parser = PacketParser(pcap_file)
    packets = parser.analyze_all()
    parser.print_summary()
    
    # Step 2: Build Baseline
    print("\n" + "="*70)
    print("STEP 2: Building Traffic Baseline")
    print("-" * 70)
    baseline = TrafficBaseline()
    baseline.learn_from_packets(packets)
    baseline.print_baseline_summary()
    
    # Step 3: Entropy Analysis
    print("\n" + "="*70)
    print("STEP 3: Entropy-Based Anomaly Detection")
    print("-" * 70)
    
    entropy_analyzer = EntropyAnalyzer()
    
    # Extract DNS queries from packets
    dns_queries = [p['dns_query'] for p in packets if 'dns_query' in p]
    
    if dns_queries:
        print(f"\nAnalyzing {len(dns_queries)} DNS queries for tunneling...\n")
        results = entropy_analyzer.batch_analyze_domains(dns_queries)
        entropy_analyzer.print_summary()
    else:
        print("\nNo DNS queries found in this capture.")
    
    # Step 4: Anomaly Detection on New Traffic
    print("\n" + "="*70)
    print("STEP 4: Testing Anomaly Detection")
    print("-" * 70)
    
    # Simulate some new packets
    test_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'payload_size': 150
        },
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'dst_port': 12345,  # Unusual port
            'payload_size': 5000  # Large packet
        }
    ]
    
    print("\nTesting baseline anomaly detection:\n")
    for i, packet in enumerate(test_packets, 1):
        result = baseline.detect_anomalies(packet)
        
        print(f"Test Packet #{i}:")
        print(f"  {packet['src_ip']}:{packet.get('src_port', '?')} → "
              f"{packet['dst_ip']}:{packet['dst_port']}")
        print(f"  Anomalous: {result['is_anomalous']}")
        print(f"  Anomaly Score: {result['anomaly_score']:.2f}")
        
        if result['indicators']:
            print(f"  Indicators:")
            for indicator in result['indicators']:
                print(f"    • {indicator}")
        print()
    
    # Step 5: DDoS Detection Demo
    print("\n" + "="*70)
    print("STEP 5: DDoS Detection Demo")
    print("-" * 70)
    
    normal_rate = 100
    attack_rate = 50000
    
    print(f"\nNormal traffic: {normal_rate} packets/sec")
    result = baseline.detect_volume_anomaly(normal_rate)
    print(f"  DDoS Detected: {result.get('is_ddos', False)}")
    
    print(f"\nAttack traffic: {attack_rate} packets/sec")
    result = baseline.detect_volume_anomaly(attack_rate)
    if result.get('is_ddos'):
        print(f"  🚨 DDoS DETECTED!")
        print(f"  Severity: {result['severity']}")
        print(f"  Traffic Multiplier: {result['multiplier']}x normal")
        print(f"  Message: {result['message']}")
    
    # Final Summary
    print("\n" + "="*70)
    print("✅ ANALYSIS COMPLETE")
    print("="*70)
    print("\nPacketMind AI successfully:")
    print("  ✓ Parsed network traffic")
    print("  ✓ Learned normal baseline")
    print("  ✓ Detected entropy anomalies")
    print("  ✓ Identified suspicious patterns")
    print("  ✓ Simulated DDoS detection")
    print("\nThis is the foundation of AI-powered network security! 🚀")
    print()


def main():
    """Run the integrated demo"""
    
    if len(sys.argv) < 2:
        print("Usage: python integrated_analysis.py <pcap_file>")
        print("\nExample:")
        print("  python integrated_analysis.py data/samples/sample_traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not Path(pcap_file).exists():
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    run_full_analysis(pcap_file)


if __name__ == '__main__':
    main()
