"""
Traffic Baseline Profiler

This module teaches you how ML learns "normal" behavior to detect anomalies.

Learning objectives:
- Understand baseline profiling (what's normal?)
- Learn statistical anomaly detection
- Detect traffic spikes (DDoS attacks)
- Identify unusual connection patterns

Key concept: First learn what's normal, then flag deviations!
"""

import json
from typing import Dict, List, Any
from collections import defaultdict, Counter
from datetime import datetime
import statistics


class TrafficBaseline:
    """
    Learn normal traffic patterns to detect anomalies
    
    This is how ML-based security works:
    1. Observe normal traffic (baseline period)
    2. Calculate statistics (mean, std dev, patterns)
    3. Compare new traffic to baseline
    4. Flag significant deviations as anomalies
    """
    
    def __init__(self):
        self.baseline = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'ips': defaultdict(int),
            'packet_sizes': [],
            'packets_per_second': [],
            'connections': defaultdict(int),
            'dns_queries': [],
            'http_requests': []
        }
        
        self.stats = {
            'avg_packet_size': 0,
            'std_packet_size': 0,
            'avg_packets_per_sec': 0,
            'std_packets_per_sec': 0,
            'top_ports': [],
            'top_ips': [],
            'common_protocols': []
        }
    
    def learn_from_packets(self, packets_info: List[Dict[str, Any]]):
        """
        Learn baseline from packet data
        
        This is the "training" phase in ML!
        """
        print(f"📚 Learning baseline from {len(packets_info)} packets...\n")
        
        self.baseline['total_packets'] = len(packets_info)
        
        for packet in packets_info:
            # Protocol distribution
            if 'TCP' in packet.get('layers', []):
                self.baseline['protocols']['TCP'] += 1
            if 'UDP' in packet.get('layers', []):
                self.baseline['protocols']['UDP'] += 1
            if 'ICMP' in packet.get('layers', []):
                self.baseline['protocols']['ICMP'] += 1
            
            # Port distribution
            if packet.get('src_port'):
                self.baseline['ports'][packet['src_port']] += 1
            if packet.get('dst_port'):
                self.baseline['ports'][packet['dst_port']] += 1
            
            # IP distribution
            if packet.get('src_ip'):
                self.baseline['ips'][packet['src_ip']] += 1
            if packet.get('dst_ip'):
                self.baseline['ips'][packet['dst_ip']] += 1
            
            # Packet sizes
            if packet.get('payload_size'):
                self.baseline['packet_sizes'].append(packet['payload_size'])
            
            # Connection tracking
            if packet.get('src_ip') and packet.get('dst_ip'):
                conn = f"{packet['src_ip']}→{packet['dst_ip']}"
                self.baseline['connections'][conn] += 1
            
            # DNS queries
            if 'dns_query' in packet:
                self.baseline['dns_queries'].append(packet['dns_query'])
            
            # HTTP requests
            if 'http_method' in packet:
                self.baseline['http_requests'].append(packet['http_method'])
        
        # Calculate statistics
        self._calculate_stats()
        
        print("✅ Baseline learning complete!")
    
    def _calculate_stats(self):
        """Calculate statistical measures"""
        
        # Packet size statistics
        if self.baseline['packet_sizes']:
            self.stats['avg_packet_size'] = statistics.mean(self.baseline['packet_sizes'])
            if len(self.baseline['packet_sizes']) > 1:
                self.stats['std_packet_size'] = statistics.stdev(self.baseline['packet_sizes'])
        
        # Top ports (most common)
        port_counts = Counter(self.baseline['ports'])
        self.stats['top_ports'] = port_counts.most_common(10)
        
        # Top IPs (most active)
        ip_counts = Counter(self.baseline['ips'])
        self.stats['top_ips'] = ip_counts.most_common(10)
        
        # Protocol distribution
        total = sum(self.baseline['protocols'].values())
        if total > 0:
            self.stats['common_protocols'] = [
                (proto, count, round(count/total*100, 1))
                for proto, count in self.baseline['protocols'].items()
            ]
    
    def detect_anomalies(self, new_packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if a packet is anomalous compared to baseline
        
        This is the "inference" phase in ML!
        """
        anomalies = {
            'is_anomalous': False,
            'anomaly_score': 0.0,
            'indicators': []
        }
        
        # Check unusual packet size
        if new_packet.get('payload_size'):
            size = new_packet['payload_size']
            avg = self.stats['avg_packet_size']
            std = self.stats['std_packet_size']
            
            if std > 0:
                # Z-score: how many standard deviations away?
                z_score = abs(size - avg) / std
                
                if z_score > 3:  # More than 3 std devs = very unusual
                    anomalies['is_anomalous'] = True
                    anomalies['anomaly_score'] += 0.3
                    anomalies['indicators'].append(
                        f'Unusual packet size: {size} bytes (avg: {avg:.0f}, z-score: {z_score:.1f})'
                    )
        
        # Check unusual port
        dst_port = new_packet.get('dst_port')
        if dst_port:
            common_ports = [port for port, _ in self.stats['top_ports']]
            
            if dst_port not in common_ports and dst_port not in [80, 443, 53, 22]:
                anomalies['is_anomalous'] = True
                anomalies['anomaly_score'] += 0.2
                anomalies['indicators'].append(
                    f'Unusual destination port: {dst_port}'
                )
        
        # Check unusual IP
        dst_ip = new_packet.get('dst_ip')
        if dst_ip:
            common_ips = [ip for ip, _ in self.stats['top_ips']]
            
            if dst_ip not in common_ips:
                anomalies['anomaly_score'] += 0.1
                anomalies['indicators'].append(
                    f'New destination IP: {dst_ip}'
                )
        
        # Check for port scanning (many different ports to same IP)
        # This would be tracked over time in a real system
        
        return anomalies
    
    def detect_volume_anomaly(self, current_rate: int) -> Dict[str, Any]:
        """
        Detect traffic volume anomalies (DDoS detection)
        
        Example:
            Normal: 100 packets/sec
            DDoS:   50,000 packets/sec ← ANOMALY!
        """
        avg_rate = self.stats.get('avg_packets_per_sec', 0)
        
        if avg_rate == 0:
            return {'is_ddos': False}
        
        # If current rate is 10x normal, flag as potential DDoS
        multiplier = current_rate / avg_rate
        
        if multiplier > 10:
            return {
                'is_ddos': True,
                'severity': 'HIGH' if multiplier > 50 else 'MEDIUM',
                'multiplier': round(multiplier, 1),
                'current_rate': current_rate,
                'baseline_rate': avg_rate,
                'message': f'Traffic spike: {multiplier:.1f}x normal rate'
            }
        
        return {'is_ddos': False}
    
    def print_baseline_summary(self):
        """Print learned baseline"""
        print("\n" + "="*60)
        print("📊 TRAFFIC BASELINE SUMMARY")
        print("="*60)
        print(f"Total Packets Analyzed: {self.baseline['total_packets']}")
        print(f"\nAverage Packet Size:    {self.stats['avg_packet_size']:.0f} bytes")
        print(f"Std Dev Packet Size:    {self.stats['std_packet_size']:.0f} bytes")
        
        print(f"\n🔌 Protocol Distribution:")
        for proto, count, pct in self.stats['common_protocols']:
            print(f"  {proto}: {count} packets ({pct}%)")
        
        print(f"\n🚪 Top 5 Ports:")
        for port, count in self.stats['top_ports'][:5]:
            port_name = self._get_port_name(port)
            print(f"  Port {port} ({port_name}): {count} packets")
        
        print(f"\n🌐 Top 5 IPs:")
        for ip, count in self.stats['top_ips'][:5]:
            print(f"  {ip}: {count} packets")
        
        print("="*60)
    
    def _get_port_name(self, port: int) -> str:
        """Get common port names"""
        port_names = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        return port_names.get(port, 'Unknown')
    
    def save_baseline(self, filename: str):
        """Save baseline to file for later use"""
        data = {
            'baseline': dict(self.baseline),
            'stats': self.stats,
            'timestamp': datetime.now().isoformat()
        }
        
        # Convert defaultdict to dict for JSON serialization
        data['baseline']['protocols'] = dict(data['baseline']['protocols'])
        data['baseline']['ports'] = dict(data['baseline']['ports'])
        data['baseline']['ips'] = dict(data['baseline']['ips'])
        data['baseline']['connections'] = dict(data['baseline']['connections'])
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n💾 Baseline saved to: {filename}")
    
    def load_baseline(self, filename: str):
        """Load baseline from file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        self.baseline = defaultdict(int, data['baseline'])
        self.stats = data['stats']
        
        print(f"📂 Baseline loaded from: {filename}")


def main():
    """Example usage"""
    print("Traffic Baseline Profiler")
    print("This module learns normal traffic patterns")
    print("\nUse with pcap_parser.py output to build baselines!")


if __name__ == '__main__':
    main()
