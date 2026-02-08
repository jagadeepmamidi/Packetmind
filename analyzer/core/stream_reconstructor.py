"""
TCP Stream Reconstruction

This module teaches you how to reassemble TCP conversations from individual packets.

Learning objectives:
- Understand TCP sequence numbers
- Reassemble fragmented data streams
- Track connection state (SYN, established, FIN)
- Extract complete HTTP requests/responses

Key concept: TCP splits data into packets. We need to put them back together!
"""

from scapy.all import *
from typing import Dict, List, Tuple
from collections import defaultdict


class TCPStream:
    """Represents a single TCP connection stream"""
    
    def __init__(self, stream_id: str):
        self.stream_id = stream_id  # "src_ip:src_port->dst_ip:dst_port"
        self.packets = []
        self.data = b''
        self.state = 'INIT'
        self.seq_numbers = []
        self.timestamps = []
    
    def add_packet(self, packet, timestamp):
        """Add packet to stream"""
        self.packets.append(packet)
        self.timestamps.append(timestamp)
        
        if TCP in packet:
            self.seq_numbers.append(packet[TCP].seq)
            
            # Track connection state
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                self.state = 'SYN'
            elif flags & 0x10:  # ACK
                if self.state == 'SYN':
                    self.state = 'ESTABLISHED'
            elif flags & 0x01:  # FIN
                self.state = 'FIN'
            
            # Extract payload
            if Raw in packet:
                self.data += bytes(packet[Raw].load)
    
    def get_http_data(self) -> str:
        """Extract HTTP data if present"""
        try:
            return self.data.decode('utf-8', errors='ignore')
        except:
            return ""
    
    def is_complete(self) -> bool:
        """Check if stream has FIN packet"""
        return self.state == 'FIN'


class StreamReconstructor:
    """
    Reconstruct TCP streams from packet capture
    
    This is how Wireshark's "Follow TCP Stream" works!
    """
    
    def __init__(self):
        self.streams = {}  # stream_id -> TCPStream
        self.stats = {
            'total_streams': 0,
            'complete_streams': 0,
            'http_streams': 0,
            'data_transferred': 0
        }
    
    def get_stream_id(self, packet) -> str:
        """
        Create unique stream identifier
        
        Format: "192.168.1.100:54321->93.184.216.34:80"
        """
        if IP not in packet or TCP not in packet:
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Normalize: always put lower IP first for bidirectional matching
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
    
    def process_pcap(self, pcap_file: str):
        """Process PCAP and reconstruct all TCP streams"""
        print(f"🔄 Reconstructing TCP streams from: {pcap_file}\n")
        
        packets = rdpcap(pcap_file)
        
        for i, packet in enumerate(packets):
            stream_id = self.get_stream_id(packet)
            
            if stream_id:
                # Create stream if new
                if stream_id not in self.streams:
                    self.streams[stream_id] = TCPStream(stream_id)
                    self.stats['total_streams'] += 1
                
                # Add packet to stream
                timestamp = float(packet.time) if hasattr(packet, 'time') else i
                self.streams[stream_id].add_packet(packet, timestamp)
        
        # Calculate stats
        for stream in self.streams.values():
            if stream.is_complete():
                self.stats['complete_streams'] += 1
            
            if stream.data:
                self.stats['data_transferred'] += len(stream.data)
                
                # Check for HTTP
                http_data = stream.get_http_data()
                if http_data.startswith(('GET', 'POST', 'HTTP')):
                    self.stats['http_streams'] += 1
        
        print(f"✅ Reconstructed {self.stats['total_streams']} TCP streams")
    
    def get_stream(self, stream_id: str) -> TCPStream:
        """Get specific stream"""
        return self.streams.get(stream_id)
    
    def get_http_streams(self) -> List[TCPStream]:
        """Get all HTTP streams"""
        http_streams = []
        
        for stream in self.streams.values():
            http_data = stream.get_http_data()
            if http_data.startswith(('GET', 'POST', 'HTTP')):
                http_streams.append(stream)
        
        return http_streams
    
    def extract_http_requests(self) -> List[Dict]:
        """Extract all HTTP requests from streams"""
        requests = []
        
        for stream in self.get_http_streams():
            http_data = stream.get_http_data()
            
            # Parse HTTP request
            lines = http_data.split('\r\n')
            if lines:
                request_line = lines[0]
                
                # Extract method, path, version
                parts = request_line.split()
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    # Extract Host header
                    host = None
                    for line in lines[1:]:
                        if line.startswith('Host:'):
                            host = line.split(':', 1)[1].strip()
                            break
                    
                    requests.append({
                        'stream_id': stream.stream_id,
                        'method': method,
                        'path': path,
                        'host': host,
                        'full_request': http_data[:500]  # First 500 chars
                    })
        
        return requests
    
    def print_summary(self):
        """Print reconstruction summary"""
        print("\n" + "="*60)
        print("📊 TCP STREAM RECONSTRUCTION SUMMARY")
        print("="*60)
        print(f"Total Streams:       {self.stats['total_streams']}")
        print(f"Complete Streams:    {self.stats['complete_streams']}")
        print(f"HTTP Streams:        {self.stats['http_streams']}")
        print(f"Data Transferred:    {self.stats['data_transferred']:,} bytes")
        print("="*60)
    
    def print_http_requests(self):
        """Print all HTTP requests found"""
        requests = self.extract_http_requests()
        
        if not requests:
            print("\nNo HTTP requests found.")
            return
        
        print(f"\n🌐 Found {len(requests)} HTTP Requests:\n")
        
        for i, req in enumerate(requests, 1):
            print(f"Request #{i}:")
            print(f"  Method: {req['method']}")
            print(f"  Host: {req['host']}")
            print(f"  Path: {req['path']}")
            print(f"  Stream: {req['stream_id']}")
            print()


def main():
    """Example usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python stream_reconstructor.py <pcap_file>")
        print("\nExample:")
        print("  python stream_reconstructor.py data/samples/sample_traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Reconstruct streams
    reconstructor = StreamReconstructor()
    reconstructor.process_pcap(pcap_file)
    
    # Print summary
    reconstructor.print_summary()
    
    # Print HTTP requests
    reconstructor.print_http_requests()


if __name__ == '__main__':
    main()
