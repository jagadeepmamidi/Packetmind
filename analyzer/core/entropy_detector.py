"""
Entropy-based Anomaly Detection

This module teaches you how to detect attacks using ENTROPY - a measure of randomness.

Learning objectives:
- Understand Shannon entropy and information theory
- Detect DNS tunneling (attackers encoding data in DNS queries)
- Identify encrypted/encoded payloads
- Spot suspicious domain names

Key concept: Normal traffic has patterns. Attacks often have high randomness!
"""

import math
from typing import Dict, List, Tuple
from collections import Counter


class EntropyAnalyzer:
    """
    Analyze entropy to detect anomalies
    
    Entropy measures randomness in data:
    - Low entropy (< 2.5): Predictable (e.g., "google.com")
    - Medium entropy (2.5-3.5): Normal variation
    - High entropy (> 3.5): Random/encoded (e.g., "aHR0cHM6Ly9leGFtcGxl")
    """
    
    # Thresholds learned from real-world data
    DNS_NORMAL_ENTROPY = 2.5
    DNS_SUSPICIOUS_ENTROPY = 3.5
    DNS_MALICIOUS_ENTROPY = 4.5
    
    def __init__(self):
        self.stats = {
            'total_analyzed': 0,
            'low_entropy': 0,
            'medium_entropy': 0,
            'high_entropy': 0,
            'suspicious_domains': []
        }
    
    def calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Formula: H(X) = -Σ P(x) * log₂(P(x))
        
        Where:
        - H(X) = entropy
        - P(x) = probability of character x
        - Σ = sum over all unique characters
        
        Example:
            "aaaa"        → entropy ≈ 0.0 (no randomness)
            "abcd"        → entropy ≈ 2.0 (some randomness)
            "aHR0cHM6Ly"  → entropy ≈ 4.5 (high randomness, base64!)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            # Probability of this character
            probability = count / length
            
            # Shannon entropy formula
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_dns_query(self, domain: str) -> Dict[str, any]:
        """
        Analyze a DNS query for suspicious patterns
        
        DNS tunneling detection:
        - Attackers encode data in subdomains
        - Example: "aHR0cHM6Ly9leGFtcGxl.evil.com"
        - The subdomain is base64-encoded data!
        """
        self.stats['total_analyzed'] += 1
        
        # Extract subdomain (everything before the main domain)
        parts = domain.split('.')
        if len(parts) > 2:
            subdomain = parts[0]
        else:
            subdomain = domain
        
        # Calculate entropy
        entropy = self.calculate_entropy(subdomain)
        
        # Analyze characteristics
        result = {
            'domain': domain,
            'subdomain': subdomain,
            'entropy': round(entropy, 2),
            'length': len(subdomain),
            'is_suspicious': False,
            'threat_level': 'NORMAL',
            'indicators': []
        }
        
        # Check entropy thresholds
        if entropy < self.DNS_NORMAL_ENTROPY:
            self.stats['low_entropy'] += 1
            result['threat_level'] = 'NORMAL'
        elif entropy < self.DNS_SUSPICIOUS_ENTROPY:
            self.stats['medium_entropy'] += 1
            result['threat_level'] = 'NORMAL'
        elif entropy < self.DNS_MALICIOUS_ENTROPY:
            self.stats['high_entropy'] += 1
            result['threat_level'] = 'SUSPICIOUS'
            result['is_suspicious'] = True
            result['indicators'].append(f'High entropy: {entropy:.2f}')
        else:
            self.stats['high_entropy'] += 1
            result['threat_level'] = 'MALICIOUS'
            result['is_suspicious'] = True
            result['indicators'].append(f'Very high entropy: {entropy:.2f}')
            result['indicators'].append('Possible base64/encoding detected')
        
        # Check length (DNS tunneling often uses long subdomains)
        if len(subdomain) > 50:
            result['is_suspicious'] = True
            result['indicators'].append(f'Unusually long subdomain: {len(subdomain)} chars')
            if result['threat_level'] == 'NORMAL':
                result['threat_level'] = 'SUSPICIOUS'
        
        # Check for base64-like patterns
        if self._looks_like_base64(subdomain):
            result['is_suspicious'] = True
            result['indicators'].append('Base64-like pattern detected')
            if result['threat_level'] != 'MALICIOUS':
                result['threat_level'] = 'SUSPICIOUS'
        
        # Track suspicious domains
        if result['is_suspicious']:
            self.stats['suspicious_domains'].append(domain)
        
        return result
    
    def _looks_like_base64(self, text: str) -> bool:
        """
        Check if text looks like base64 encoding
        
        Base64 characteristics:
        - Only uses A-Z, a-z, 0-9, +, /, =
        - Length is multiple of 4
        - High entropy
        """
        # Check character set
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        text_chars = set(text)
        
        # If more than 80% of chars are base64 chars, it's suspicious
        if len(text) > 10:
            base64_ratio = len(text_chars & base64_chars) / len(text_chars)
            return base64_ratio > 0.8
        
        return False
    
    def analyze_payload(self, payload: bytes) -> Dict[str, any]:
        """
        Analyze packet payload for encryption/encoding
        
        Encrypted payloads have high entropy (random-looking data)
        """
        if not payload:
            return {'entropy': 0.0, 'is_encrypted': False}
        
        # Convert bytes to string for entropy calculation
        try:
            text = payload.decode('utf-8', errors='ignore')
        except:
            text = str(payload)
        
        entropy = self.calculate_entropy(text)
        
        return {
            'entropy': round(entropy, 2),
            'size': len(payload),
            'is_encrypted': entropy > 4.0,  # High entropy suggests encryption
            'threat_level': 'ENCRYPTED' if entropy > 4.0 else 'PLAINTEXT'
        }
    
    def batch_analyze_domains(self, domains: List[str]) -> List[Dict[str, any]]:
        """Analyze multiple domains and return results"""
        results = []
        
        print(f"🔍 Analyzing {len(domains)} domains for anomalies...\n")
        
        for domain in domains:
            result = self.analyze_dns_query(domain)
            results.append(result)
            
            # Print suspicious ones
            if result['is_suspicious']:
                self._print_alert(result)
        
        return results
    
    def _print_alert(self, result: Dict[str, any]):
        """Print alert for suspicious domain"""
        threat_emoji = {
            'SUSPICIOUS': '⚠️',
            'MALICIOUS': '🚨'
        }
        
        emoji = threat_emoji.get(result['threat_level'], '❓')
        
        print(f"{emoji} {result['threat_level']}: {result['domain']}")
        print(f"   Entropy: {result['entropy']} (threshold: {self.DNS_SUSPICIOUS_ENTROPY})")
        print(f"   Length: {result['length']} chars")
        
        for indicator in result['indicators']:
            print(f"   • {indicator}")
        print()
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("📊 ENTROPY ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Analyzed:        {self.stats['total_analyzed']}")
        print(f"Low Entropy:           {self.stats['low_entropy']} (normal)")
        print(f"Medium Entropy:        {self.stats['medium_entropy']} (normal)")
        print(f"High Entropy:          {self.stats['high_entropy']} (suspicious)")
        print(f"Suspicious Domains:    {len(self.stats['suspicious_domains'])}")
        print("="*60)
        
        if self.stats['suspicious_domains']:
            print("\n🚨 Flagged Domains:")
            for domain in self.stats['suspicious_domains'][:10]:
                print(f"  - {domain}")


def demonstrate_entropy():
    """
    Demonstrate entropy with examples
    
    This shows you how entropy works!
    """
    analyzer = EntropyAnalyzer()
    
    print("="*60)
    print("🎓 ENTROPY DEMONSTRATION")
    print("="*60)
    print("\nEntropy measures randomness (0 = predictable, 5+ = random)\n")
    
    examples = [
        ("google.com", "Normal domain"),
        ("facebook.com", "Normal domain"),
        ("api-v2-prod.example.com", "Normal subdomain"),
        ("aHR0cHM6Ly9leGFtcGxl.evil.com", "Base64 encoded (DNS tunneling!)"),
        ("x7k2m9p4q8r1s5t3u6v9w2y4z7a1b3c5.malware.net", "Random subdomain (C2 beacon!)"),
        ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA.cert.com", "Certificate data"),
    ]
    
    for domain, description in examples:
        result = analyzer.analyze_dns_query(domain)
        
        print(f"Domain: {domain}")
        print(f"  Description: {description}")
        print(f"  Entropy: {result['entropy']}")
        print(f"  Threat Level: {result['threat_level']}")
        
        if result['indicators']:
            print(f"  Indicators:")
            for indicator in result['indicators']:
                print(f"    • {indicator}")
        print()


def main():
    """Example usage"""
    demonstrate_entropy()


if __name__ == '__main__':
    main()
