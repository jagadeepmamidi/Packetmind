"""
Signature-Based Detection Rules

This module teaches you how signature-based IDS works (like Snort/Suricata).

Learning objectives:
- Understand signature-based vs anomaly-based detection
- Write detection rules for known attacks
- Pattern matching in network traffic
- Rule-based alerting

Key concept: If you know what an attack looks like, write a rule for it!
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class DetectionRule:
    """Represents a single detection rule"""
    rule_id: str
    name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    pattern: str  # Regex pattern or condition
    category: str  # MALWARE, EXPLOIT, POLICY, RECON


class SignatureDetector:
    """
    Signature-based threat detection
    
    Similar to Snort/Suricata IDS rules
    """
    
    def __init__(self):
        self.rules = []
        self.alerts = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default detection rules"""
        
        # Rule 1: SQL Injection
        self.add_rule(DetectionRule(
            rule_id="SIG-001",
            name="SQL Injection Attempt",
            severity="HIGH",
            description="Detects SQL injection patterns in HTTP requests",
            pattern=r"(union.*select|or\s+1\s*=\s*1|'.*or.*'.*=.*')",
            category="EXPLOIT"
        ))
        
        # Rule 2: XSS Attack
        self.add_rule(DetectionRule(
            rule_id="SIG-002",
            name="Cross-Site Scripting (XSS)",
            severity="HIGH",
            description="Detects XSS attack patterns",
            pattern=r"(<script|javascript:|onerror=|onload=)",
            category="EXPLOIT"
        ))
        
        # Rule 3: Directory Traversal
        self.add_rule(DetectionRule(
            rule_id="SIG-003",
            name="Directory Traversal",
            severity="MEDIUM",
            description="Detects path traversal attempts",
            pattern=r"(\.\./|\.\.\\|/etc/passwd|/windows/system32)",
            category="EXPLOIT"
        ))
        
        # Rule 4: Suspicious User-Agent
        self.add_rule(DetectionRule(
            rule_id="SIG-004",
            name="Suspicious User-Agent",
            severity="MEDIUM",
            description="Detects known malicious user agents",
            pattern=r"(sqlmap|nikto|nmap|masscan|metasploit)",
            category="RECON"
        ))
        
        # Rule 5: Cryptocurrency Mining
        self.add_rule(DetectionRule(
            rule_id="SIG-005",
            name="Cryptocurrency Mining",
            severity="MEDIUM",
            description="Detects crypto mining pool connections",
            pattern=r"(stratum\+tcp|xmr-|monero|cryptonight)",
            category="MALWARE"
        ))
        
        # Rule 6: Reverse Shell
        self.add_rule(DetectionRule(
            rule_id="SIG-006",
            name="Reverse Shell Command",
            severity="CRITICAL",
            description="Detects reverse shell commands",
            pattern=r"(bash\s+-i|nc\s+-e|/bin/sh|cmd\.exe)",
            category="EXPLOIT"
        ))
        
        # Rule 7: Suspicious DNS Query
        self.add_rule(DetectionRule(
            rule_id="SIG-007",
            name="Suspicious DNS Query Length",
            severity="MEDIUM",
            description="Detects unusually long DNS queries (possible tunneling)",
            pattern=r"^.{50,}\..*",  # 50+ char subdomain
            category="MALWARE"
        ))
        
        # Rule 8: Known C2 Domain
        self.add_rule(DetectionRule(
            rule_id="SIG-008",
            name="Known C2 Domain",
            severity="CRITICAL",
            description="Detects connections to known C2 domains",
            pattern=r"(evil\.com|malware\.net|c2server\.org)",
            category="MALWARE"
        ))
        
        # Rule 9: Port Scan Detection
        self.add_rule(DetectionRule(
            rule_id="SIG-009",
            name="Port Scan Activity",
            severity="MEDIUM",
            description="Detects port scanning patterns",
            pattern="PORT_SCAN_PATTERN",  # Special pattern
            category="RECON"
        ))
        
        # Rule 10: Brute Force Login
        self.add_rule(DetectionRule(
            rule_id="SIG-010",
            name="Brute Force Login Attempt",
            severity="HIGH",
            description="Detects multiple failed login attempts",
            pattern="BRUTE_FORCE_PATTERN",  # Special pattern
            category="EXPLOIT"
        ))
    
    def add_rule(self, rule: DetectionRule):
        """Add a detection rule"""
        self.rules.append(rule)
    
    def check_http_payload(self, payload: str) -> List[Dict]:
        """Check HTTP payload against rules"""
        matches = []
        
        payload_lower = payload.lower()
        
        for rule in self.rules:
            if rule.category in ['EXPLOIT', 'RECON']:
                # Check regex pattern
                if re.search(rule.pattern, payload_lower, re.IGNORECASE):
                    matches.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'description': rule.description,
                        'category': rule.category,
                        'matched_pattern': rule.pattern
                    })
                    
                    # Add to alerts
                    self.alerts.append({
                        'rule': rule.name,
                        'severity': rule.severity,
                        'payload_snippet': payload[:100]
                    })
        
        return matches
    
    def check_dns_query(self, domain: str) -> List[Dict]:
        """Check DNS query against rules"""
        matches = []
        
        for rule in self.rules:
            if rule.rule_id in ['SIG-007', 'SIG-008']:
                if re.search(rule.pattern, domain, re.IGNORECASE):
                    matches.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'description': rule.description,
                        'matched_domain': domain
                    })
                    
                    self.alerts.append({
                        'rule': rule.name,
                        'severity': rule.severity,
                        'domain': domain
                    })
        
        return matches
    
    def check_port_scan(self, src_ip: str, ports_accessed: List[int]) -> List[Dict]:
        """Check for port scanning behavior"""
        matches = []
        
        # If accessing more than 10 different ports, flag as scan
        if len(ports_accessed) > 10:
            rule = next(r for r in self.rules if r.rule_id == 'SIG-009')
            
            matches.append({
                'rule_id': rule.rule_id,
                'name': rule.name,
                'severity': rule.severity,
                'description': rule.description,
                'src_ip': src_ip,
                'ports_count': len(ports_accessed)
            })
            
            self.alerts.append({
                'rule': rule.name,
                'severity': rule.severity,
                'src_ip': src_ip,
                'ports': ports_accessed[:10]  # First 10
            })
        
        return matches
    
    def get_alerts(self, severity: str = None) -> List[Dict]:
        """Get all alerts, optionally filtered by severity"""
        if severity:
            return [a for a in self.alerts if a.get('severity') == severity]
        return self.alerts
    
    def print_rules(self):
        """Print all loaded rules"""
        print("\n" + "="*60)
        print("📋 LOADED DETECTION RULES")
        print("="*60)
        
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for rule in self.rules:
            by_severity[rule.severity].append(rule)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                print(f"\n{severity} Severity:")
                for rule in by_severity[severity]:
                    print(f"  [{rule.rule_id}] {rule.name}")
                    print(f"      Category: {rule.category}")
                    print(f"      {rule.description}")
        
        print("\n" + "="*60)
    
    def print_alerts_summary(self):
        """Print alerts summary"""
        if not self.alerts:
            print("\n✅ No alerts triggered")
            return
        
        print("\n" + "="*60)
        print(f"🚨 ALERTS SUMMARY ({len(self.alerts)} total)")
        print("="*60)
        
        # Count by severity
        severity_counts = {}
        for alert in self.alerts:
            sev = alert.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nBy Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in severity_counts:
                print(f"  {sev}: {severity_counts[sev]}")
        
        print("\nRecent Alerts:")
        for alert in self.alerts[-5:]:  # Last 5
            print(f"  🚨 {alert['rule']} ({alert['severity']})")


def main():
    """Demo signature detection"""
    print("="*60)
    print("🎯 SIGNATURE-BASED DETECTION")
    print("="*60)
    
    detector = SignatureDetector()
    detector.print_rules()
    
    # Test cases
    print("\n" + "="*60)
    print("🧪 TESTING DETECTION RULES")
    print("="*60)
    
    test_cases = [
        {
            'type': 'http',
            'name': 'SQL Injection',
            'payload': "GET /login?user=admin' OR '1'='1 HTTP/1.1"
        },
        {
            'type': 'http',
            'name': 'XSS Attack',
            'payload': "GET /search?q=<script>alert('XSS')</script> HTTP/1.1"
        },
        {
            'type': 'dns',
            'name': 'Long DNS Query',
            'domain': 'aHR0cHM6Ly9leGFtcGxlLmNvbS9zZWNyZXRkYXRhMTIzNDU2Nzg5MA.evil.com'
        },
        {
            'type': 'dns',
            'name': 'Known C2 Domain',
            'domain': 'beacon.evil.com'
        }
    ]
    
    for test in test_cases:
        print(f"\nTest: {test['name']}")
        
        if test['type'] == 'http':
            matches = detector.check_http_payload(test['payload'])
        elif test['type'] == 'dns':
            matches = detector.check_dns_query(test['domain'])
        
        if matches:
            for match in matches:
                print(f"  🚨 MATCH: {match['name']} ({match['severity']})")
                print(f"      {match['description']}")
        else:
            print("  ✅ No matches")
    
    # Print summary
    detector.print_alerts_summary()


if __name__ == '__main__':
    main()
