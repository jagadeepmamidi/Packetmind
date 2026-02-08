"""
Real-Time Alerting System

This module teaches you how to build a real-time security alerting system.

Learning objectives:
- Understand alert prioritization
- Implement alert deduplication
- Create alert notifications
- Build alert management

Key concept: Not all alerts are equal - prioritize and deduplicate!
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class Alert:
    """Represents a security alert"""
    alert_id: str
    timestamp: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # MALWARE, EXPLOIT, POLICY, RECON, ANOMALY
    title: str
    description: str
    source_ip: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    indicators: List[str] = None
    raw_data: Dict = None
    status: str = "NEW"  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.raw_data is None:
            self.raw_data = {}


class AlertManager:
    """
    Manage security alerts with deduplication and prioritization
    
    Features:
    - Alert deduplication (don't spam same alert)
    - Priority scoring
    - Alert aggregation
    - Notification routing
    """
    
    def __init__(self):
        self.alerts = []
        self.alert_counts = defaultdict(int)
        self.dedupe_window = 300  # 5 minutes in seconds
        self.alert_hashes = {}  # For deduplication
        
        self.severity_scores = {
            'CRITICAL': 100,
            'HIGH': 75,
            'MEDIUM': 50,
            'LOW': 25
        }
    
    def create_alert(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        source_ip: str,
        **kwargs
    ) -> Alert:
        """Create a new alert"""
        
        # Generate alert ID
        alert_id = self._generate_alert_id(title, source_ip)
        
        # Check for duplicates
        if self._is_duplicate(alert_id):
            print(f"⚠️  Duplicate alert suppressed: {title}")
            return None
        
        # Create alert
        alert = Alert(
            alert_id=alert_id,
            timestamp=datetime.now().isoformat(),
            severity=severity,
            category=category,
            title=title,
            description=description,
            source_ip=source_ip,
            **kwargs
        )
        
        # Add to alerts
        self.alerts.append(alert)
        self.alert_counts[severity] += 1
        
        # Track for deduplication
        self.alert_hashes[alert_id] = datetime.now().timestamp()
        
        # Print alert
        self._print_alert(alert)
        
        return alert
    
    def _generate_alert_id(self, title: str, source_ip: str) -> str:
        """Generate unique alert ID"""
        data = f"{title}:{source_ip}:{datetime.now().strftime('%Y%m%d%H%M')}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _is_duplicate(self, alert_id: str) -> bool:
        """Check if alert is duplicate within time window"""
        if alert_id in self.alert_hashes:
            last_time = self.alert_hashes[alert_id]
            current_time = datetime.now().timestamp()
            
            if current_time - last_time < self.dedupe_window:
                return True
        
        return False
    
    def _print_alert(self, alert: Alert):
        """Print alert to console"""
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        emoji = severity_emoji.get(alert.severity, '⚪')
        
        print(f"\n{emoji} [{alert.severity}] {alert.title}")
        print(f"   Time: {alert.timestamp}")
        print(f"   Category: {alert.category}")
        print(f"   Source: {alert.source_ip}", end='')
        
        if alert.dest_ip:
            print(f" → {alert.dest_ip}:{alert.dest_port}")
        else:
            print()
        
        print(f"   {alert.description}")
        
        if alert.indicators:
            print(f"   Indicators:")
            for indicator in alert.indicators[:3]:  # First 3
                print(f"     • {indicator}")
    
    def get_alerts(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Alert]:
        """Get alerts with optional filtering"""
        filtered = self.alerts
        
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        
        if category:
            filtered = [a for a in filtered if a.category == category]
        
        if status:
            filtered = [a for a in filtered if a.status == status]
        
        return filtered[-limit:]  # Most recent
    
    def get_critical_alerts(self) -> List[Alert]:
        """Get all critical alerts"""
        return self.get_alerts(severity='CRITICAL')
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = 'ACKNOWLEDGED'
                print(f"✓ Alert {alert_id} acknowledged")
                return
        
        print(f"✗ Alert {alert_id} not found")
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = 'RESOLVED'
                print(f"✓ Alert {alert_id} resolved")
                return
        
        print(f"✗ Alert {alert_id} not found")
    
    def get_alert_stats(self) -> Dict:
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.alerts),
            'by_severity': dict(self.alert_counts),
            'by_category': defaultdict(int),
            'by_status': defaultdict(int),
            'top_sources': defaultdict(int)
        }
        
        for alert in self.alerts:
            stats['by_category'][alert.category] += 1
            stats['by_status'][alert.status] += 1
            stats['top_sources'][alert.source_ip] += 1
        
        # Convert to regular dicts
        stats['by_category'] = dict(stats['by_category'])
        stats['by_status'] = dict(stats['by_status'])
        
        # Top 5 sources
        top_sources = sorted(
            stats['top_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        stats['top_sources'] = dict(top_sources)
        
        return stats
    
    def print_dashboard(self):
        """Print alert dashboard"""
        stats = self.get_alert_stats()
        
        print("\n" + "="*60)
        print("📊 SECURITY ALERT DASHBOARD")
        print("="*60)
        
        print(f"\nTotal Alerts: {stats['total_alerts']}")
        
        print("\n🔥 By Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = stats['by_severity'].get(sev, 0)
            if count > 0:
                print(f"  {sev}: {count}")
        
        print("\n📂 By Category:")
        for cat, count in stats['by_category'].items():
            print(f"  {cat}: {count}")
        
        print("\n📌 By Status:")
        for status, count in stats['by_status'].items():
            print(f"  {status}: {count}")
        
        if stats['top_sources']:
            print("\n🎯 Top Alert Sources:")
            for ip, count in stats['top_sources'].items():
                print(f"  {ip}: {count} alerts")
        
        print("="*60)
    
    def export_alerts(self, filename: str, format: str = 'json'):
        """Export alerts to file"""
        if format == 'json':
            data = [asdict(alert) for alert in self.alerts]
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"\n💾 Exported {len(self.alerts)} alerts to: {filename}")
        
        elif format == 'csv':
            import csv
            
            with open(filename, 'w', newline='') as f:
                if self.alerts:
                    writer = csv.DictWriter(f, fieldnames=asdict(self.alerts[0]).keys())
                    writer.writeheader()
                    
                    for alert in self.alerts:
                        writer.writerow(asdict(alert))
            
            print(f"\n💾 Exported {len(self.alerts)} alerts to: {filename}")


def main():
    """Demo alerting system"""
    print("="*60)
    print("🚨 REAL-TIME ALERTING SYSTEM")
    print("="*60)
    
    manager = AlertManager()
    
    # Simulate various alerts
    print("\n🧪 Simulating Security Alerts...\n")
    
    # Critical: C2 Communication
    manager.create_alert(
        severity='CRITICAL',
        category='MALWARE',
        title='C2 Communication Detected',
        description='Outbound connection to known C2 server',
        source_ip='192.168.1.42',
        dest_ip='185.220.101.50',
        dest_port=443,
        indicators=['Known C2 IP', 'Encrypted traffic', 'Regular beaconing']
    )
    
    # High: SQL Injection
    manager.create_alert(
        severity='HIGH',
        category='EXPLOIT',
        title='SQL Injection Attempt',
        description='SQL injection pattern detected in HTTP request',
        source_ip='203.0.113.45',
        dest_ip='192.168.1.10',
        dest_port=80,
        indicators=["Pattern: ' OR '1'='1", 'Multiple attempts']
    )
    
    # Medium: Port Scan
    manager.create_alert(
        severity='MEDIUM',
        category='RECON',
        title='Port Scan Detected',
        description='Host scanned 15 ports in 10 seconds',
        source_ip='198.51.100.23',
        dest_ip='192.168.1.0/24',
        indicators=['15 ports scanned', 'SYN packets only']
    )
    
    # Low: Policy Violation
    manager.create_alert(
        severity='LOW',
        category='POLICY',
        title='Unauthorized Protocol',
        description='BitTorrent traffic detected',
        source_ip='192.168.1.99',
        indicators=['Port 6881', 'BitTorrent protocol']
    )
    
    # Duplicate (should be suppressed)
    manager.create_alert(
        severity='MEDIUM',
        category='RECON',
        title='Port Scan Detected',
        description='Host scanned 15 ports in 10 seconds',
        source_ip='198.51.100.23',
        dest_ip='192.168.1.0/24'
    )
    
    # Print dashboard
    manager.print_dashboard()
    
    # Show critical alerts
    print("\n" + "="*60)
    print("🔴 CRITICAL ALERTS REQUIRING IMMEDIATE ACTION")
    print("="*60)
    
    critical = manager.get_critical_alerts()
    for alert in critical:
        print(f"\n[{alert.alert_id}] {alert.title}")
        print(f"  {alert.description}")
        print(f"  Source: {alert.source_ip}")


if __name__ == '__main__':
    main()
