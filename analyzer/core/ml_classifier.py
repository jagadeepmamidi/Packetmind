"""
ML-Based Threat Classifier

This module teaches you how to use machine learning to classify network threats.

Learning objectives:
- Understand supervised learning for security
- Use Random Forest and Isolation Forest
- Feature engineering from network data
- Train and evaluate ML models

Key concept: ML learns patterns from labeled data to predict threats!
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from typing import Dict, List, Tuple
import json


class ThreatClassifier:
    """
    ML-based threat classification
    
    Uses two approaches:
    1. Random Forest (supervised) - learns from labeled examples
    2. Isolation Forest (unsupervised) - detects outliers
    """
    
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.iso_model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
        # Threat categories
        self.threat_types = {
            0: 'NORMAL',
            1: 'PORT_SCAN',
            2: 'DNS_TUNNELING',
            3: 'DDOS',
            4: 'C2_BEACONING'
        }
    
    def extract_features(self, packet_info: Dict) -> List[float]:
        """
        Extract ML features from packet
        
        Features (10 total):
        1. Packet size
        2. Port number (normalized)
        3. Protocol (TCP=1, UDP=2, ICMP=3)
        4. Payload entropy (if available)
        5. Is common port (80, 443, 53, 22)
        6. Has payload
        7. TCP flags count
        8. Source port (normalized)
        9. Is private IP
        10. DNS query length (if DNS)
        """
        features = []
        
        # Feature 1: Packet size
        features.append(packet_info.get('payload_size', 0))
        
        # Feature 2: Destination port (normalized to 0-1)
        dst_port = packet_info.get('dst_port', 0)
        features.append(dst_port / 65535.0 if dst_port else 0)
        
        # Feature 3: Protocol
        protocol = 0
        if 'TCP' in packet_info.get('layers', []):
            protocol = 1
        elif 'UDP' in packet_info.get('layers', []):
            protocol = 2
        elif 'ICMP' in packet_info.get('layers', []):
            protocol = 3
        features.append(protocol)
        
        # Feature 4: Payload entropy (placeholder - would calculate from payload)
        features.append(0.0)  # Would use entropy_detector here
        
        # Feature 5: Is common port
        common_ports = {80, 443, 53, 22, 25, 21}
        is_common = 1 if dst_port in common_ports else 0
        features.append(is_common)
        
        # Feature 6: Has payload
        has_payload = 1 if packet_info.get('payload_size', 0) > 0 else 0
        features.append(has_payload)
        
        # Feature 7: TCP flags count
        flags = packet_info.get('flags', '')
        flag_count = len(flags.split('|')) if flags else 0
        features.append(flag_count)
        
        # Feature 8: Source port (normalized)
        src_port = packet_info.get('src_port', 0)
        features.append(src_port / 65535.0 if src_port else 0)
        
        # Feature 9: Is private IP
        src_ip = packet_info.get('src_ip', '')
        is_private = 1 if src_ip.startswith(('192.168.', '10.', '172.')) else 0
        features.append(is_private)
        
        # Feature 10: DNS query length
        dns_query = packet_info.get('dns_query', '')
        features.append(len(dns_query) if dns_query else 0)
        
        return features
    
    def create_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create synthetic training data
        
        In real-world: you'd have labeled PCAP files
        Here: we simulate different attack patterns
        """
        X = []  # Features
        y = []  # Labels
        
        # NORMAL traffic (label 0)
        for _ in range(100):
            features = [
                np.random.randint(100, 1500),  # Normal packet size
                np.random.choice([80, 443, 53]) / 65535.0,  # Common ports
                1,  # TCP
                2.5,  # Low entropy
                1,  # Is common port
                1,  # Has payload
                2,  # Normal flags
                np.random.randint(1024, 65535) / 65535.0,  # Random src port
                1,  # Private IP
                15  # Normal DNS length
            ]
            X.append(features)
            y.append(0)
        
        # PORT SCAN (label 1)
        for _ in range(50):
            features = [
                60,  # Small packets
                np.random.randint(1, 65535) / 65535.0,  # Random ports
                1,  # TCP
                0.0,  # No payload
                0,  # Not common port
                0,  # No payload
                1,  # SYN only
                np.random.randint(1024, 65535) / 65535.0,
                1,
                0
            ]
            X.append(features)
            y.append(1)
        
        # DNS TUNNELING (label 2)
        for _ in range(50):
            features = [
                200,  # Larger DNS packets
                53 / 65535.0,  # DNS port
                2,  # UDP
                4.5,  # High entropy!
                1,  # DNS port
                1,  # Has payload
                0,  # UDP no flags
                np.random.randint(1024, 65535) / 65535.0,
                1,
                60  # Long DNS query!
            ]
            X.append(features)
            y.append(2)
        
        # DDOS (label 3)
        for _ in range(50):
            features = [
                40,  # Tiny packets
                80 / 65535.0,  # Target port
                1,  # TCP
                0.0,  # No payload
                1,  # Common port
                0,  # No payload
                1,  # SYN flood
                np.random.randint(1, 65535) / 65535.0,  # Spoofed
                0,  # Not private
                0
            ]
            X.append(features)
            y.append(3)
        
        # C2 BEACONING (label 4)
        for _ in range(50):
            features = [
                150,  # Small encrypted payload
                443 / 65535.0,  # HTTPS
                1,  # TCP
                4.8,  # Encrypted (high entropy)
                1,  # HTTPS port
                1,  # Has payload
                2,  # PSH|ACK
                np.random.randint(1024, 65535) / 65535.0,
                1,
                0
            ]
            X.append(features)
            y.append(4)
        
        return np.array(X), np.array(y)
    
    def train(self):
        """Train both ML models"""
        print("🎓 Training ML models...\n")
        
        # Create training data
        X, y = self.create_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train Random Forest (supervised)
        print("Training Random Forest (supervised learning)...")
        self.rf_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.rf_model.predict(X_test)
        accuracy = np.mean(y_pred == y_test)
        print(f"  ✓ Accuracy: {accuracy:.2%}\n")
        
        # Train Isolation Forest (unsupervised)
        print("Training Isolation Forest (anomaly detection)...")
        self.iso_model.fit(X_train)
        print("  ✓ Model trained\n")
        
        self.is_trained = True
        
        # Print classification report
        print("Classification Report:")
        print("-" * 60)
        target_names = [self.threat_types[i] for i in range(5)]
        print(classification_report(y_test, y_pred, target_names=target_names))
    
    def predict(self, packet_info: Dict) -> Dict:
        """Predict threat type for a packet"""
        if not self.is_trained:
            return {'error': 'Model not trained'}
        
        # Extract features
        features = np.array([self.extract_features(packet_info)])
        
        # Random Forest prediction
        rf_pred = self.rf_model.predict(features)[0]
        rf_proba = self.rf_model.predict_proba(features)[0]
        
        # Isolation Forest prediction (-1 = anomaly, 1 = normal)
        iso_pred = self.iso_model.predict(features)[0]
        
        return {
            'threat_type': self.threat_types[rf_pred],
            'confidence': float(max(rf_proba)),
            'is_anomaly': iso_pred == -1,
            'probabilities': {
                self.threat_types[i]: float(prob)
                for i, prob in enumerate(rf_proba)
            }
        }
    
    def save_model(self, filename: str):
        """Save trained model"""
        import pickle
        
        with open(filename, 'wb') as f:
            pickle.dump({
                'rf_model': self.rf_model,
                'iso_model': self.iso_model,
                'is_trained': self.is_trained
            }, f)
        
        print(f"💾 Model saved to: {filename}")
    
    def load_model(self, filename: str):
        """Load trained model"""
        import pickle
        
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        
        self.rf_model = data['rf_model']
        self.iso_model = data['iso_model']
        self.is_trained = data['is_trained']
        
        print(f"📂 Model loaded from: {filename}")


def main():
    """Demo ML threat classification"""
    print("="*60)
    print("🤖 ML-BASED THREAT CLASSIFIER")
    print("="*60)
    print()
    
    # Create and train classifier
    classifier = ThreatClassifier()
    classifier.train()
    
    # Test predictions
    print("\n" + "="*60)
    print("🎯 TESTING PREDICTIONS")
    print("="*60)
    print()
    
    test_packets = [
        {
            'name': 'Normal HTTP',
            'payload_size': 500,
            'dst_port': 80,
            'layers': ['IP', 'TCP', 'HTTP'],
            'src_port': 54321
        },
        {
            'name': 'DNS Tunneling',
            'payload_size': 200,
            'dst_port': 53,
            'layers': ['IP', 'UDP', 'DNS'],
            'dns_query': 'aHR0cHM6Ly9leGFtcGxlLmNvbS9zZWNyZXQ=.evil.com',
            'src_port': 12345
        },
        {
            'name': 'Port Scan',
            'payload_size': 0,
            'dst_port': 8080,
            'layers': ['IP', 'TCP'],
            'flags': 'SYN',
            'src_port': 54321
        }
    ]
    
    for packet in test_packets:
        name = packet.pop('name')
        result = classifier.predict(packet)
        
        print(f"Packet: {name}")
        print(f"  Predicted: {result['threat_type']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print(f"  Is Anomaly: {result['is_anomaly']}")
        print()


if __name__ == '__main__':
    main()
