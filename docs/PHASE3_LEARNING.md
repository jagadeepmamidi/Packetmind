# Phase 3: Learning ML for Network Security

## What You're Learning

This phase teaches you **how machine learning detects cyber attacks** using two powerful techniques:

1. **Entropy Analysis** - Detecting randomness (DNS tunneling, encryption)
2. **Baseline Profiling** - Learning "normal" to spot "abnormal"

---

## Core Concepts

### 1. Shannon Entropy - Measuring Randomness

**The Formula:**

```
H(X) = -Σ P(x) * log₂(P(x))

Where:
- H(X) = entropy (randomness score)
- P(x) = probability of character x
- Σ = sum over all unique characters
```

**What It Means:**

- **Low entropy (< 2.5)**: Predictable patterns
  - Example: `"google.com"` → entropy ≈ 2.1
- **High entropy (> 4.0)**: Random/encoded data
  - Example: `"aHR0cHM6Ly9leGFtcGxl"` → entropy ≈ 4.5 (base64!)

**Why Attackers Have High Entropy:**

- Encoding data (base64, hex)
- Encryption (TLS, custom crypto)
- Random domain generation (DGA malware)

---

### 2. Baseline Profiling - The ML Approach

**How It Works:**

```
Step 1: LEARN (Training Phase)
┌─────────────────────────────────┐
│ Observe 1000 packets            │
│ Average size: 500 bytes         │
│ Std dev: 100 bytes              │
│ Common ports: 80, 443, 53       │
└─────────────────────────────────┘

Step 2: DETECT (Inference Phase)
┌─────────────────────────────────┐
│ New packet: 5000 bytes          │
│ Z-score = (5000-500)/100 = 45   │
│ 45 std devs away = ANOMALY! 🚨  │
└─────────────────────────────────┘
```

**Z-Score Interpretation:**

- Z < 2: Normal variation
- Z = 2-3: Unusual but possible
- Z > 3: **Anomaly!** (only 0.3% chance)

---

## Attack Detection Techniques

### 1. DNS Tunneling Detection

**The Attack:**

```
Normal DNS:     google.com
Tunneled DNS:   aHR0cHM6Ly9leGFtcGxl.evil.com
                └─────────┬─────────┘
                    base64 encoded data!
```

**How We Detect It:**

```python
entropy = calculate_entropy("aHR0cHM6Ly9leGFtcGxl")
# entropy = 4.5 (very high!)

if entropy > 3.5:
    alert("Possible DNS tunneling!")
```

**Real Example:**

- Attacker exfiltrates: `"password=admin123"`
- Base64 encoded: `"cGFzc3dvcmQ9YWRtaW4xMjM="`
- Hidden in DNS: `"cGFzc3dvcmQ9YWRtaW4xMjM=.attacker.com"`
- Our detector: **FLAGGED** (entropy 4.6)

---

### 2. Port Scanning Detection

**The Attack:**

```
Attacker probes many ports rapidly:
192.168.1.200 → 10.0.0.50:21   (FTP)
192.168.1.200 → 10.0.0.50:22   (SSH)
192.168.1.200 → 10.0.0.50:23   (Telnet)
192.168.1.200 → 10.0.0.50:80   (HTTP)
... 100 more ports in 10 seconds
```

**How We Detect It:**

```python
# Baseline: Normal user connects to 2-3 ports
# Attacker: Connects to 100+ ports

if unique_ports_per_ip > 20:
    alert("Port scan detected!")
```

---

### 3. DDoS Detection

**The Attack:**

```
Normal Traffic:     100 packets/sec
DDoS Attack:     50,000 packets/sec  (500x increase!)
```

**How We Detect It:**

```python
multiplier = current_rate / baseline_rate
# multiplier = 50000 / 100 = 500

if multiplier > 10:
    alert(f"DDoS attack! {multiplier}x normal traffic")
```

---

### 4. C2 Beaconing Detection

**The Attack:**

```
Malware "phones home" at regular intervals:

Time:  0s    300s   600s   900s   1200s
       │     │      │      │      │
       ●─────●──────●──────●──────●
       └─5min┘      └─5min─┘

Pattern: Clockwork regularity (humans are random!)
```

**How We Detect It:**

```python
# Calculate time intervals between connections
intervals = [300, 300, 300, 300]  # seconds

# Check for regularity
std_dev = stdev(intervals)  # ≈ 0 (very regular!)

if std_dev < 10:  # Too regular for human
    alert("C2 beaconing detected!")
```

---

## Files Created

### 1. Entropy Detector (`entropy_detector.py`)

**Features:**

- Shannon entropy calculation
- DNS tunneling detection
- Base64 pattern recognition
- Threat level classification
- Batch domain analysis

**Usage:**

```python
from entropy_detector import EntropyAnalyzer

analyzer = EntropyAnalyzer()
result = analyzer.analyze_dns_query("aHR0cHM6Ly9.evil.com")

print(result['entropy'])        # 4.5
print(result['threat_level'])   # "MALICIOUS"
print(result['indicators'])     # ["High entropy", "Base64 detected"]
```

---

### 2. Baseline Profiler (`baseline_profiler.py`)

**Features:**

- Statistical baseline learning
- Z-score anomaly detection
- DDoS volume detection
- Protocol/port/IP tracking
- Baseline persistence (save/load)

**Usage:**

```python
from baseline_profiler import TrafficBaseline

baseline = TrafficBaseline()
baseline.learn_from_packets(packets)  # Training
baseline.print_baseline_summary()

# Test new packet
anomaly = baseline.detect_anomalies(new_packet)
if anomaly['is_anomalous']:
    print(f"Anomaly score: {anomaly['anomaly_score']}")
```

---

### 3. Integrated Analysis (`integrated_analysis.py`)

**Complete Pipeline:**

1. Parse PCAP
2. Build baseline
3. Detect entropy anomalies
4. Flag suspicious activity
5. Generate report

**Usage:**

```bash
python analyzer/core/integrated_analysis.py data/samples/attack_combined.pcap
```

---

### 4. Attack Sample Generator (`create_attack_samples.py`)

**Creates Realistic Attacks:**

- DNS tunneling (base64 exfiltration)
- Port scanning (SYN probes)
- DDoS (SYN flood)
- C2 beaconing (periodic connections)

**Usage:**

```bash
python analyzer/core/create_attack_samples.py
```

**Output:**

- `attack_dns_tunneling.pcap`
- `attack_port_scan.pcap`
- `attack_ddos.pcap`
- `attack_c2_beaconing.pcap`
- `attack_combined.pcap` (all attacks)

---

## Hands-On Exercises

### Exercise 1: Test Entropy Detection

```bash
# Create attack samples
python analyzer/core/create_attack_samples.py

# Run entropy analysis
python analyzer/core/entropy_detector.py
```

**Challenge:** Can you identify which domains are tunneling data?

---

### Exercise 2: Build Your Baseline

```bash
# Create normal traffic
python analyzer/core/create_sample_pcap.py

# Parse it
python analyzer/core/pcap_parser.py data/samples/sample_traffic.pcap

# Build baseline
python analyzer/core/integrated_analysis.py data/samples/sample_traffic.pcap
```

**Challenge:** What's the average packet size in your baseline?

---

### Exercise 3: Detect Attacks

```bash
# Run full analysis on attack traffic
python analyzer/core/integrated_analysis.py data/samples/attack_combined.pcap
```

**Challenge:** How many DNS tunneling attempts were detected?

---

## The Math Behind It

### Shannon Entropy Calculation

```python
def calculate_entropy(data):
    # Count character frequencies
    freq = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
```

**Example:**

```
Data: "aaaa"
Frequencies: {'a': 4}
Probability: 4/4 = 1.0
Entropy: -1.0 * log₂(1.0) = 0.0  (no randomness!)

Data: "abcd"
Frequencies: {'a': 1, 'b': 1, 'c': 1, 'd': 1}
Probability: 1/4 = 0.25 each
Entropy: -4 * (0.25 * log₂(0.25)) = 2.0  (random!)
```

---

### Z-Score Anomaly Detection

```python
def detect_anomaly(value, mean, std_dev):
    z_score = (value - mean) / std_dev

    if abs(z_score) > 3:
        return "ANOMALY"
    return "NORMAL"
```

**Example:**

```
Baseline: mean=500 bytes, std_dev=100 bytes
New packet: 5000 bytes

Z-score = (5000 - 500) / 100 = 45
45 > 3 → ANOMALY!
```

---

## Key Takeaways

| Concept        | What It Detects                  | How It Works                    |
| -------------- | -------------------------------- | ------------------------------- |
| **Entropy**    | Encoding, encryption, randomness | Measures character distribution |
| **Z-Score**    | Statistical outliers             | Measures std devs from mean     |
| **Baseline**   | Deviations from normal           | Learns patterns, flags changes  |
| **Volume**     | DDoS attacks                     | Compares traffic rates          |
| **Regularity** | C2 beaconing                     | Detects clockwork patterns      |

---

## Real-World Impact

**These techniques detect:**

- 🎯 DNS tunneling (data exfiltration)
- 🎯 Port scans (reconnaissance)
- 🎯 DDoS attacks (service disruption)
- 🎯 C2 communication (malware control)
- 🎯 Encrypted payloads (suspicious traffic)

**This is how enterprise security tools work!** You've just built the core of:

- Intrusion Detection Systems (IDS)
- Security Information and Event Management (SIEM)
- Network Traffic Analysis (NTA)

---

## Next Steps

Phase 3 continues with:

- [ ] ML models for threat classification (Random Forest, Isolation Forest)
- [ ] Signature-based detection rules (Snort-like rules)
- [ ] Real-time alerting system

**You're building real AI-powered security!** 🚀
