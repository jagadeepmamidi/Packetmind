# Phase 2: Learning TCP/IP with PacketMind

## What You'll Learn in This Phase

This phase teaches you **how the internet actually works** by analyzing real network packets at the byte level.

### Core Concepts

1. **The OSI Model (Simplified)**

   ```
   Layer 7: Application (HTTP, DNS)
   Layer 4: Transport (TCP, UDP)
   Layer 3: Network (IP)
   Layer 2: Data Link (Ethernet)
   ```

2. **TCP Three-Way Handshake**

   ```
   Client                    Server
      │                         │
      │──────── SYN ──────────→ │  "Let's connect!"
      │                         │
      │←───── SYN-ACK ─────────│  "OK, let's connect!"
      │                         │
      │──────── ACK ──────────→ │  "Great, connected!"
      │                         │
      │    Data Transfer...     │
   ```

3. **TCP Flags** (The Secret Handshake)
   - **SYN**: Synchronize (start connection)
   - **ACK**: Acknowledge (I got your message)
   - **FIN**: Finish (close connection)
   - **RST**: Reset (abort connection)
   - **PSH**: Push (send data immediately)

4. **Ports** (The Apartment Numbers)
   - Port 80: HTTP (websites)
   - Port 443: HTTPS (secure websites)
   - Port 53: DNS (domain lookups)
   - Port 22: SSH (secure shell)

## Files Created

### 1. PCAP Parser (`analyzer/core/pcap_parser.py`)

**What it does:**

- Reads PCAP files (packet capture files)
- Extracts IP addresses, ports, protocols
- Parses TCP flags to understand connection state
- Detects HTTP requests and DNS queries
- Generates statistics and JSON reports

**Key features:**

```python
# Parse a packet and see its layers
info = parser.analyze_packet(packet)
# Output: {'layers': ['IP', 'TCP', 'HTTP'], ...}

# See TCP flags
info['flags']  # "SYN|ACK" or "PSH|ACK"

# Extract DNS queries
info['dns_query']  # "google.com"
```

### 2. Sample PCAP Generator (`analyzer/core/create_sample_pcap.py`)

**What it creates:**

- TCP three-way handshake (SYN → SYN-ACK → ACK)
- HTTP GET request
- DNS query and response
- HTTPS encrypted traffic
- UDP packets
- TCP connection close (FIN)
- ICMP ping

**Why this is cool:**
You're literally creating network traffic from scratch! This teaches you how packets are constructed.

## How to Use

### Step 1: Build Docker Environment

```bash
cd c:\Users\jagad\OneDrive\Desktop\alpha\packetmind

# Build the container (first time only)
docker compose build dev

# Start the container
docker compose up -d dev

# Enter the container
docker exec -it packetmind-dev /bin/bash
```

### Step 2: Create Sample Traffic

Inside the Docker container:

```bash
# Navigate to workspace
cd /workspace

# Create sample PCAP file
python3 analyzer/core/create_sample_pcap.py
```

**Output:**

```
🔨 Creating sample network traffic...

1️⃣  Creating TCP handshake (the famous SYN-SYN/ACK-ACK)
2️⃣  Creating HTTP GET request
3️⃣  Creating DNS query for google.com
4️⃣  Creating DNS response
5️⃣  Creating HTTPS traffic (encrypted)
6️⃣  Creating generic UDP packet
7️⃣  Creating TCP FIN (closing connection)
8️⃣  Creating ICMP ping

✅ Created sample PCAP: data/samples/sample_traffic.pcap
📦 Total packets: 8
```

### Step 3: Analyze the Traffic

```bash
# Run the parser
python3 analyzer/core/pcap_parser.py data/samples/sample_traffic.pcap
```

**You'll see:**

```
📂 Loading PCAP file: data/samples/sample_traffic.pcap
✅ Loaded 8 packets

🔍 Analyzing 8 packets...

Packet #1: IP → TCP
  📍 192.168.1.100:54321 → 93.184.216.34:80
  🚩 TCP Flags: SYN

Packet #2: IP → TCP
  📍 93.184.216.34:80 → 192.168.1.100:54321
  🚩 TCP Flags: SYN|ACK

Packet #3: IP → TCP
  📍 192.168.1.100:54321 → 93.184.216.34:80
  🚩 TCP Flags: ACK

Packet #4: IP → TCP → HTTP
  📍 192.168.1.100:54321 → 93.184.216.34:80
  🚩 TCP Flags: PSH|ACK
  🌍 HTTP GET request
  📦 Payload: 41 bytes

Packet #5: IP → UDP → DNS
  📍 192.168.1.100:53210 → 8.8.8.8:53
  🌐 DNS Query: google.com

...

📊 PCAP ANALYSIS SUMMARY
============================================================
Total Packets:     8
TCP Packets:       5
UDP Packets:       2
DNS Queries:       1
HTTP Requests:     1
Unique IPs:        4
Unique Ports:      8
============================================================
```

## The "Aha!" Moments

### 1. Seeing the TCP Handshake

Look at packets #1, #2, #3:

```
Packet #1: SYN          → "Can we connect?"
Packet #2: SYN|ACK      → "Yes! Here's my SYN too"
Packet #3: ACK          → "Got it, we're connected!"
```

**This is how EVERY TCP connection starts!** When you visit a website, this happens first.

### 2. Understanding Flags

```
PSH|ACK = "I'm sending data (PSH) and acknowledging yours (ACK)"
FIN|ACK = "I'm done (FIN) and acknowledging (ACK)"
```

Flags are like emojis for network packets! They tell you what's happening.

### 3. Ports Tell the Story

```
Port 80  = HTTP  = Regular website
Port 443 = HTTPS = Secure website
Port 53  = DNS   = Looking up domain names
```

When you see `192.168.1.100:54321 → 93.184.216.34:80`, you know:

- Source: Your computer (192.168.1.100) from random port 54321
- Destination: Web server (93.184.216.34) on HTTP port 80

## Next Steps

Now that you understand packet structure, we'll:

1. **Parse Ethernet frames** (MAC addresses)
2. **Deep dive into IP headers** (TTL, fragmentation)
3. **Understand TCP sequence numbers** (how data is ordered)
4. **Build TCP stream reconstruction** (reassemble conversations)
5. **Write a Go version** (100x faster!)

## Exercises

### Exercise 1: Analyze Your Own Traffic

Capture real traffic from your computer:

```bash
# On Windows (run as Administrator)
# Install Wireshark first
# Then capture 10 packets:
tshark -i WiFi -c 10 -w my_traffic.pcap

# Copy to packetmind folder and analyze
python analyzer\core\pcap_parser.py my_traffic.pcap
```

### Exercise 2: Modify the Sample Generator

Edit `create_sample_pcap.py` and add:

- A packet to port 22 (SSH)
- A packet to port 25 (SMTP/Email)
- Multiple DNS queries

### Exercise 3: Find the Handshake

Run the parser and identify:

1. Which packets form the TCP handshake?
2. What are their sequence numbers?
3. What flags are set?

## Key Takeaways

| Concept           | What You Learned                                |
| ----------------- | ----------------------------------------------- |
| **Packets**       | Data is sent in small chunks with headers       |
| **Layers**        | Ethernet → IP → TCP → HTTP (like Russian dolls) |
| **TCP Handshake** | SYN → SYN-ACK → ACK (the internet's greeting)   |
| **Flags**         | Tell you what's happening in the connection     |
| **Ports**         | Identify which service/application              |
| **Scapy**         | Python library to create and parse packets      |

**The Big Picture:**
Every time you load a webpage, send an email, or stream a video, this is happening under the hood. You're now seeing the Matrix! 🤯

Ready to go deeper? 🚀
