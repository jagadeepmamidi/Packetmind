# PacketMind AI - Getting Started

## Prerequisites

Before you begin, make sure you have:

- **Docker Desktop** installed ([Download here](https://www.docker.com/products/docker-desktop/))
- **Git** installed
- **VS Code** with these extensions:
  - Docker (by Microsoft)
  - Markdown Preview Enhanced
  - Go (by Go Team at Google)
  - Python (by Microsoft)

## Quick Start

### 1. Clone and Setup

```bash
cd c:\Users\jagad\OneDrive\Desktop\alpha\packetmind

# Copy environment template
copy .env.example .env

# Edit .env and add your Gemini API key
# Get one from: https://makersuite.google.com/app/apikey
```

### 2. Build Docker Development Environment

```bash
# Build the development container
docker compose build dev

# Start the development container
docker compose up -d dev

# Enter the container
docker exec -it packetmind-dev /bin/bash
```

### 3. Verify Installation

Inside the Docker container:

```bash
# Check Python
python3 --version

# Check Go
go version

# Check networking tools
tcpdump --version
```

## Project Structure

```
packetmind/
├── capture/              # Go - High-performance packet processing
│   ├── cmd/
│   │   └── capture/      # Main entry point
│   └── internal/
│       └── parser/       # Protocol parsers
│
├── analyzer/             # Python - Analysis & AI
│   ├── core/             # ML models and analysis
│   ├── ai/               # RAG and agents
│   └── api/              # FastAPI backend
│
├── dashboard/            # Next.js - Frontend
│
├── data/                 # Sample PCAPs and models
│
├── docker/               # Docker configuration
│   └── Dockerfile.dev    # Development environment
│
└── docs/                 # Documentation
```

## Next Steps

Once your environment is set up, we'll start with:

1. **Phase 2**: Building a basic PCAP parser in Python
2. Learning how TCP/IP packets are structured
3. Parsing DNS, HTTP, and TCP headers

## Useful Docker Commands

```bash
# Start development environment
docker compose up -d dev

# Enter the container
docker exec -it packetmind-dev /bin/bash

# Stop all containers
docker compose down

# Rebuild after changes
docker compose build dev

# View logs
docker compose logs -f dev
```

## Troubleshooting

### Docker Desktop not running

- Start Docker Desktop from Windows Start menu
- Wait for it to fully start (whale icon in system tray)

### Permission errors with packet capture

- The container has `NET_ADMIN` and `NET_RAW` capabilities
- This allows tcpdump and packet capture to work

### Can't access files in container

- Files are mounted from your Windows directory
- Changes in the container reflect on Windows and vice versa

## Learning Resources

As we build, you'll learn:

- **Docker**: Containerization basics
- **Linux**: Essential networking commands
- **Go**: High-performance programming
- **TCP/IP**: How the internet actually works
- **ML**: Anomaly detection algorithms
- **LLMs**: RAG and multi-agent systems

Ready to start coding! 🚀
