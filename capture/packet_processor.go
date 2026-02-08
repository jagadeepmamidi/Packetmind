// High-Performance Packet Processor in Go
//
// This teaches you why Go is perfect for network programming:
// - Goroutines for concurrency
// - Fast execution (compiled language)
// - Great networking libraries
//
// Learning objectives:
// - Understand Go's concurrency model
// - Use gopacket for packet processing
// - Build high-performance network tools

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketStats holds packet processing statistics
type PacketStats struct {
	TotalPackets   int
	TCPPackets     int
	UDPPackets     int
	ICMPPackets    int
	DNSQueries     int
	HTTPRequests   int
	BytesProcessed int64
}

// PacketProcessor processes packets at high speed
type PacketProcessor struct {
	stats       PacketStats
	startTime   time.Time
	packetChan  chan gopacket.Packet
	workerCount int
}

// NewPacketProcessor creates a new processor
func NewPacketProcessor(workers int) *PacketProcessor {
	return &PacketProcessor{
		stats:       PacketStats{},
		startTime:   time.Now(),
		packetChan:  make(chan gopacket.Packet, 1000),
		workerCount: workers,
	}
}

// ProcessPCAP reads and processes a PCAP file
func (pp *PacketProcessor) ProcessPCAP(filename string) error {
	fmt.Printf("🚀 Processing PCAP: %s\n", filename)
	fmt.Printf("⚡ Using %d worker goroutines\n\n", pp.workerCount)

	// Open PCAP file
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("error opening pcap: %v", err)
	}
	defer handle.Close()

	// Start worker goroutines
	for i := 0; i < pp.workerCount; i++ {
		go pp.worker(i)
	}

	// Read packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		pp.packetChan <- packet
		pp.stats.TotalPackets++
	}

	// Close channel and wait for workers
	close(pp.packetChan)
	time.Sleep(100 * time.Millisecond) // Give workers time to finish

	return nil
}

// worker processes packets concurrently
func (pp *PacketProcessor) worker(id int) {
	for packet := range pp.packetChan {
		pp.analyzePacket(packet)
	}
}

// analyzePacket extracts information from a packet
func (pp *PacketProcessor) analyzePacket(packet gopacket.Packet) {
	// Get packet size
	pp.stats.BytesProcessed += int64(len(packet.Data()))

	// Check for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		pp.stats.TCPPackets++

		tcp, _ := tcpLayer.(*layers.TCP)

		// Check for HTTP (port 80 or 8080)
		if tcp.DstPort == 80 || tcp.DstPort == 8080 || tcp.SrcPort == 80 || tcp.SrcPort == 8080 {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := string(appLayer.Payload())
				if len(payload) > 4 {
					if payload[:3] == "GET" || payload[:4] == "POST" || payload[:4] == "HTTP" {
						pp.stats.HTTPRequests++
					}
				}
			}
		}
	}

	// Check for UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		pp.stats.UDPPackets++

		udp, _ := udpLayer.(*layers.UDP)

		// Check for DNS (port 53)
		if udp.DstPort == 53 || udp.SrcPort == 53 {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if len(dns.Questions) > 0 {
					pp.stats.DNSQueries++
				}
			}
		}
	}

	// Check for ICMP
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		pp.stats.ICMPPackets++
	}
}

// PrintStats prints processing statistics
func (pp *PacketProcessor) PrintStats() {
	duration := time.Since(pp.startTime)
	packetsPerSec := float64(pp.stats.TotalPackets) / duration.Seconds()
	mbytesPerSec := float64(pp.stats.BytesProcessed) / duration.Seconds() / 1024 / 1024

	fmt.Println("\n" + "============================================================")
	fmt.Println("📊 PACKET PROCESSING STATISTICS")
	fmt.Println("============================================================")
	fmt.Printf("Total Packets:     %d\n", pp.stats.TotalPackets)
	fmt.Printf("TCP Packets:       %d\n", pp.stats.TCPPackets)
	fmt.Printf("UDP Packets:       %d\n", pp.stats.UDPPackets)
	fmt.Printf("ICMP Packets:      %d\n", pp.stats.ICMPPackets)
	fmt.Printf("DNS Queries:       %d\n", pp.stats.DNSQueries)
	fmt.Printf("HTTP Requests:     %d\n", pp.stats.HTTPRequests)
	fmt.Printf("Bytes Processed:   %d (%.2f MB)\n", pp.stats.BytesProcessed, float64(pp.stats.BytesProcessed)/1024/1024)
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("Processing Time:   %.2f seconds\n", duration.Seconds())
	fmt.Printf("Packets/sec:       %.0f\n", packetsPerSec)
	fmt.Printf("Throughput:        %.2f MB/s\n", mbytesPerSec)
	fmt.Println("============================================================")
}

func main() {
	// Check arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run packet_processor.go <pcap_file>")
		fmt.Println("\nExample:")
		fmt.Println("  go run packet_processor.go ../data/samples/sample_traffic.pcap")
		os.Exit(1)
	}

	pcapFile := os.Args[1]

	// Create processor with 4 workers
	processor := NewPacketProcessor(4)

	// Process PCAP
	if err := processor.ProcessPCAP(pcapFile); err != nil {
		log.Fatal(err)
	}

	// Print statistics
	processor.PrintStats()

	fmt.Println("\n✅ Processing complete!")
	fmt.Println("\n💡 Why Go is faster:")
	fmt.Println("  • Compiled (not interpreted like Python)")
	fmt.Println("  • Goroutines for concurrency")
	fmt.Println("  • Efficient memory management")
	fmt.Println("  • Native networking libraries")
}
