package network

import (
	"sync"

	"github.com/google/gopacket"
)

type NetworkStats struct {
	PacketCount       int
	IpStats           map[string]int // ip -> packets
	FragmentedPackets int
	ReassembledFlows  int
	TTLStats          map[uint8]int
	ProtocolDist      map[string]int
	fragments         map[string][]gopacket.Packet
}

type NetworkAnalyzer struct {
	stats NetworkStats
	mu    sync.Mutex
}
