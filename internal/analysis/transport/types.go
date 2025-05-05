package transport

import (
	"bytes"
	"sync"

	"github.com/google/gopacket"
)

type TCPSegment struct {
	Sequence uint32
	Payload  []byte
}

type TCPStream struct {
	Segments    []TCPSegment
	Reassembled bytes.Buffer
	Complete    bool
}

type TransportStats struct {
	TCPPacketCount  int
	UDPPacketCount  int
	PortStats       map[int]int // port with packets
	TCPConnection   int
	Retransmission  int
	InvalidTCPFlags int
	UDPFloodPorts   map[int]int
	NewStreamData   map[string]*TCPStream        // with tcp segments
	StreamData      map[string]int               // key >> flowKey | value >> count
	streams         map[string][]gopacket.Packet // key >> flowKey
}

type TransportAnalysis struct {
	stats TransportStats
	mu    sync.Mutex
}
