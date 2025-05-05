package transport

import (
	"fmt"
	"sort"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewTransportAnalyzer() *TransportAnalysis {
	return &TransportAnalysis{
		stats: TransportStats{
			UDPFloodPorts: make(map[int]int),
			NewStreamData: make(map[string]*TCPStream),
			PortStats:     make(map[int]int),
			streams:       make(map[string][]gopacket.Packet),
		},
	}
}

func (ta *TransportAnalysis) Analyze(packet gopacket.Packet) error {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		ta.mu.Lock()
		defer ta.mu.Unlock()

		ta.stats.TCPPacketCount++
		ta.stats.PortStats[int(tcp.SrcPort)]++
		ta.stats.PortStats[int(tcp.DstPort)]++

		flowKey := fmt.Sprintf("%s:%d-%s:%d",
			packet.NetworkLayer().NetworkFlow().Src().String(),
			tcp.SrcPort,
			packet.NetworkLayer().NetworkFlow().Dst().String(),
			tcp.DstPort,
		)

		if tcp.SYN && !tcp.ACK {
			ta.stats.streams[flowKey] = append(ta.stats.streams[flowKey], packet)
		} else if tcp.SYN && tcp.ACK {
			if _, exists := ta.stats.streams[flowKey]; exists {
				ta.stats.TCPConnection++
			}
		} else if tcp.FIN || tcp.RST {
			ta.handleStreamCompletion(flowKey)
		}

		if (tcp.FIN && tcp.URG && tcp.PSH) || (tcp.SYN && tcp.FIN) {
			ta.stats.InvalidTCPFlags++ // need to hold packet as well (future work)
		}

		ta.handleTCPStream(flowKey, packet, tcp)
		return nil
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		ta.mu.Lock()
		defer ta.mu.Unlock()

		ta.stats.UDPPacketCount++
		ta.stats.PortStats[int(udp.SrcPort)]++
		ta.stats.PortStats[int(udp.DstPort)]++
		ta.stats.UDPFloodPorts[int(udp.DstPort)]++

		// flowKey := fmt.Sprintf("%s:%d-%s:%d",
		// 	packet.NetworkLayer().NetworkFlow().Src().String(),
		// 	udp.SrcPort,
		// 	packet.NetworkLayer().NetworkFlow().Dst().String(),
		// 	udp.DstPort,
		// )

		// ta.stats.StreamData[flowKey] += len(udp.Payload)
		return nil
	}

	return nil
}

func (ta *TransportAnalysis) GetResult() map[string]interface{} {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	floodResult := make(map[int]int)
	for port, count := range ta.stats.UDPFloodPorts {
		if count > 100 {
			floodResult[port] = count
		}
	}

	streamSynopsis := make(map[string]int)
	for key, stream := range ta.stats.NewStreamData {
		streamSynopsis[key] = stream.Reassembled.Len()
	}

	return map[string]interface{}{
		"TCPPacketCount":  ta.stats.TCPPacketCount,
		"UDPPacketCount":  ta.stats.UDPPacketCount,
		"PortStats":       ta.stats.PortStats,
		"TCPConnections":  ta.stats.TCPConnection,
		"Retransmissions": ta.stats.Retransmission,
		"InvalidTCPFlags": ta.stats.InvalidTCPFlags,
		"UDPFloodPorts":   floodResult,
		"StreamData":      streamSynopsis,
	}
}

func (ta *TransportAnalysis) handleTCPStream(flowKey string, packet gopacket.Packet, tcp *layers.TCP) {
	if len(tcp.Payload) == 0 {
		return
	}

	segments := ta.stats.streams[flowKey]
	for _, segment := range segments {
		prevTCP := segment.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp.Seq == prevTCP.Seq && len(tcp.Payload) > 0 {
			ta.stats.Retransmission++
			return
		}
	}

	ta.stats.streams[flowKey] = append(ta.stats.streams[flowKey], packet)
	if _, exist := ta.stats.NewStreamData[flowKey]; !exist {
		ta.stats.NewStreamData[flowKey] = &TCPStream{} // if doesn't exist, assign new
	}

	stream := ta.stats.NewStreamData[flowKey]
	stream.Segments = append(stream.Segments, TCPSegment{
		Sequence: tcp.Seq,
		Payload:  tcp.Payload,
	})

	sort.Slice(stream.Segments, func(i, j int) bool {
		return stream.Segments[i].Sequence < stream.Segments[j].Sequence
	})

	stream.Reassembled.Reset()
	for _, segment := range stream.Segments {
		stream.Reassembled.Write(segment.Payload) // reassembling segments
	}

}

func (ta *TransportAnalysis) handleStreamCompletion(flowKey string) {
	if streamData, exists := ta.stats.NewStreamData[flowKey]; exists && len(streamData.Segments) > 0 {
		streamData.Complete = true
		fmt.Printf("Completed TCP stream %s with %d bytes reassembled \n", flowKey, streamData.Reassembled.Len())
		delete(ta.stats.streams, flowKey)
	}
}

func (ta *TransportAnalysis) ProcessPackets(packetChan <-chan gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for packet := range packetChan {
		if err := ta.Analyze(packet); err != nil {
			fmt.Println("Error while processing packets")
		}
	}
}
