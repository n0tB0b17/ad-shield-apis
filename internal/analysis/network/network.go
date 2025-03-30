package network

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewNetworkAnalyzer() *NetworkAnalyzer {
	return &NetworkAnalyzer{
		stats: NetworkStats{
			IpStats:      make(map[string]int),
			TTLStats:     make(map[uint8]int),
			ProtocolDist: make(map[string]int),
			fragments:    make(map[string][]gopacket.Packet),
		},
	}
}

func (na *NetworkAnalyzer) GetResult() map[string]interface{} {
	return map[string]interface{}{
		"TotalPacket":       na.stats.PacketCount,
		"FragmentedPackets": na.stats.FragmentedPackets,
		"IPStats":           na.stats.IpStats,
		"ReassembledFlows":  na.stats.ReassembledFlows,
		"TTLStats":          na.stats.TTLStats,
		"ProtocolDist":      na.stats.ProtocolDist,
	}
}

// process a single packet
func (na *NetworkAnalyzer) Analyze(packet gopacket.Packet) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	if ipLayer == nil {
		return nil // skip packet
	}

	na.stats.PacketCount++
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		na.mu.Lock()
		srcIP, destIP := ipv4.SrcIP.String(), ipv4.DstIP.String()
		na.stats.IpStats[srcIP]++
		na.stats.IpStats[destIP]++
		na.stats.TTLStats[ipv4.TTL]++
		na.stats.ProtocolDist[ipv4.Protocol.String()]++

		if ipv4.Flags&layers.IPv4MoreFragments != 0 || ipv4.FragOffset > 0 {
			na.stats.FragmentedPackets++
			flowKey := fmt.Sprintf("%s-%s-%s-%d", srcIP, destIP, ipv4.Protocol.String(), ipv4.Id)
			na.handleFragments(flowKey, packet)
		}

		na.mu.Unlock()
		return nil
	}

	if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		na.mu.Lock()
		srcIP, destIP := ipv6.SrcIP.String(), ipv6.DstIP.String()
		na.stats.IpStats[srcIP]++
		na.stats.IpStats[destIP]++
		na.stats.TTLStats[ipv6.HopLimit]++
		na.stats.ProtocolDist[ipv6.NextHeader.String()]++

		if fragLayer := packet.Layer(layers.LayerTypeIPv6Fragment); fragLayer != nil {
			na.stats.FragmentedPackets++
			ipv6Fragment := fragLayer.(*layers.IPv6Fragment)
			flowkey := fmt.Sprintf("%s-%s-%s-%d", srcIP, destIP, ipv6.NextHeader.String(), ipv6Fragment.Identification)
			na.handleFragments(flowkey, packet)
		}

		na.mu.Unlock()
	}

	return nil
}

func (na *NetworkAnalyzer) ProcessPackets(packetChan <-chan gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for packet := range packetChan {
		if err := na.Analyze(packet); err != nil {
			fmt.Printf("error while analyzing packets: %+v \n", err)
		}
	}
}

func (na *NetworkAnalyzer) handleFragments(flowKey string, packet gopacket.Packet) {
	na.stats.fragments[flowKey] = append(na.stats.fragments[flowKey], packet)

	var totalLength int
	complete := false

	for _, frags := range na.stats.fragments[flowKey] {
		if ipv4, ok := frags.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			totalLength += len(ipv4.Contents)
			if ipv4.Flags&layers.IPv4MoreFragments == 0 {
				complete = true
			}
		} else if ipv6, ok := frags.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
			totalLength += len(ipv6.Contents)
			if !ipv6.MoreFragments {
				complete = true
			}
		}
	}

	if complete {
		na.stats.ReassembledFlows++
		fmt.Printf("Reassembled flow %s with total length %d \n", flowKey, totalLength)
		delete(na.stats.fragments, flowKey)
	}
}
