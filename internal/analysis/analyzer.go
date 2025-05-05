package analysis

import "github.com/google/gopacket"

type Analyzer interface {
	Analysis(packet gopacket.Packet) error
	GetResults() map[string]interface{}
}
