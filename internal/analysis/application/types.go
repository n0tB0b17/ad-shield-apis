package application

import (
	"bytes"
	"sync"
)

type ApplicationProtocolStats struct {
	PacketCount   int
	RequestCount  int
	ResponseCount int
	Domains       map[string]int
	PayloadSize   map[string]int
	Anomalies     map[string]int
}

type TLSMeta struct {
	CipherSuites map[string]int
	Versions     map[string]int
	Certificates int
	SNI          map[string]int // server name indication
}

type ApplicationStats struct {
	ProtocolStats map[string]*ApplicationProtocolStats
	TLSStats      TLSMeta
	streams       map[string]*bytes.Buffer
}

type ApplicationLayerAnalyzer struct {
	Stats ApplicationStats
	mu    sync.Mutex
}
