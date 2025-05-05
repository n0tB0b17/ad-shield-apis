package application

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewApplicationLayerAnalyzer() *ApplicationLayerAnalyzer {
	return &ApplicationLayerAnalyzer{
		Stats: ApplicationStats{
			ProtocolStats: map[string]*ApplicationProtocolStats{
				"HTTP": {
					Domains:     make(map[string]int),
					PayloadSize: make(map[string]int),
					Anomalies:   make(map[string]int),
				},
				"DNS": {
					Domains:     make(map[string]int),
					PayloadSize: make(map[string]int),
					Anomalies:   make(map[string]int),
				},
				"FTP": {
					Domains:     make(map[string]int),
					PayloadSize: make(map[string]int),
					Anomalies:   make(map[string]int),
				},
				"SMTP": {
					Domains:     make(map[string]int),
					PayloadSize: make(map[string]int),
					Anomalies:   make(map[string]int),
				},
				"TLS": {
					Domains:     make(map[string]int),
					PayloadSize: make(map[string]int),
					Anomalies:   make(map[string]int),
				},
			},
			TLSStats: TLSMeta{
				CipherSuites: make(map[string]int),
				Versions:     make(map[string]int),
				SNI:          make(map[string]int),
			},
			streams: make(map[string]*bytes.Buffer),
		},
	}
}

func (a *ApplicationLayerAnalyzer) Analyze(packet gopacket.Packet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	flowKey := a.getFlowKey(packet)
	if flowKey == "" {
		return nil
	}

	if _, exists := a.Stats.streams[flowKey]; !exists {
		a.Stats.streams[flowKey] = new(bytes.Buffer)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 {
			a.Stats.streams[flowKey].Write(tcp.Payload)
			a.analyzeTCPApplication(flowKey, tcp, packet)
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if len(udp.Payload) > 0 {
			a.Stats.streams[flowKey].Write(udp.Payload)
			a.analyzeUDPApplication(flowKey, udp, packet)
		}
	}

	return nil
}

func (a *ApplicationLayerAnalyzer) analyzeTCPApplication(flowKey string, tcp *layers.TCP, packet gopacket.Packet) {
	payload := a.Stats.streams[flowKey].Bytes()
	// detect http protocol
	a.detectHTTPProtocol(tcp, payload, flowKey)
	a.detectFTPProtocol(tcp, payload, flowKey)
	a.detectSMTPProtocol(tcp, payload, flowKey)
	// a.detectTLSProtocol(packet, tcp, payload, flowKey)
}

// func (a *ApplicationLayerAnalyzer) detectTLSProtocol(packet gopacket.Packet, tcp *layers.TCP, payload []byte, flowkey string) {
// 	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
// 		// tls := tlsLayer.(*layers.TLS)
// 		tlsStats := a.Stats.ProtocolStats["TLS"]
// 		tlsStats.PacketCount++
// 		tlsStats.PayloadSize[flowkey] = len(payload)

// 	}
// }

func (a *ApplicationLayerAnalyzer) detectHTTPProtocol(tcp *layers.TCP, payload []byte, flowKey string) {
	httpMethods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
		[]byte("PATCH "),
	}

	isHttp := tcp.SrcPort == 80 || tcp.DstPort == 80
	if !isHttp {
		for _, method := range httpMethods {
			if bytes.HasPrefix(payload, method) {
				isHttp = true
				break
			}
		}
	}

	if !isHttp && len(payload) > 4 && bytes.HasPrefix(payload, []byte("HTTP")) {
		isHttp = true
	}

	if isHttp {
		httpStats := a.Stats.ProtocolStats["HTTP"]
		httpStats.PacketCount++
		httpStats.PayloadSize[flowKey] = len(payload)

		lines := strings.Split(string(payload), "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "Host: ") {
				domain := strings.TrimPrefix(line, "Host: ")
				httpStats.Domains[domain]++
				break
			}
		}

		for _, method := range httpMethods {
			if bytes.HasPrefix(payload, method) {
				httpStats.RequestCount++
				break
			}
		}

		if bytes.HasPrefix(payload, []byte("HTTP/1.")) || bytes.HasPrefix(payload, []byte("HTTP/2")) {
			httpStats.ResponseCount++
			statusCode := ""

			if len(lines) > 0 && len(lines[0]) > 9 {
				statusCode = lines[0][9:12]

				if statusCode != "200" && statusCode != "301" && statusCode != "302" && statusCode != "304" {
					txt := fmt.Sprintf("HTTP_unusual_status_%s", statusCode)
					httpStats.Anomalies[txt]++
				}
			}
		}

		if len(payload) > 8192 {
			httpStats.Anomalies["HTTP_large_payload_size"]++
		}

		if bytes.Contains(payload, []byte("../")) || bytes.Contains(payload, []byte("%2e%2e")) {
			httpStats.Anomalies["HTTP_path_traversal_attemp"]++
		}

		if bytes.Contains(payload, []byte("<script>")) || bytes.Contains(payload, []byte("alert(")) {
			httpStats.Anomalies["HTTP_xss_attempt"]++
		}
	}
}

func (a *ApplicationLayerAnalyzer) detectFTPProtocol(tcp *layers.TCP, payload []byte, flowkey string) {
	if tcp.SrcPort == 21 || tcp.DstPort == 21 || bytes.HasPrefix(payload, []byte("USER")) || bytes.HasPrefix(payload, []byte("PASS")) {
		ftpStats := a.Stats.ProtocolStats["FTP"]
		ftpStats.PacketCount++
		ftpStats.PayloadSize[flowkey] = len(payload)

		lines := strings.Split(string(payload), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "USER") || strings.HasPrefix(line, "PASS") {
				ftpStats.RequestCount++
			} else if strings.HasPrefix(line, "230") {
				ftpStats.ResponseCount++
			}

			if len(line) > 100 {
				ftpStats.Anomalies["FTP_long_command"]++
			}

		}

		return
	}
}

func (a *ApplicationLayerAnalyzer) detectSMTPProtocol(tcp *layers.TCP, payload []byte, flowkey string) {
	if tcp.SrcPort == 25 || tcp.DstPort == 25 || bytes.HasPrefix(payload, []byte("HELO")) || bytes.HasPrefix(payload, []byte("MAIL")) {
		smtpStats := a.Stats.ProtocolStats["SMTP"]
		smtpStats.PacketCount++
		smtpStats.PayloadSize[flowkey] = len(payload)

		lines := strings.Split(string(payload), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "HELO") || strings.HasPrefix(line, "MAIL") {
				smtpStats.RequestCount++
			} else if strings.HasPrefix(line, "250") {
				smtpStats.ResponseCount++
			}

			if strings.HasPrefix(line, "HELO") && smtpStats.RequestCount > 1 {
				smtpStats.Anomalies["SMTP_multiple_helo"]++
			}
		}
	}
}

func (a *ApplicationLayerAnalyzer) analyzeUDPApplication(flowKey string, udp *layers.UDP, packet gopacket.Packet) {
	payload := a.Stats.streams[flowKey].Bytes()
	if (udp.SrcPort == 53 || udp.DstPort == 53) || packet.Layer(layers.LayerTypeDNS) != nil {

		dnsStats := a.Stats.ProtocolStats["DNS"]
		dnsStats.PacketCount++
		dnsStats.PayloadSize[flowKey] = len(payload)

		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)

			if dns.QR {
				dnsStats.ResponseCount++
			} else {
				dnsStats.RequestCount++
			}

			for _, question := range dns.Questions {
				dnsStats.Domains[string(question.Name)]++
				if len(question.Name) > 50 {
					dnsStats.Anomalies["DNS_long_domain_name"]++
				}
			}

			// minor anomalies
			if len(payload) > 512 {
				dnsStats.Anomalies["DNS_Tunneling"]++
			}

			if len(dns.Answers) > 10 {
				dnsStats.Anomalies["DNS_high_answer_count"]++
			}
		} else if udp.SrcPort != 53 && udp.DstPort != 53 {
			dnsStats.Anomalies["DNS_non_standard_port"]++
		}

		if len(udp.Payload) > 1024 {
			dnsStats.Anomalies["DNS_large_payload"]++
		}
	}
}

func (a *ApplicationLayerAnalyzer) getFlowKey(packet gopacket.Packet) string {
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return ""
	}

	srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
	dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()
	srcPort := packet.TransportLayer().TransportFlow().Src().String()
	dstPort := packet.TransportLayer().TransportFlow().Dst().String()

	return fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
}

func (a *ApplicationLayerAnalyzer) GetResult() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := map[string]interface{}{
		"ProtocolStats": make(map[string]interface{}),
		"TLSStats":      a.Stats.TLSStats,
	}

	for proto, stats := range a.Stats.ProtocolStats {
		result["ProtocolStats"].(map[string]interface{})[proto] = map[string]interface{}{
			"PacketCount":   stats.PacketCount,
			"RequestCount":  stats.RequestCount,
			"ResponseCount": stats.ResponseCount,
			"Domains":       stats.Domains,
			"PayloadSizes":  stats.PayloadSize,
			"Anomalies":     stats.Anomalies,
		}
	}

	return result
}

func (a *ApplicationLayerAnalyzer) ProcessPackets(packetChan <-chan gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for packet := range packetChan {
		if err := a.Analyze(packet); err != nil {
			fmt.Printf("error while analyzing packet: %v \n", err)
		}
	}
}
