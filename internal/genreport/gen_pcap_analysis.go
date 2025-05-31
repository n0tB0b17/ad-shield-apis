package genreport

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"github.com/bob17/adpis/internal/analysis/application"
	"github.com/bob17/adpis/internal/analysis/network"
	"github.com/bob17/adpis/internal/analysis/transport"
	"github.com/bob17/adpis/internal/db"
)

type PCAPScanReportGenerator struct {
	*BaseReportGenerator
	NetworkAnalysisContent     *network.NetworkStats
	TransportAnalysisContent   *transport.TransportStats
	ApplicationAnalysisContent *application.ApplicationStats
}

func (p *PCAPScanReportGenerator) Generate() ([]byte, error) {
	p.Pdf.AddPage()
	p.addHeader()
	p.addUserInfo()

	switch docs := p.Content.(type) {
	case *db.PCAPMetaData:
		p.addSinglePCAPData(*docs)
	case []*db.PCAPMetaData:
		for i, doc := range docs {
			if i > 0 {
				p.Pdf.AddPage()
				p.addHeader()
			}

			p.addSinglePCAPData(*doc)
		}

	default:
		p.Pdf.SetFont("Arial", "", 12)
		p.Pdf.MultiCell(190, 6, "Invalid pcap anylsis type", "", "L", false)
	}

	p.addPCAPAnalysisData()
	p.addFooter()

	var buf bytes.Buffer
	if err := p.Pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("unable to output data into pdf: %v", err)
	}

	return buf.Bytes(), nil
}

func (p *PCAPScanReportGenerator) SetUser(user interface{}) error {
	if _, ok := user.(*db.Users); !ok {
		return fmt.Errorf("error while parsing user struct")
	}

	p.User = user
	return nil
}

func (p *PCAPScanReportGenerator) SetContent(content interface{}) error {
	p.Content = content
	return nil
}

func (p *PCAPScanReportGenerator) SetAnalysis(content map[string]interface{}) error {
	networkAnalysis := content["networkAnalysis"]
	transportAnalysis := content["transportAnalysis"]
	applicationAnalysis := content["applicationAnalysis"]

	p.setNetworkLayerContent(networkAnalysis)
	p.setTransportLayerContent(transportAnalysis)
	p.setApplicationLayerContent(applicationAnalysis)

	return nil
}

func (p *PCAPScanReportGenerator) setNetworkLayerContent(content interface{}) error {
	if stats, ok := content.(network.NetworkStats); ok {
		p.NetworkAnalysisContent = &stats
	}

	return fmt.Errorf("expected NetworkStats, got %T", content)
}

func (p *PCAPScanReportGenerator) setTransportLayerContent(content interface{}) error {
	stats, _ := content.(transport.TransportStats)
	p.TransportAnalysisContent = &stats
	return nil
}

func (p *PCAPScanReportGenerator) setApplicationLayerContent(content interface{}) error {
	stats, _ := content.(application.ApplicationStats)
	p.ApplicationAnalysisContent = &stats
	return nil
}

func (p *PCAPScanReportGenerator) SetBranding(branding interface{}) error {
	if p.Branding.Theme == nil {
		p.Branding.Theme = &DefaultTheme
	}

	p.Branding = branding.(BrandingInfo)
	return nil
}

func (p *PCAPScanReportGenerator) SaveToFile(file_string string) error {
	pdf, err := p.Generate()
	if err != nil {
		return err
	}

	return os.WriteFile(file_string, pdf, 0644)
}

func (p *PCAPScanReportGenerator) addSinglePCAPData(pcap db.PCAPMetaData) {
	pdf := p.Pdf

	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "File Information", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	p.addTableRow("Original Filename", pcap.OriginalFileName)
	p.addTableRow("Stored Filename", pcap.StoredFileName)
	p.addTableRow("Storage Path", pcap.StoragePath)
	p.addTableRow("File Size", formatFileSize(pcap.FileSizeBytes))
	p.addTableRow("File Hash", pcap.FileHash)
	p.addTableRow("Content Type", pcap.ContentType)
	p.addTableRow("Uploaded At", pcap.UploadedAt.Format("2006-01-02 15:04:05"))

	if pcap.LastAnalyzedTime != nil {
		p.addTableRow("Last Analyzed", pcap.LastAnalyzedTime.Format("2006-01-02 15:04:05"))
	} else {
		p.addTableRow("Last Analyzed", "Never")
	}

	pdf.Ln(10)

	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "Analysis Details", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(190, 6, "Detailed packet analysis would be shown here. This can include traffic patterns, protocol distributions, detected anomalies, etc.", "", "L", false)
}

func (p *PCAPScanReportGenerator) addPCAPAnalysisData() {
	pdf := p.Pdf
	pdf.Ln(5)

	if p.NetworkAnalysisContent == nil && p.TransportAnalysisContent == nil && p.ApplicationAnalysisContent == nil {
		p.addTitle("Detailed Analysis Results")
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No detailed analysis results were provided for this PCAP.", "", "L", false)
		pdf.Ln(10)
		return
	}

	// Add Network Layer Metrics
	if p.NetworkAnalysisContent != nil {
		p.addTitle("Network Layer Metrics")
		p.addNetworkStats(p.NetworkAnalysisContent)
		pdf.Ln(10)
	} else {
		p.addTitle("Network Layer Metrics") // Still add title to indicate section, but with no data message
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No network layer analysis results available.", "", "L", false)
		pdf.Ln(10)
	}

	// Add Transport Layer Metrics
	if p.TransportAnalysisContent != nil {
		p.addTitle("Transport Layer Metrics")
		p.addTransportStats(p.TransportAnalysisContent)
		pdf.Ln(10)
	} else {
		p.addTitle("Transport Layer Metrics")
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No transport layer analysis results available.", "", "L", false)
		pdf.Ln(10)
	}

	// Add Application Layer Metrics
	if p.ApplicationAnalysisContent != nil {
		p.addTitle("Application Layer Metrics")
		p.addApplicationStats(p.ApplicationAnalysisContent)
		pdf.Ln(10)
	} else {
		p.addTitle("Application Layer Metrics")
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No application layer analysis results available.", "", "L", false)
		pdf.Ln(10)
	}
}

func (p *PCAPScanReportGenerator) addNetworkStats(stats *network.NetworkStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	p.addTableRow("Total Packet Count", strconv.Itoa(stats.PacketCount))
	p.addTableRow("Fragmented Packets", strconv.Itoa(stats.FragmentedPackets))
	p.addTableRow("Reassembled Flows", strconv.Itoa(stats.ReassembledFlows))

	if len(stats.IpStats) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "IP Statistics (IP -> Packets)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for ip, count := range stats.IpStats {
			p.addTableRow(ip, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("IP Statistics", "No data")
	}

	if len(stats.TTLStats) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "TTL Statistics (TTL -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for ttl, count := range stats.TTLStats {
			p.addTableRow(strconv.Itoa(int(ttl)), strconv.Itoa(count))
		}
	} else {
		p.addTableRow("TTL Statistics", "No data")
	}

	if len(stats.ProtocolDist) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Protocol Distribution (Protocol -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for proto, count := range stats.ProtocolDist {
			p.addTableRow(proto, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("Protocol Distribution", "No data")
	}
}

// addTransportStats renders the details for TransportStats.
func (p *PCAPScanReportGenerator) addTransportStats(stats *transport.TransportStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	p.addTableRow("TCP Packet Count", strconv.Itoa(stats.TCPPacketCount))
	p.addTableRow("UDP Packet Count", strconv.Itoa(stats.UDPPacketCount))
	p.addTableRow("TCP Connections", strconv.Itoa(stats.TCPConnection))
	p.addTableRow("Retransmissions", strconv.Itoa(stats.Retransmission))
	p.addTableRow("Invalid TCP Flags", strconv.Itoa(stats.InvalidTCPFlags))

	if len(stats.PortStats) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Port Statistics (Port -> Packets)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for port, count := range stats.PortStats {
			p.addTableRow(strconv.Itoa(port), strconv.Itoa(count))
		}
	} else {
		p.addTableRow("Port Statistics", "No data")
	}

	if len(stats.UDPFloodPorts) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "UDP Flood Ports (Port -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for port, count := range stats.UDPFloodPorts {
			p.addTableRow(strconv.Itoa(port), strconv.Itoa(count))
		}
	} else {
		p.addTableRow("UDP Flood Ports", "No data")
	}

	if len(stats.StreamData) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Stream Data (Flow Key -> Packet Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for flowKey, count := range stats.StreamData {
			p.addTableRow(flowKey, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("Stream Data", "No data")
	}

	if len(stats.NewStreamData) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Reassembled TCP Streams (Flow Key -> Status)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for flowKey, stream := range stats.NewStreamData {
			status := "Incomplete"
			if stream.Complete {
				status = "Complete"
			}
			p.addTableRow(flowKey, fmt.Sprintf("%s (%d segments, %d bytes)", status, len(stream.Segments), stream.Reassembled.Len()))
		}
	} else {
		p.addTableRow("Reassembled TCP Streams", "No data")
	}
}

// addApplicationStats renders the details for ApplicationStats.
func (p *PCAPScanReportGenerator) addApplicationStats(stats *application.ApplicationStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	if len(stats.ProtocolStats) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Application Protocol Statistics", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for proto, protoStats := range stats.ProtocolStats {
			pdf.Ln(2)
			pdf.SetFont("Arial", "BU", 10) // Underline for sub-protocol
			pdf.CellFormat(190, 7, fmt.Sprintf("Protocol: %s", proto), "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 10)
			p.addTableRow("  Packet Count", strconv.Itoa(protoStats.PacketCount))
			p.addTableRow("  Request Count", strconv.Itoa(protoStats.RequestCount))
			p.addTableRow("  Response Count", strconv.Itoa(protoStats.ResponseCount))

			if len(protoStats.Domains) > 0 {
				pdf.Ln(1)
				pdf.SetFont("Arial", "B", 10)
				pdf.CellFormat(190, 7, "  Domains (Domain -> Count)", "B", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "", 10)
				for domain, count := range protoStats.Domains {
					p.addTableRow("    "+domain, strconv.Itoa(count))
				}
			}

			if len(protoStats.PayloadSize) > 0 {
				pdf.Ln(1)
				pdf.SetFont("Arial", "B", 10)
				pdf.CellFormat(190, 7, "  Payload Sizes (Type -> Bytes)", "B", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "", 10)
				for pType, size := range protoStats.PayloadSize {
					p.addTableRow("    "+pType, formatFileSize(int64(size)))
				}
			}

			if len(protoStats.Anomalies) > 0 {
				pdf.Ln(1)
				pdf.SetFont("Arial", "B", 10)
				pdf.CellFormat(190, 7, "  Anomalies (Anomaly -> Count)", "B", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "", 10)
				for anomaly, count := range protoStats.Anomalies {
					p.addTableRow("    "+anomaly, strconv.Itoa(count))
				}
			}
		}
	} else {
		p.addTableRow("Application Protocol Statistics", "No data")
	}

	pdf.Ln(5) // Space before TLS stats

	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "TLS Statistics", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	p.addTableRow("Certificates Detected", strconv.Itoa(stats.TLSStats.Certificates))

	if len(stats.TLSStats.CipherSuites) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Cipher Suites (Suite -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for suite, count := range stats.TLSStats.CipherSuites {
			p.addTableRow(suite, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("Cipher Suites", "No data")
	}

	if len(stats.TLSStats.Versions) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "TLS Versions (Version -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for version, count := range stats.TLSStats.Versions {
			p.addTableRow(version, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("TLS Versions", "No data")
	}

	if len(stats.TLSStats.SNI) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Server Name Indication (SNI -> Count)", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		for sni, count := range stats.TLSStats.SNI {
			p.addTableRow(sni, strconv.Itoa(count))
		}
	} else {
		p.addTableRow("Server Name Indication", "No data")
	}
}

func formatFileSize(sizeInBytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case sizeInBytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(sizeInBytes)/float64(GB))
	case sizeInBytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(sizeInBytes)/float64(MB))
	case sizeInBytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(sizeInBytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", sizeInBytes)
	}
}
