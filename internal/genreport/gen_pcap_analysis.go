package genreport

import (
	"bytes"
	"fmt"
	"os"
	"sort"
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
	p.Pdf.Ln(5)
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
	pdf.MultiCell(190, 6, "Detailed packet analysis would be shown here. This can include traffic patterns, protocol distributions", "", "L", false)
}

// addPCAPAnalysisData orchestrates the rendering of network, transport, and application stats.
func (p *PCAPScanReportGenerator) addPCAPAnalysisData() {
	pdf := p.Pdf
	pdf.Ln(5) // Add some space before the analysis section starts

	// Check if any analysis data is available
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

// addNetworkStats renders the details for NetworkStats using the new compact block helper.
func (p *PCAPScanReportGenerator) addNetworkStats(stats *network.NetworkStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	p.addTableRow("Total Packet Count", strconv.Itoa(stats.PacketCount))
	p.addTableRow("Fragmented Packets", strconv.Itoa(stats.FragmentedPackets))
	p.addTableRow("Reassembled Flows", strconv.Itoa(stats.ReassembledFlows))

	// IP Statistics
	ipStatsItems := make([]string, 0, len(stats.IpStats))
	keys := make([]string, 0, len(stats.IpStats))
	for k := range stats.IpStats {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort IP addresses for consistent output
	for _, k := range keys {
		ipStatsItems = append(ipStatsItems, fmt.Sprintf("%s: %d", k, stats.IpStats[k]))
	}
	p.addCompactInfoBlock("IP Statistics (IP: Packets)", ipStatsItems)

	// TTL Statistics
	ttlStatsItems := make([]string, 0, len(stats.TTLStats))
	ttlKeys := make([]int, 0, len(stats.TTLStats))
	for k := range stats.TTLStats {
		ttlKeys = append(ttlKeys, int(k)) // Convert uint8 to int for sorting
	}
	sort.Ints(ttlKeys) // Sort TTL values
	for _, k := range ttlKeys {
		ttlStatsItems = append(ttlStatsItems, fmt.Sprintf("%d: %d", k, stats.TTLStats[uint8(k)]))
	}
	p.addCompactInfoBlock("TTL Statistics (TTL: Count)", ttlStatsItems)

	// Protocol Distribution
	protoDistItems := make([]string, 0, len(stats.ProtocolDist))
	protoKeys := make([]string, 0, len(stats.ProtocolDist))
	for k := range stats.ProtocolDist {
		protoKeys = append(protoKeys, k)
	}
	sort.Strings(protoKeys) // Sort protocol names
	for _, k := range protoKeys {
		protoDistItems = append(protoDistItems, fmt.Sprintf("%s: %d", k, stats.ProtocolDist[k]))
	}
	p.addCompactInfoBlock("Protocol Distribution (Protocol: Count)", protoDistItems)
}

// addTransportStats renders the details for TransportStats using the new compact block helper.
func (p *PCAPScanReportGenerator) addTransportStats(stats *transport.TransportStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	p.addTableRow("TCP Packet Count", strconv.Itoa(stats.TCPPacketCount))
	p.addTableRow("UDP Packet Count", strconv.Itoa(stats.UDPPacketCount))
	p.addTableRow("TCP Connections", strconv.Itoa(stats.TCPConnection))
	p.addTableRow("Retransmissions", strconv.Itoa(stats.Retransmission))
	p.addTableRow("Invalid TCP Flags", strconv.Itoa(stats.InvalidTCPFlags))

	// Port Statistics
	portStatsItems := make([]string, 0, len(stats.PortStats))
	portKeys := make([]int, 0, len(stats.PortStats))
	for k := range stats.PortStats {
		portKeys = append(portKeys, k)
	}
	sort.Ints(portKeys) // Sort port numbers
	for _, k := range portKeys {
		portStatsItems = append(portStatsItems, fmt.Sprintf("%d: %d", k, stats.PortStats[k]))
	}
	p.addCompactInfoBlock("Port Statistics (Port: Packets)", portStatsItems)

	// UDP Flood Ports
	udpFloodPortsItems := make([]string, 0, len(stats.UDPFloodPorts))
	udpFloodKeys := make([]int, 0, len(stats.UDPFloodPorts))
	for k := range stats.UDPFloodPorts {
		udpFloodKeys = append(udpFloodKeys, k)
	}
	sort.Ints(udpFloodKeys) // Sort UDP flood port numbers
	for _, k := range udpFloodKeys {
		udpFloodPortsItems = append(udpFloodPortsItems, fmt.Sprintf("%d: %d", k, stats.UDPFloodPorts[k]))
	}
	p.addCompactInfoBlock("UDP Flood Ports (Port: Count)", udpFloodPortsItems)

	// Stream Data (Flow Key -> Count)
	streamDataItems := make([]string, 0, len(stats.StreamData))
	streamKeys := make([]string, 0, len(stats.StreamData))
	for k := range stats.StreamData {
		streamKeys = append(streamKeys, k)
	}
	sort.Strings(streamKeys) // Sort flow keys
	for _, k := range streamKeys {
		streamDataItems = append(streamDataItems, fmt.Sprintf("%s: %d", k, stats.StreamData[k]))
	}
	p.addCompactInfoBlock("Stream Data (Flow Key: Packet Count)", streamDataItems)

	// Reassembled TCP Streams (Flow Key -> Status) - This one is better as a small table due to structured data
	if len(stats.NewStreamData) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Reassembled TCP Streams", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)

		// Sort NewStreamData keys for consistent output
		streamKeys := make([]string, 0, len(stats.NewStreamData))
		for k := range stats.NewStreamData {
			streamKeys = append(streamKeys, k)
		}
		sort.Strings(streamKeys)

		// Create a temporary table for reassembled streams
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(60, 8, "Flow Key", "1", 0, "L", false, 0, "")
		pdf.CellFormat(130, 8, "Status (Segments, Bytes)", "1", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)

		for _, flowKey := range streamKeys {
			stream := stats.NewStreamData[flowKey]
			status := "Incomplete"
			if stream.Complete {
				status = "Complete"
			}
			p.Pdf.CellFormat(60, 8, flowKey, "1", 0, "L", false, 0, "")
			p.Pdf.CellFormat(130, 8, fmt.Sprintf("%s (%d segments, %s)", status, len(stream.Segments), formatFileSize(int64(stream.Reassembled.Len()))), "1", 1, "L", false, 0, "")
		}
	}
}

// addApplicationStats renders the details for ApplicationStats using the new compact block helper.
func (p *PCAPScanReportGenerator) addApplicationStats(stats *application.ApplicationStats) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "", 10)

	if len(stats.ProtocolStats) > 0 {
		p.addCompactInfoBlock("Application Protocol Statistics Overview", []string{"See detailed breakdown below."}) // Just a lead-in
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(190, 7, "Detailed Application Protocol Breakdown", "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)

		// Sort protocol names for consistent output
		protoNames := make([]string, 0, len(stats.ProtocolStats))
		for name := range stats.ProtocolStats {
			protoNames = append(protoNames, name)
		}
		sort.Strings(protoNames)

		for _, proto := range protoNames {
			protoStats := stats.ProtocolStats[proto]
			pdf.Ln(2)
			pdf.SetFont("Arial", "BU", 10) // Underline for sub-protocol
			pdf.CellFormat(190, 7, fmt.Sprintf("Protocol: %s", proto), "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 10)

			// Simple table for counts
			p.addTableRow("  Packet Count", strconv.Itoa(protoStats.PacketCount))
			p.addTableRow("  Request Count", strconv.Itoa(protoStats.RequestCount))
			p.addTableRow("  Response Count", strconv.Itoa(protoStats.ResponseCount))

			// Domains
			domainItems := make([]string, 0, len(protoStats.Domains))
			domainKeys := make([]string, 0, len(protoStats.Domains))
			for k := range protoStats.Domains {
				domainKeys = append(domainKeys, k)
			}
			sort.Strings(domainKeys)
			for _, k := range domainKeys {
				domainItems = append(domainItems, fmt.Sprintf("%s: %d", k, protoStats.Domains[k]))
			}
			p.addCompactInfoBlock("  Domains (Domain: Count)", domainItems)

			// Payload Sizes
			payloadItems := make([]string, 0, len(protoStats.PayloadSize))
			payloadKeys := make([]string, 0, len(protoStats.PayloadSize))
			for k := range protoStats.PayloadSize {
				payloadKeys = append(payloadKeys, k)
			}
			sort.Strings(payloadKeys)
			for _, k := range payloadKeys {
				payloadItems = append(payloadItems, fmt.Sprintf("%s: %s", k, formatFileSize(int64(protoStats.PayloadSize[k]))))
			}
			p.addCompactInfoBlock("  Payload Sizes (Type: Bytes)", payloadItems)

			// Anomalies
			anomalyItems := make([]string, 0, len(protoStats.Anomalies))
			anomalyKeys := make([]string, 0, len(protoStats.Anomalies))
			for k := range protoStats.Anomalies {
				anomalyKeys = append(anomalyKeys, k)
			}
			sort.Strings(anomalyKeys)
			for _, k := range anomalyKeys {
				anomalyItems = append(anomalyItems, fmt.Sprintf("%s: %d", k, protoStats.Anomalies[k]))
			}
			p.addCompactInfoBlock("  Anomalies (Anomaly: Count)", anomalyItems)
		}
	} else {
		p.addTableRow("Application Protocol Statistics", "No data")
	}

	pdf.Ln(5) // Space before TLS stats

	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "TLS Statistics", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	p.addTableRow("Certificates Detected", strconv.Itoa(stats.TLSStats.Certificates))

	// Cipher Suites
	cipherSuiteItems := make([]string, 0, len(stats.TLSStats.CipherSuites))
	cipherSuiteKeys := make([]string, 0, len(stats.TLSStats.CipherSuites))
	for k := range stats.TLSStats.CipherSuites {
		cipherSuiteKeys = append(cipherSuiteKeys, k)
	}
	sort.Strings(cipherSuiteKeys) // Sort cipher suite names
	for _, k := range cipherSuiteKeys {
		cipherSuiteItems = append(cipherSuiteItems, fmt.Sprintf("%s: %d", k, stats.TLSStats.CipherSuites[k]))
	}
	p.addCompactInfoBlock("Cipher Suites (Suite: Count)", cipherSuiteItems)

	// TLS Versions
	versionItems := make([]string, 0, len(stats.TLSStats.Versions))
	versionKeys := make([]string, 0, len(stats.TLSStats.Versions))
	for k := range stats.TLSStats.Versions {
		versionKeys = append(versionKeys, k)
	}
	sort.Strings(versionKeys) // Sort TLS versions
	for _, k := range versionKeys {
		versionItems = append(versionItems, fmt.Sprintf("%s: %d", k, stats.TLSStats.Versions[k]))
	}
	p.addCompactInfoBlock("TLS Versions (Version: Count)", versionItems)

	// SNI
	sniItems := make([]string, 0, len(stats.TLSStats.SNI))
	sniKeys := make([]string, 0, len(stats.TLSStats.SNI))
	for k := range stats.TLSStats.SNI {
		sniKeys = append(sniKeys, k)
	}
	sort.Strings(sniKeys) // Sort SNI entries
	for _, k := range sniKeys {
		sniItems = append(sniItems, fmt.Sprintf("%s: %d", k, stats.TLSStats.SNI[k]))
	}
	p.addCompactInfoBlock("Server Name Indication (SNI: Count)", sniItems)
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
