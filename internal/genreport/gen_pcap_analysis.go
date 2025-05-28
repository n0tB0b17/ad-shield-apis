package genreport

import (
	"bytes"
	"fmt"
	"os"

	"github.com/bob17/adpis/internal/db"
)

type PCAPScanReportGenerator struct {
	*BaseReportGenerator
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

	// PCAP metadata
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "File Information", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	// Add PCAP details
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

// formatFileSize formats file size in bytes to a human-readable string
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
