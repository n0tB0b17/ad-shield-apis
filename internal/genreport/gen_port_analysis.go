package genreport

import (
	"bytes"
	"fmt"

	"github.com/bob17/adpis/internal/db"
)

type PortScanReportGenerator struct {
	*BaseReportGenerator
}

func (p *PortScanReportGenerator) Generate() ([]byte, error) {
	p.Pdf.AddPage()
	p.addHeader()
	p.addUserInfo()

	p.Pdf.SetFont("Arial", "B", 14)
	accent := p.Branding.Theme.Accent
	p.Pdf.SetFillColor(int(accent.R), int(accent.G), int(accent.B))
	p.Pdf.SetTextColor(255, 255, 255)
	p.Pdf.CellFormat(190, 10, "Port Scan Results", "", 1, "L", true, 0, "")
	p.Pdf.SetTextColor(int(p.Branding.Theme.Text.R), int(p.Branding.Theme.Text.G), int(p.Branding.Theme.Text.B))
	p.Pdf.Ln(5)

	switch docs := p.Content.(type) {
	case db.PortScanHistory:
		p.addSinglePortScanData(docs)
	case []db.PortScanHistory:
		for i, doc := range docs {
			if i > 0 {
				p.Pdf.AddPage()
				p.addHeader()
			}

			p.addSinglePortScanData(doc)
		}
	default:
		p.Pdf.SetFont("Arial", "", 12)
		p.Pdf.MultiCell(190, 6, "invalid port scan data provided", "", "L", false)
		fmt.Println("default type for pdf generate")
	}

	p.addFooter()

	var buf bytes.Buffer
	if err := p.Pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("error generating output: %v", err)
	}

	return buf.Bytes(), nil
}

func (p *PortScanReportGenerator) SetUser(user interface{}) error {
	// if _, ok := user.()

	return nil
}
func (p *PortScanReportGenerator) SetContent(interface{}) error        { return nil }
func (p *PortScanReportGenerator) SetBranding(interface{}) error       { return nil }
func (p *PortScanReportGenerator) SaveToFile(file_string string) error { return nil }

func (p *PortScanReportGenerator) addSinglePortScanData(scan db.PortScanHistory) {
	pdf := p.Pdf

	// Scan metadata
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "Scan Information", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)

	// Add scan details
	p.addTableRow("Target Address", scan.TargetAddress)
	p.addTableRow("Port Range", scan.RequestedPortRange)
	p.addTableRow("Start Time", scan.ScanStartTime.Format("2006-01-02 15:04:05"))
	p.addTableRow("End Time", scan.ScanEndTime.Format("2006-01-02 15:04:05"))
	p.addTableRow("Duration", scan.ScanDuration.String())
	p.addTableRow("Status", scan.Status)

	pdf.Ln(5)

	// Add scan results
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "Scan Results", "", 1, "L", false, 0, "")

	// Table header for results
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(40, 8, "Address", "1", 0, "C", false, 0, "")
	pdf.CellFormat(25, 8, "Port", "1", 0, "C", false, 0, "")
	pdf.CellFormat(25, 8, "Status", "1", 0, "C", false, 0, "")
	pdf.CellFormat(50, 8, "Service", "1", 0, "C", false, 0, "")
	pdf.CellFormat(50, 8, "Version", "1", 1, "C", false, 0, "")

	// Table content
	pdf.SetFont("Arial", "", 10)

	// Determine if we need to create a new page for results
	resultsPerPage := 25
	// totalResults := len(scan.ScanDetail)

	for i, result := range scan.ScanDetail {
		// Check if we need a new page
		if i > 0 && i%resultsPerPage == 0 {
			pdf.AddPage()
			p.addHeader()

			// Repeat table header
			pdf.SetFont("Arial", "B", 12)
			pdf.CellFormat(190, 8, "Scan Results (Continued)", "", 1, "L", false, 0, "")

			pdf.SetFont("Arial", "B", 10)
			pdf.CellFormat(40, 8, "Address", "1", 0, "C", false, 0, "")
			pdf.CellFormat(25, 8, "Port", "1", 0, "C", false, 0, "")
			pdf.CellFormat(25, 8, "Status", "1", 0, "C", false, 0, "")
			pdf.CellFormat(50, 8, "Service", "1", 0, "C", false, 0, "")
			pdf.CellFormat(50, 8, "Version", "1", 1, "C", false, 0, "")

			pdf.SetFont("Arial", "", 10)
		}

		// Color code based on status
		if result.Status == "open" {
			pdf.SetFillColor(230, 255, 230) // Light green
		} else if result.Status == "closed" {
			pdf.SetFillColor(255, 230, 230) // Light red
		} else {
			pdf.SetFillColor(255, 255, 230) // Light yellow
		}

		pdf.CellFormat(40, 8, result.Addr, "1", 0, "L", true, 0, "")
		pdf.CellFormat(25, 8, fmt.Sprintf("%d", result.Port), "1", 0, "C", true, 0, "")
		pdf.CellFormat(25, 8, result.Status, "1", 0, "C", true, 0, "")
		pdf.CellFormat(50, 8, result.Service, "1", 0, "L", true, 0, "")
		pdf.CellFormat(50, 8, result.Version, "1", 1, "L", true, 0, "")
	}

	// Reset fill color
	pdf.SetFillColor(255, 255, 255)

	// Add summary
	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 8, "Summary", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	p.addTableRow("Total Ports Scanned", fmt.Sprintf("%d", len(scan.ScanDetail)))

	// Count open/closed ports
	openPorts := 0
	for _, result := range scan.ScanDetail {
		if result.Status == "open" {
			openPorts++
		}
	}

	p.addTableRow("Open Ports", fmt.Sprintf("%d", openPorts))
	p.addTableRow("Closed/Filtered Ports", fmt.Sprintf("%d", len(scan.ScanDetail)-openPorts))
}
