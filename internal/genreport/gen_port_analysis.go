package genreport

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/searchsploit"
	"github.com/bob17/adpis/internal/vulners"
)

type PortScanReportGenerator struct {
	*BaseReportGenerator
	VulnersResp []*vulners.Resp
	ExploitResp *searchsploit.Resp
}

func (p *PortScanReportGenerator) Generate() ([]byte, error) {
	p.Pdf.AddPage()
	p.Pdf.Ln(5)
	p.addUserInfo()

	p.Pdf.SetFont("Arial", "B", 14)
	accent := p.Branding.Theme.Accent
	p.Pdf.SetFillColor(int(accent.R), int(accent.G), int(accent.B))
	p.Pdf.SetTextColor(255, 255, 255)
	p.Pdf.CellFormat(190, 10, "Port Scan Results", "", 1, "L", true, 0, "")
	p.Pdf.SetTextColor(int(p.Branding.Theme.Text.R), int(p.Branding.Theme.Text.G), int(p.Branding.Theme.Text.B))
	p.Pdf.Ln(5)

	switch docs := p.Content.(type) {
	case *db.PortScanHistory:
		p.addSinglePortScanData(*docs)
	case []*db.PortScanHistory:
		for i, doc := range docs {
			if i > 0 {
				p.Pdf.AddPage()
				p.addHeader()
			}

			p.addSinglePortScanData(*doc)
		}
	default:
		p.Pdf.SetFont("Arial", "", 12)
		p.Pdf.MultiCell(190, 6, "invalid port scan data provided", "", "L", false)
	}

	p.addVulnersScanResults()

	var buf bytes.Buffer
	if err := p.Pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("error generating output: %v", err)
	}

	return buf.Bytes(), nil
}

func (p *PortScanReportGenerator) SetUser(user interface{}) error {
	if _, ok := user.(*db.Users); !ok {
		return fmt.Errorf("error while parsing user struct")
	}

	p.User = user
	return nil
}

func (p *PortScanReportGenerator) SetContent(content interface{}) error {
	p.Content = content
	return nil
}

func (p *PortScanReportGenerator) SetAnalysis(content map[string]interface{}) error {
	vulnersStats := content["vulnersAnalysis"]

	p.setVulner(vulnersStats)
	p.setExploitdb(nil)
	return nil
}

func (p *PortScanReportGenerator) setVulner(content interface{}) {
	if vulner, ok := content.([]*vulners.Resp); ok {
		p.VulnersResp = vulner
	}
}

func (p *PortScanReportGenerator) setExploitdb(content interface{}) {
	if explotdb, ok := content.(searchsploit.Resp); ok {
		p.ExploitResp = &explotdb
	}

	p.ExploitResp = nil
}

func (p *PortScanReportGenerator) SetBranding(branding interface{}) error {
	if p.Branding.Theme == nil {
		p.Branding.Theme = &DefaultTheme
	}

	p.Branding = branding.(BrandingInfo)
	return nil
}

func (p *PortScanReportGenerator) SaveToFile(file_string string) error {
	pdf, err := p.Generate()
	if err != nil {
		return err
	}

	return os.WriteFile(file_string, pdf, 0644)
}

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

	openPorts := 0
	for _, result := range scan.ScanDetail {
		if result.Status == "open" {
			openPorts++
		}
	}

	p.addTableRow("Open Ports", fmt.Sprintf("%d", openPorts))
	p.addTableRow("Closed/Filtered Ports", fmt.Sprintf("%d", len(scan.ScanDetail)-openPorts))
}
func (p *PortScanReportGenerator) addVulnersScanResults() {
	pdf := p.Pdf
	pdf.Ln(5)

	p.addTitle("Vulnerability Scan Results (Vulners.com)")

	if len(p.VulnersResp) == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No vulnerability scan data provided for any service/version.", "", "L", false)
		pdf.Ln(10)
		return
	}

	// Calculate total vulnerabilities across all responses for summary
	totalVulnerabilitiesAcrossAllResponses := 0
	for _, r := range p.VulnersResp {
		if r != nil && r.Data.Total > 0 {
			totalVulnerabilitiesAcrossAllResponses += r.Data.Total
		}
	}

	if totalVulnerabilitiesAcrossAllResponses == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(190, 6, "No vulnerabilities found across all scanned services/versions.", "", "L", false)
		pdf.Ln(10)
		return
	}

	pdf.SetFont("Arial", "", 10)
	p.addTableRow("Total Vulnerabilities Found (Across All Scans)", strconv.Itoa(totalVulnerabilitiesAcrossAllResponses))
	pdf.Ln(5)

	// Iterate through each individual *vulners.Resp object (each potentially representing a scan for a different service/version)
	for scanIdx, vulnersResp := range p.VulnersResp {
		if vulnersResp == nil || vulnersResp.Data.Total == 0 {
			continue // Skip if this particular response is empty or has no vulnerabilities
		}

		// Add a sub-heading for each specific scan result's vulnerabilities
		if scanIdx > 0 {
			pdf.Ln(10)            // Space between different service's vulnerability lists
			if pdf.GetY() > 250 { // Check if near bottom of A4 for a new page
				pdf.AddPage()
			}
		}
		pdf.SetFont("Arial", "B", 13) // Slightly larger font for service/version sub-title
		// You might want to pass the actual service/version name here if you stored it alongside vulners.Resp
		pdf.CellFormat(190, 10, fmt.Sprintf("Vulnerabilities for Scan Result Group %d (Total: %d)", scanIdx+1, vulnersResp.Data.Total), "B", 1, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		pdf.Ln(5)

		// Now iterate through the individual Search results within THIS vulnersResp
		for vulnIdx, searchResult := range vulnersResp.Data.Search {
			// Check if we need to add a new page *within* this single vulnersResp's search results
			if vulnIdx > 0 && pdf.GetY() > 250 {
				pdf.AddPage()
				// Re-add the service/version header for continuity
				pdf.SetFont("Arial", "B", 13)
				pdf.CellFormat(190, 10, fmt.Sprintf("Vulnerabilities for Scan Result Group %d (Continued)", scanIdx+1), "B", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "B", 12)
				pdf.CellFormat(190, 8, fmt.Sprintf("Vulnerability: %s (ID: %s) (Continued)", searchResult.Source.Title, searchResult.Source.ID), "B", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "", 10)
				pdf.Ln(2)
			} else if vulnIdx > 0 {
				pdf.Ln(5) // Space between vulnerabilities on the same page
			}

			pdf.SetFont("Arial", "B", 12)
			pdf.CellFormat(190, 8, fmt.Sprintf("Vulnerability: %s (ID: %s)", searchResult.Source.Title, searchResult.Source.ID), "B", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 10)
			pdf.Ln(2)

			p.addTableRow("Bulletin Family", searchResult.Source.BulletinFamily)
			p.addTableRow("Type", searchResult.Source.Type)
			p.addTableRow("Score", fmt.Sprintf("%.2f", searchResult.Score))
			p.addTableRow("Published", formatInterfaceTime(searchResult.Source.Published))
			p.addTableRow("Last Seen", formatInterfaceTime(searchResult.Source.Lastseen))

			pdf.SetFont("Arial", "B", 10)
			pdf.CellFormat(190, 7, "Description:", "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 9)
			// Ensure MultiCell wraps correctly; adjusted height to 5, border "1" for clarity
			pdf.MultiCell(190, 5, searchResult.FlatDescription, "1", "L", false)
			pdf.Ln(2)

			if len(searchResult.Source.CveList) > 0 {
				pdf.SetFont("Arial", "B", 10)
				pdf.CellFormat(190, 7, "CVEs:", "", 1, "L", false, 0, "")
				pdf.SetFont("Arial", "", 9)
				cves := ""
				for j, cve := range searchResult.Source.CveList {
					cves += cve
					if j < len(searchResult.Source.CveList)-1 {
						cves += ", "
					}
				}
				pdf.MultiCell(190, 5, cves, "1", "L", false)
				pdf.Ln(2)
			}

			p.renderCVSSDetails(&searchResult.Source.CVSS3, &searchResult.Source.CVSS2, &searchResult.Source.CVSS)
		}
	}
	pdf.Ln(10)
}

func (p *PortScanReportGenerator) renderCVSSDetails(cvss3 *vulners.CVSS3, cvss2 *vulners.CVSS2, cvssSummary *vulners.CVSSSummary) {
	pdf := p.Pdf
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(190, 7, "CVSS Scores:", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 9)

	if cvss3 != nil && cvss3.CVSSv3.Version != "" {
		p.addTableRow("  CVSSv3 Base Score", fmt.Sprintf("%.1f (%s)", cvss3.CVSSv3.BaseScore, cvss3.CVSSv3.BaseSeverity))
		pdf.CellFormat(40, 6, "  Vector String (v3)", "1", 0, "L", false, 0, "")
		pdf.MultiCell(150, 6, cvss3.CVSSv3.VectorString, "1", "L", false)
	}

	if cvss2 != nil && cvss2.CVSSv2.Version != "" {
		p.addTableRow("  CVSSv2 Base Score", fmt.Sprintf("%.1f (%s)", cvss2.CVSSv2.BaseScore, cvss2.CVSSv2.BaseSeverity))
		pdf.CellFormat(40, 6, "  Vector String (v2)", "1", 0, "L", false, 0, "")
		pdf.MultiCell(150, 6, cvss2.CVSSv2.VectorString, "1", "L", false)
	}

	if cvssSummary != nil && cvssSummary.Version != "" {
		p.addTableRow("  CVSS Summary Score", fmt.Sprintf("%.1f (%s) - %s", cvssSummary.Score, cvssSummary.Severity, cvssSummary.Version))
		pdf.CellFormat(40, 6, "  Vector String (Summary)", "1", 0, "L", false, 0, "")
		pdf.MultiCell(150, 6, cvssSummary.Vector, "1", "L", false)
	}

	if cvss3 == nil && cvss2 == nil && cvssSummary == nil {
		p.addTableRow("  CVSS Scores", "No CVSS data available.")
	}
	pdf.Ln(2)
}

func formatInterfaceTime(t interface{}) string {
	if t == nil {
		return "N/A"
	}
	switch v := t.(type) {
	case string:
		// Try parsing common date formats from Vulners.com (e.g., ISO 8601)
		parsedTime, err := time.Parse(time.RFC3339Nano, v)
		if err == nil {
			return parsedTime.Format("2006-01-02 15:04:05")
		}
		return v // Return as is if it's a string but cannot be parsed
	case float64:
		// Assume Unix timestamp (seconds)
		return time.Unix(int64(v), 0).Format("2006-01-02 15:04:05")
	case int64:
		// Assume Unix timestamp (seconds)
		return time.Unix(v, 0).Format("2006-01-02 15:04:05")
	default:
		return fmt.Sprintf("%v", t) // Fallback for any other type
	}
}
