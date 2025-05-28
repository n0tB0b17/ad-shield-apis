package genreport

import (
	"bytes"
	"fmt"
	"image/color"
	"os"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/go-pdf/fpdf"
)

type ColorTheme struct {
	Primary   color.RGBA
	Secondary color.RGBA
	Accent    color.RGBA
	Text      color.RGBA
}

var DefaultTheme = ColorTheme{
	Primary:   color.RGBA{R: 0, G: 123, B: 255, A: 255},
	Secondary: color.RGBA{R: 108, G: 117, B: 125, A: 255},
	Text:      color.RGBA{R: 33, G: 37, B: 41, A: 255},
	Accent:    color.RGBA{R: 40, G: 167, B: 69, A: 255},
}

type BrandingInfo struct {
	CompanyName        string
	LogoURL            string
	Addr               string
	AdminEmailAddress  string
	AdminContactNumber string
	Theme              *ColorTheme
}

type BaseReportGenerator struct {
	User        interface{}
	Content     interface{}
	Branding    BrandingInfo
	ContentType string
	Pdf         *fpdf.Fpdf
}

func NewReportGenerator(contentType string) ReportGenerator {
	base := &BaseReportGenerator{
		Pdf:         fpdf.New("P", "mm", "A4", ""),
		ContentType: contentType,
		Branding: BrandingInfo{
			CompanyName:        "companyName",
			LogoURL:            "./assets/logos/logo-2.png",
			Addr:               "companyAddr",
			AdminEmailAddress:  "company@gmail.com",
			AdminContactNumber: "777777777",
			Theme:              &DefaultTheme,
		},
	}

	switch contentType {
	case "PCAP_REPORT":
		return &PCAPScanReportGenerator{BaseReportGenerator: base}
	case "PORT_REPORT":
		return &PortScanReportGenerator{BaseReportGenerator: base}
	default:
		fmt.Println("invalid content_type")
	}

	return nil
}

func (b *BaseReportGenerator) Generate() ([]byte, error) {
	b.Pdf.AddPage()
	b.addHeader()
	b.addUserInfo()

	// Add generic content
	b.Pdf.SetFont("Arial", "B", 14)
	accent := b.Branding.Theme.Accent
	b.Pdf.SetFillColor(int(accent.R), int(accent.G), int(accent.B))
	b.Pdf.SetTextColor(255, 255, 255)
	b.Pdf.CellFormat(190, 10, "Report Content", "", 1, "L", true, 0, "")
	b.Pdf.SetTextColor(int(b.Branding.Theme.Text.R), int(b.Branding.Theme.Text.G), int(b.Branding.Theme.Text.B))
	b.Pdf.Ln(5)

	b.Pdf.SetFont("Arial", "", 12)
	b.Pdf.MultiCell(190, 6, "This report contains generic content. The specific report generator for this content type is not implemented.", "", "L", false)

	b.addFooter()

	// Return PDF as bytes
	var buf bytes.Buffer
	err := b.Pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return buf.Bytes(), nil
}

func (b *BaseReportGenerator) SetUser(user interface{}) error {
	if _, ok := user.(db.Users); !ok {
		if users, ok := user.([]db.Users); !ok || len(users) == 0 {
			return fmt.Errorf("error while parsing user struct")
		}
	}

	b.User = user
	return nil
}

func (b *BaseReportGenerator) SetContent(content interface{}) error {
	b.Content = content
	return nil
}

func (p *BaseReportGenerator) SetBranding(branding BrandingInfo) error {
	if p.Branding.Theme == nil {
		p.Branding.Theme = &DefaultTheme
	}

	p.Branding = branding
	return nil
}

func (b *BaseReportGenerator) SaveToFile(file_name string) error {
	pdf, err := b.Generate()
	if err != nil {
		return err
	}

	return os.WriteFile(file_name, pdf, 0644)
}

func (b *BaseReportGenerator) addUserInfo() {
	pdf := b.Pdf

	pdf.SetFont("Arial", "B", 14)
	accent := b.Branding.Theme.Accent
	pdf.SetFillColor(int(accent.R), int(accent.G), int(accent.B))
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(190, 10, "User Information", "", 1, "L", true, 0, "")
	pdf.SetTextColor(int(b.Branding.Theme.Text.R), int(b.Branding.Theme.Text.G), int(b.Branding.Theme.Text.B))
	pdf.Ln(5)
	pdf.SetFont("Arial", "", 12)

	if user, ok := b.User.(*db.Users); ok {
		b.addSingleUserInfo(*user)
	} else if users, ok := b.User.([]*db.Users); ok && len(users) > 0 {
		for i, user := range users {
			if i > 0 {
				pdf.Ln(5)
			}

			b.addSingleUserInfo(*user)
		}
	}

	pdf.Ln(10)
}

func (b *BaseReportGenerator) addHeader() {
	pdf := b.Pdf

	// Set header color
	primary := b.Branding.Theme.Primary
	pdf.SetFillColor(int(primary.R), int(primary.G), int(primary.B))

	// Add logo if available
	if b.Branding.LogoURL != "" {
		pdf.Image(b.Branding.LogoURL, 10, 10, 30, 0, false, "", 0, "")
	}

	// Add company name
	pdf.SetFont("Arial", "B", 16)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetY(10)
	pdf.SetX(50)
	pdf.CellFormat(150, 10, b.Branding.CompanyName, "", 0, "L", true, 0, "")

	// Add report type
	pdf.SetFont("Arial", "I", 12)
	pdf.SetY(20)
	pdf.SetX(50)
	pdf.CellFormat(150, 10, "Report Type: "+b.ContentType, "", 0, "L", true, 0, "")

	// Add date
	pdf.SetY(30)
	pdf.SetX(50)
	pdf.CellFormat(150, 10, "Generated: "+time.Now().Format("2006-01-02 15:04:05"), "", 0, "L", true, 0, "")

	// Reset for body content
	pdf.SetY(45)
	pdf.SetTextColor(int(b.Branding.Theme.Text.R), int(b.Branding.Theme.Text.G), int(b.Branding.Theme.Text.B))
}

func (b *BaseReportGenerator) addFooter() {
	pdf := b.Pdf

	// Save current position
	currentY := pdf.GetY()

	// Move to footer position
	// pdf.SetY(pdf.GetPageSize() - 20)

	// Add footer line
	secondary := b.Branding.Theme.Secondary
	pdf.SetDrawColor(int(secondary.R), int(secondary.G), int(secondary.B))
	pdf.Line(10, pdf.GetY(), 200, pdf.GetY())

	// Add contact information
	pdf.SetFont("Arial", "", 8)
	pdf.SetY(pdf.GetY() + 3)
	pdf.CellFormat(190, 5, fmt.Sprintf("Contact: %s | %s | %s",
		b.Branding.Addr, b.Branding.AdminContactNumber, b.Branding.AdminEmailAddress), "", 0, "C", false, 0, "")

	// Add page number
	pdf.SetY(pdf.GetY() + 5)
	pdf.CellFormat(190, 5, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")

	// Restore position
	pdf.SetY(currentY)
}

func (b *BaseReportGenerator) addTableRow(label, value string) {
	pdf := b.Pdf
	pdf.CellFormat(40, 8, label, "1", 0, "L", false, 0, "")
	pdf.CellFormat(150, 8, value, "1", 1, "L", false, 0, "")
}

func (b *BaseReportGenerator) addSingleUserInfo(user db.Users) {
	pdf := b.Pdf

	// Table header
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(40, 8, "Field", "1", 0, "L", false, 0, "")
	pdf.CellFormat(150, 8, "Value", "1", 1, "L", false, 0, "")

	// Table content
	pdf.SetFont("Arial", "", 10)

	// Add user details
	b.addTableRow("Name", fmt.Sprintf("%s %s", user.FirstName, user.LastName))
	b.addTableRow("Username", user.UserName)
	b.addTableRow("Email", user.Email)
	b.addTableRow("Contact", fmt.Sprintf("%d", user.ContactNumber))
	b.addTableRow("Created At", user.CreatedAt.Format("2006-01-02 15:04:05"))
}
