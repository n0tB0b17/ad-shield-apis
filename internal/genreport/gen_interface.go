package genreport

type ReportGenerator interface {
	Generate() ([]byte, error)
	SetUser(interface{}) error
	SetContent(interface{}) error
	SetBranding(interface{}) error
	SetAnalysis(map[string]interface{}) error
	SaveToFile(file_path string) error
}
