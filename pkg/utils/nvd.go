package utils

type VulnerabilityInfo struct {
	CVEID       string `json:"cveid"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type NVDResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		Cve struct {
			Id               string `json:"id"`
			SourceIdentifier string `json:"sourceIdentifier"`
			Published        string `json:"published"`
			LastModified     string `json:"lastModified"`
			VulnStatus       string `json:"vulnStatus"`
			Descriptions     []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				Url    string   `json:"url"`
				Source string   `json:"source"`
				Tags   []string `json:"tags"`
			} `json:"references"`
			Metrics struct {
				CvssMetricV31 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AttackVector          string  `json:"attackVector"`
						AttackComplexity      string  `json:"attackComplexity"`
						PrivilegesRequired    string  `json:"privilegesRequired"`
						UserInteraction       string  `json:"userInteraction"`
						Scope                 string  `json:"scope"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
						BaseSeverity          string  `json:"baseSeverity"`
					} `json:"cvssData"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"cvssMetricV3.1"`
			} `json:"metrics"`
			Weaknesses []struct {
				Source      string `json:"source"`
				Type        string `json:"type"`
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					Operator string `json:"operator"`
					Negate   bool   `json:"negate"`
					Cpes     []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Cpe23Uri              string `json:"cpe23Uri"`
						CpeName               string `json:"cpeName"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
						VersionStartExcluding string `json:"versionStartExcluding"`
						VersionStartIncluding string `json:"versionStartIncluding"`
					} `json:"cpes"`
				} `json:"nodes"`
			} `json:"configurations"`
			CvssSeverity string `json:"cvssSeverity"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}
