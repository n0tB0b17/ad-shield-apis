package vulners

type Resp struct {
	Result string     `json:"result"`
	Data   VulnerResp `json:"data"`
}

type VulnerResp struct {
	ExactMatch    int      `json:"exactMatch"`
	References    string   `json:"references"`
	Total         int      `json:"total"`
	MaxSearchSize int      `json:"maxSearchSize"`
	Search        []Search `json:"search"`
}

type Search struct {
	Index           string                 `json:"_index"`
	ID              string                 `json:"_id"`
	Score           float64                `json:"_score"`
	Source          SourceData             `json:"_source"`
	Highlight       map[string]interface{} `json:"highlight,omitempty"`
	Sort            []interface{}          `json:"sort,omitempty"`
	FlatDescription string                 `json:"flatDescription"`
}

type SourceData struct {
	Lastseen       interface{} `json:"lastseen"`
	Description    string      `json:"description"`
	CVSS3          CVSS3       `json:"cvss3,omitempty"`
	Published      interface{} `json:"published"`
	Type           string      `json:"type"`
	Title          string      `json:"title"`
	BulletinFamily string      `json:"bulletinFamily"`
	CVSS2          CVSS2       `json:"cvss2,omitempty"`
	CWE            []string    `json:"cwe,omitempty"`
	CveList        []string    `json:"cvelist"`
	Modified       interface{} `json:"modified"`
	ID             string      `json:"id"`
	Href           string      `json:"href"`
	CVSS           CVSSSummary `json:"cvss,omitempty"`
	PrivateArea    int         `json:"privateArea,omitempty"`
	Vhref          string      `json:"vhref"`
}

type CVSS3 struct {
	CVSSv3 CVSSv3Details `json:"cvssV3"`
}

type CVSSv3Details struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

type CVSSSummary struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector"`
	Version  string  `json:"version"`
}

type CVSS2 struct {
	CVSSv2 CVSSv2Details `json:"cvssV2"`
}

type CVSSv2Details struct {
	Version                 string  `json:"version"`
	VectorString            string  `json:"vectorString"`
	BaseScore               float64 `json:"baseScore"`
	BaseSeverity            string  `json:"baseSeverity"`
	AttackVector            string  `json:"attackVector"`
	AttackComplexity        string  `json:"attackComplexity"`
	Authentication          string  `json:"authentication"`
	ConfidentialityImpact   string  `json:"confidentialityImpact"`
	IntegrityImpact         string  `json:"integrityImpact"`
	AvailabilityImpact      string  `json:"availabilityImpact"`
	AcInsufInfo             bool    `json:"acInsufInfo"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}
