package models

type ReqClientAdd struct {
	ClientName        string `json:"clientName"`
	Description       string `json:"description"`
	OrganizationType  string `json:"organizationType"`
	HeadQuarter       string `json:"headQuarter"`
	AdminUserName     string `json:"adminUserName"`
	AdminEmail        string `json:"adminEmail"`
	AdminPassword     string `json:"adminPassword"`
	ContactNumber     uint64 `json:"contactNumber"`
	PrimaryColorHex   string `json:"primaryColorHex"`
	SecondaryColorHex string `json:"secondaryColorHex"`
}
