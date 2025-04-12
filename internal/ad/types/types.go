package types

type UserInfo struct {
	DN          string
	Username    string
	DisplayName string
	Email       string
	UPN         string
	Groups      []string
	Attributes  map[string][]string
}

type GroupInfo struct {
	DN          string
	Name        string
	Description string
	Members     []string
	Attributes  map[string][]string
}
