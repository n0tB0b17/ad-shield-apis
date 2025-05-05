package models

type ReqADAuth struct {
	Address    string `json:"address"`
	DomainName string `json:"domain_name"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type ReqADServerHealthCheck struct {
	Address string `json:"address"`
}

type ReqADObjectFetch struct {
	Address    string `json:"address"`
	DomainName string `json:"domain_name"`
}

type ReqADObjectFetchWithDN struct {
	Address    string `json:"address"`
	DomainName string `json:"domain_name"`
	DN         string `json:"dn"`
}

type ReqCreateNewGroup struct {
	Address           string `json:"address"`
	DomainName        string `json:"domain_name"`
	SAMAccountName    string `json:"samAccountName"`
	DistinguishedName string `json:"distinguishedName"`
	Name              string `json:"name"`
	DisplayName       string `json:"displayName"`
	Description       string `json:"description"`
	Type              int    `json:"type"`
}

type ReqCreateNewOU struct {
	Address           string `json:"address"`
	DomainName        string `json:"domain_name"`
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedName"`
	Description       string `json:"description"`
}
