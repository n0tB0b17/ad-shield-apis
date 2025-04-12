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

type ReqADFetchUsers struct {
	Address    string `json:"address"`
	DomainName string `json:"domain_name"`
}

type ReqGetUserByDN struct {
	Address    string `json:"address"`
	DomainName string `json:"domain_name"`
	DN         string `json:"dn"`
}
