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

type ReqCreateNewUser struct {
	Address           string `json:"address"`
	DomainName        string `json:"domain_name"`
	SAMAccountName    string `json:"samAccountName" validate:"required,min=1,max=20"`
	Password          string `json:"password"`
	DistinguishedName string `json:"distinguishedName" validate:"required"`
	UserPrincipalName string `json:"userPrincipalName" validate:"required,email"`
	DisplayName       string `json:"displayName" validate:"required,min=1,max=64"`
	GivenName         string `json:"givenName" validate:"required,min=1,max=64"`
	SurName           string `json:"surName" validate:"required,min=1,max=64"`
	Description       string `json:"description,omitempty" validate:"max=256"`
	Title             string `json:"title,omitempty" validate:"max=64"`
	Department        string `json:"department,omitempty" validate:"max=64"`
	Company           string `json:"company,omitempty" validate:"max=64"`
	TelephoneNumber   string `json:"telephoneNumber,omitempty" validate:"max=32"`
	Mobile            string `json:"mobile,omitempty" validate:"max=32"`
}
