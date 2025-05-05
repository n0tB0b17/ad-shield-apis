package objects

import (
	"fmt"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

// OUAttribute defines LDAP attribute names for organizational units
type OUAttribute string

const (
	OUAttrName              OUAttribute = "name"
	OUAttrDistinguishedName OUAttribute = "distinguishedName"
	OUAttrDescription       OUAttribute = "description"
	OUAttrWhenCreated       OUAttribute = "whenCreated"
	OUAttrWhenChanged       OUAttribute = "whenChanged"
	OUAttrObjectGUID        OUAttribute = "objectGUID"
	OUAttrObjectSID         OUAttribute = "objectSid"
)

// OU represents an Organizational Unit in Active Directory
type OU struct {
	Name              string              `json:"name"`
	DistinguishedName string              `json:"distinguishedName"`
	Description       string              `json:"description"`
	WhenCreated       time.Time           `json:"whenCreated"`
	WhenChanged       time.Time           `json:"whenChanged"`
	ObjectGUID        string              `json:"objectGUID"`
	ObjectSID         string              `json:"objectSID"`
	RawAttributes     map[string][]string `json:"rawAttributes"`
}

// OUManager manages OU-related operations
type OUManager struct {
	conn   *connection.Manager
	baseDN string
}

// NewOUManager creates a new OUManager instance
func NewOUManager(conn *connection.Manager, baseDN string) *OUManager {
	return &OUManager{
		conn:   conn,
		baseDN: baseDN,
	}
}

// GetAllOUs fetches all OU objects in the AD forest
func (om *OUManager) GetAllOUs(bindUser, bindPassword string, page *int, attr []string) ([]*OU, error) {
	// Default page size (aligned with UserManager/GroupManager)
	p := 10
	if page != nil {
		p = *page
	}

	fmt.Println(p)

	if len(attr) == 0 {
		attr = defaultOUAttr()
	}

	req := ldap.NewSearchRequest(
		om.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		attr,
		nil,
	)

	resp, err := om.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search OUs: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no OUs found in domain: %s", om.baseDN)
	}

	var ous []*OU
	for _, ent := range resp.Entries {
		ou := om.entryToOU(ent)
		if ou != nil {
			ous = append(ous, ou)
		}
	}

	if len(ous) == 0 {
		fmt.Printf("no OUs parsed for domain: %s\n", om.baseDN)
	}

	return ous, nil
}

// GetOUByName retrieves an OU by its name
func (om *OUManager) GetOUByName(name, bindUser, bindPassword string) (*OU, error) {
	searchFilter := fmt.Sprintf("(&(objectClass=organizationalUnit)(name=%s))", ldap.EscapeFilter(name))
	req := ldap.NewSearchRequest(
		om.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		defaultOUAttr(),
		nil,
	)

	resp, err := om.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search OU by name: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no OU found with name: %s", name)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple OUs found with name: %s\n", name)
	}

	ou := om.entryToOU(resp.Entries[0])
	return ou, nil
}

// GetOUByDN retrieves an OU by its distinguishedName
func (om *OUManager) GetOUByDN(dn, bindUser, bindPassword string) (*OU, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		defaultOUAttr(),
		nil,
	)

	resp, err := om.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search OU by DN: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no OU found with DN: %s", dn)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple OUs found with DN: %s\n", dn)
	}

	ou := om.entryToOU(resp.Entries[0])
	return ou, nil
}

// FindOUs searches for OUs using a custom LDAP filter
func (om *OUManager) FindOUs(filter, bindUser, bindPassword string, attr []string) ([]*OU, error) {
	if len(attr) == 0 {
		attr = defaultOUAttr()
	}

	if !strings.HasPrefix(filter, "(&") && !strings.HasPrefix(filter, "(|") && !strings.HasPrefix(filter, "(") {
		filter = fmt.Sprintf("(&(objectClass=organizationalUnit)(%s))", filter)
	}

	req := ldap.NewSearchRequest(
		om.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attr,
		nil,
	)

	resp, err := om.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to find OUs: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no OUs found with filter: %s", filter)
	}

	var ous []*OU
	for _, ent := range resp.Entries {
		ou := om.entryToOU(ent)
		ous = append(ous, ou)
	}

	return ous, nil
}

// CreateOU adds a new OU to Active Directory
func (om *OUManager) CreateOU(ou *OU, bindUser, bindPassword string) error {
	fmt.Println("Adding OU:")
	fmt.Println(ou)

	// Validate required fields
	if ou.Name == "" {
		return fmt.Errorf("name is a required field")
	}
	if ou.DistinguishedName == "" {
		return fmt.Errorf("distinguishedName is a required field")
	}

	// Build LDAP attributes
	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "organizationalUnit"}},
		{Type: "name", Vals: []string{ou.Name}},
	}

	if ou.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: "description", Vals: []string{ou.Description}})
	}

	// Create the LDAP add request
	req := ldap.NewAddRequest(ou.DistinguishedName, nil)
	req.Attributes = attrs

	// Get LDAP connection
	conn, err := om.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer om.conn.ReleaseConnection(conn)

	// Execute the add request
	if err := conn.Add(req); err != nil {
		return fmt.Errorf("failed to create OU: %v", err)
	}

	fmt.Printf("OU created successfully\n")
	return nil
}

func (om *OUManager) DeleteOU(dn, bindUser, bindPassword string) error {
	req := ldap.NewDelRequest(dn, nil)

	conn, err := om.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer om.conn.ReleaseConnection(conn)

	if err := conn.Delete(req); err != nil {
		return fmt.Errorf("failed to delete OU: %v", err)
	}

	fmt.Printf("OU deleted successfully\n")
	return nil
}

func (om *OUManager) entryToOU(o *ldap.Entry) *OU {
	ou := &OU{
		RawAttributes: make(map[string][]string),
	}

	// Store raw attributes
	for _, attr := range o.Attributes {
		ou.RawAttributes[attr.Name] = attr.Values
	}

	// Helper to get single attribute value
	getSingleValue := func(attr string) string {
		v := o.GetAttributeValue(attr)
		if len(v) > 0 {
			return v
		}
		return ""
	}

	// Helper to parse time
	parseTime := func(t string) time.Time {
		if t == "" {
			return time.Time{}
		}
		parsedTime, err := time.Parse("20060102150405.0Z", t)
		if err != nil {
			return time.Time{}
		}
		return parsedTime
	}

	ou.Name = getSingleValue(string(OUAttrName))
	ou.DistinguishedName = getSingleValue(string(OUAttrDistinguishedName))
	ou.Description = getSingleValue(string(OUAttrDescription))
	ou.WhenCreated = parseTime(getSingleValue(string(OUAttrWhenCreated)))
	ou.WhenChanged = parseTime(getSingleValue(string(OUAttrWhenChanged)))
	ou.ObjectGUID = getSingleValue(string(OUAttrObjectGUID))
	ou.ObjectSID = getSingleValue(string(OUAttrObjectSID))

	return ou
}

// defaultOUAttr returns the default attributes to fetch for OUs
func defaultOUAttr() []string {
	return []string{
		string(OUAttrName),
		string(OUAttrDistinguishedName),
		string(OUAttrDescription),
		string(OUAttrWhenCreated),
		string(OUAttrWhenChanged),
		string(OUAttrObjectGUID),
		string(OUAttrObjectSID),
	}
}
