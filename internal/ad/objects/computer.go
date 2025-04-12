package objects

import (
	"fmt"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

// ComputerAttribute defines LDAP attribute names for computer objects
type ComputerAttribute string

const (
	ComputerAttrSAMAccountName     ComputerAttribute = "sAMAccountName"
	ComputerAttrDistinguishedName  ComputerAttribute = "distinguishedName"
	ComputerAttrDNSHostName        ComputerAttribute = "dNSHostName"
	ComputerAttrDescription        ComputerAttribute = "description"
	ComputerAttrOperatingSystem    ComputerAttribute = "operatingSystem"
	ComputerAttrOSVersion          ComputerAttribute = "operatingSystemVersion"
	ComputerAttrWhenCreated        ComputerAttribute = "whenCreated"
	ComputerAttrWhenChanged        ComputerAttribute = "whenChanged"
	ComputerAttrObjectGUID         ComputerAttribute = "objectGUID"
	ComputerAttrObjectSID          ComputerAttribute = "objectSid"
	ComputerAttrUserAccountControl ComputerAttribute = "userAccountControl"
	ComputerAttrLastLogon          ComputerAttribute = "lastLogon"
	ComputerAttrLastLogonTimestamp ComputerAttribute = "lastLogonTimestamp"
)

// ComputerAccountControlFlag reuses UserAccountControlFlag for computers
// Only relevant flags are listed
const (
	ComputerUAC_WORKSTATION_TRUST_ACCOUNT UserAccountControlFlag = 0x1000 // Default for computers
	ComputerUAC_ACCOUNTDISABLE            UserAccountControlFlag = 0x0002
)

// Computer represents a computer object in Active Directory
type Computer struct {
	SAMAccountName         string
	DistinguishedName      string
	DNSHostName            string
	Description            string
	OperatingSystem        string
	OperatingSystemVersion string

	WhenCreated        time.Time
	WhenChanged        time.Time
	LastLogon          int64
	LastLogonTimestamp int64

	UserAccountControl uint32
	ObjectGUID         string
	ObjectSID          string

	RawAttributes map[string][]string
}

// ComputerManager manages computer-related operations
type ComputerManager struct {
	conn   *connection.Manager
	baseDN string
}

// NewComputerManager creates a new ComputerManager instance
func NewComputerManager(conn *connection.Manager, baseDN string) *ComputerManager {
	return &ComputerManager{
		conn:   conn,
		baseDN: baseDN,
	}
}

// GetAllComputers fetches all computer objects in the AD forest
func (cm *ComputerManager) GetAllComputers(bindUser, bindPassword string, page *int, attr []string) ([]*Computer, error) {
	// Default page size (aligned with UserManager/GroupManager/OUManager)
	p := 10
	if page != nil {
		p = *page
	}

	fmt.Println(p)

	if len(attr) == 0 {
		attr = defaultComputerAttr()
	}

	req := ldap.NewSearchRequest(
		cm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(objectCategory=computer))",
		attr,
		nil,
	)

	resp, err := cm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search computers: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no computers found in domain: %s", cm.baseDN)
	}

	var computers []*Computer
	for _, ent := range resp.Entries {
		computer := cm.entryToComputer(ent)
		if computer != nil {
			computers = append(computers, computer)
		}
	}

	if len(computers) == 0 {
		fmt.Printf("no computers parsed for domain: %s\n", cm.baseDN)
	}

	return computers, nil
}

// GetComputerBySAMAccountName retrieves a computer by its sAMAccountName
func (cm *ComputerManager) GetComputerBySAMAccountName(samAccountName, bindUser, bindPassword string) (*Computer, error) {
	searchFilter := fmt.Sprintf("(&(objectClass=computer)(objectCategory=computer)(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName))
	req := ldap.NewSearchRequest(
		cm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		defaultComputerAttr(),
		nil,
	)

	resp, err := cm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search computer by sAMAccountName: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no computer found with sAMAccountName: %s", samAccountName)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple computers found with sAMAccountName: %s\n", samAccountName)
	}

	computer := cm.entryToComputer(resp.Entries[0])
	return computer, nil
}

// GetComputerByDN retrieves a computer by its distinguishedName
func (cm *ComputerManager) GetComputerByDN(dn, bindUser, bindPassword string) (*Computer, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(objectCategory=computer))",
		defaultComputerAttr(),
		nil,
	)

	resp, err := cm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search computer by DN: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no computer found with DN: %s", dn)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple computers found with DN: %s\n", dn)
	}

	computer := cm.entryToComputer(resp.Entries[0])
	return computer, nil
}

// FindComputers searches for computers using a custom LDAP filter
func (cm *ComputerManager) FindComputers(filter, bindUser, bindPassword string, attr []string) ([]*Computer, error) {
	if len(attr) == 0 {
		attr = defaultComputerAttr()
	}

	if !strings.HasPrefix(filter, "(&") && !strings.HasPrefix(filter, "(|") && !strings.HasPrefix(filter, "(") {
		filter = fmt.Sprintf("(&(objectClass=computer)(objectCategory=computer)(%s))", filter)
	}

	req := ldap.NewSearchRequest(
		cm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attr,
		nil,
	)

	resp, err := cm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to find computers: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no computers found with filter: %s", filter)
	}

	var computers []*Computer
	for _, ent := range resp.Entries {
		computer := cm.entryToComputer(ent)
		computers = append(computers, computer)
	}

	return computers, nil
}

// CreateComputer adds a new computer to Active Directory
func (cm *ComputerManager) CreateComputer(computer *Computer, password, bindUser, bindPassword string) error {
	fmt.Println("Adding computer:")
	fmt.Println(computer)

	// Validate required fields
	if computer.SAMAccountName == "" {
		return fmt.Errorf("sAMAccountName is a required field")
	}
	if computer.DistinguishedName == "" {
		return fmt.Errorf("distinguishedName is a required field")
	}

	// Ensure sAMAccountName ends with $
	if !strings.HasSuffix(computer.SAMAccountName, "$") {
		computer.SAMAccountName += "$"
	}

	// Build LDAP attributes
	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "person", "organizationalPerson", "user", "computer"}},
		{Type: "sAMAccountName", Vals: []string{computer.SAMAccountName}},
	}

	if computer.DNSHostName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "dNSHostName", Vals: []string{computer.DNSHostName}})
	}
	if computer.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: "description", Vals: []string{computer.Description}})
	}
	if computer.OperatingSystem != "" {
		attrs = append(attrs, ldap.Attribute{Type: "operatingSystem", Vals: []string{computer.OperatingSystem}})
	}
	if computer.OperatingSystemVersion != "" {
		attrs = append(attrs, ldap.Attribute{Type: "operatingSystemVersion", Vals: []string{computer.OperatingSystemVersion}})
	}

	// Set default userAccountControl for an enabled computer account
	intialUAC := uint32(ComputerUAC_WORKSTATION_TRUST_ACCOUNT | ComputerUAC_ACCOUNTDISABLE)
	attrs = append(attrs, ldap.Attribute{
		Type: "userAccountControl",
		Vals: []string{fmt.Sprintf("%d", intialUAC)},
	})

	// Create the LDAP add request
	req := ldap.NewAddRequest(computer.DistinguishedName, nil)
	req.Attributes = attrs

	// Get LDAP connection
	conn, err := cm.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer cm.conn.ReleaseConnection(conn)

	// Execute the add request
	if err := conn.Add(req); err != nil {
		return fmt.Errorf("failed to create computer: %v", err)
	}

	// Set password and enable the account if password is provided
	if password != "" {
		if err := cm.SetPassword(computer.DistinguishedName, password, bindUser, bindPassword); err != nil {
			fmt.Println("unable to set password")
			return fmt.Errorf("computer created but failed to set password: %v", err)
		}

		newModifyReq := ldap.NewModifyRequest(computer.DistinguishedName, nil)
		enabledUAC := uint32(ComputerUAC_WORKSTATION_TRUST_ACCOUNT)
		newModifyReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", enabledUAC)})

		if err := conn.Modify(newModifyReq); err != nil {
			return fmt.Errorf("computer created with password but failed to enable account: %v", err)
		}
	}

	fmt.Printf("Computer created successfully\n")
	return nil
}

// DeleteComputer removes a computer from Active Directory
func (cm *ComputerManager) DeleteComputer(dn, bindUser, bindPassword string) error {
	req := ldap.NewDelRequest(dn, nil)

	conn, err := cm.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer cm.conn.ReleaseConnection(conn)

	if err := conn.Delete(req); err != nil {
		return fmt.Errorf("failed to delete computer: %v", err)
	}

	fmt.Printf("Computer deleted successfully\n")
	return nil
}

// SetPassword sets the password for a computer account
func (cm *ComputerManager) SetPassword(dn, password, bindUser, bindPassword string) error {
	conn, err := cm.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer cm.conn.ReleaseConnection(conn)

	quotedPwd := fmt.Sprintf("\"%s\"", password)
	encodedPwd := utf16LittleEndianEncode(quotedPwd)

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{encodedPwd})

	if err := conn.Modify(mod); err != nil {
		fmt.Println("error while modifying password")
		return fmt.Errorf("failed to set password: %v", err)
	}

	return nil
}

// entryToComputer converts an LDAP entry to a Computer struct
func (cm *ComputerManager) entryToComputer(c *ldap.Entry) *Computer {
	computer := &Computer{
		RawAttributes: make(map[string][]string),
	}

	// Store raw attributes
	for _, attr := range c.Attributes {
		computer.RawAttributes[attr.Name] = attr.Values
	}

	// Helper to get single attribute value
	getSingleValue := func(attr string) string {
		v := c.GetAttributeValue(attr)
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

	// Helper to parse int64
	parseInt64 := func(v string) int64 {
		if v == "" {
			return 0
		}
		var holder int64
		_, err := fmt.Sscanf(v, "%d", &holder)
		if err != nil {
			return 0
		}
		return holder
	}

	computer.SAMAccountName = getSingleValue(string(ComputerAttrSAMAccountName))
	computer.DistinguishedName = getSingleValue(string(ComputerAttrDistinguishedName))
	computer.DNSHostName = getSingleValue(string(ComputerAttrDNSHostName))
	computer.Description = getSingleValue(string(ComputerAttrDescription))
	computer.OperatingSystem = getSingleValue(string(ComputerAttrOperatingSystem))
	computer.OperatingSystemVersion = getSingleValue(string(ComputerAttrOSVersion))
	computer.WhenCreated = parseTime(getSingleValue(string(ComputerAttrWhenCreated)))
	computer.WhenChanged = parseTime(getSingleValue(string(ComputerAttrWhenChanged)))
	computer.LastLogon = parseInt64(getSingleValue(string(ComputerAttrLastLogon)))
	computer.LastLogonTimestamp = parseInt64(getSingleValue(string(ComputerAttrLastLogonTimestamp)))
	computer.ObjectGUID = getSingleValue(string(ComputerAttrObjectGUID))
	computer.ObjectSID = getSingleValue(string(ComputerAttrObjectSID))

	uacStr := getSingleValue(string(ComputerAttrUserAccountControl))
	if uacStr != "" {
		var uac uint32
		_, err := fmt.Sscanf(uacStr, "%d", &uac)
		if err == nil {
			computer.UserAccountControl = uac
		}
	}

	return computer
}

// defaultComputerAttr returns the default attributes to fetch for computers
func defaultComputerAttr() []string {
	return []string{
		string(ComputerAttrSAMAccountName),
		string(ComputerAttrDistinguishedName),
		string(ComputerAttrDNSHostName),
		string(ComputerAttrDescription),
		string(ComputerAttrOperatingSystem),
		string(ComputerAttrOSVersion),
		string(ComputerAttrWhenCreated),
		string(ComputerAttrWhenChanged),
		string(ComputerAttrLastLogon),
		string(ComputerAttrLastLogonTimestamp),
		string(ComputerAttrObjectGUID),
		string(ComputerAttrObjectSID),
		string(ComputerAttrUserAccountControl),
	}
}
