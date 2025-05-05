package objects

import (
	"fmt"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

type GroupAttribute string

const (
	GroupAttrName              GroupAttribute = "name"
	GroupAttrSAMAccountName    GroupAttribute = "sAMAccountName"
	GroupAttrDistinguishedName GroupAttribute = "distinguishedName"
	GroupAttrDisplayName       GroupAttribute = "displayName"
	GroupAttrDescription       GroupAttribute = "description"
	GroupAttrGroupType         GroupAttribute = "groupType"
	GroupAttrMember            GroupAttribute = "member"
	GroupAttrMemberOf          GroupAttribute = "memberOf"
	GroupAttrMail              GroupAttribute = "mail"
	GroupAttrManagedBy         GroupAttribute = "managedBy"
	GroupAttrWhenCreated       GroupAttribute = "whenCreated"
	GroupAttrWhenChanged       GroupAttribute = "whenChanged"
	GroupAttrObjectGUID        GroupAttribute = "objectGUID"
	GroupAttrObjectSID         GroupAttribute = "objectSID"
)

type GroupType int

const (
	GroupTypeGlobal      GroupType = 2
	GroupTypeDomainLocal GroupType = 4
	GroupTypeUniversal   GroupType = 8
	GroupTypeSecurity              = 0x80000000
)

type Group struct {
	DN                string              `json:"dn"`
	Name              string              `json:"name"`
	SAMAccountName    string              `json:"samAccountName"`
	DistinguishedName string              `json:"distinguishedName"`
	DisplayName       string              `json:"displayName"`
	Description       string              `json:"description"`
	Type              GroupType           `json:"type"`
	Members           []string            `json:"members"`
	MemberOf          []string            `json:"memberOf"`
	Email             string              `json:"email"`
	Scope             string              `json:"scope"`
	ManagedBy         string              `json:"managedBy"`
	GroupCategory     string              `json:"groupCategory"`
	WhenCreated       string              `json:"whenCreated"`
	WhenChanged       string              `json:"whenChanged"`
	ObjectGUID        string              `json:"objectGUID"`
	ObjectSID         string              `json:"objectSID"`
	RawAttributes     map[string][]string `json:"rawAttributes"`
}

type GroupManager struct {
	conn   *connection.Manager
	baseDN string
}

// NewGroupManager creates a new GroupManager instance
func NewGroupManager(conn *connection.Manager, baseDN string) *GroupManager {
	return &GroupManager{
		conn:   conn,
		baseDN: baseDN,
	}
}

func (gm *GroupManager) GetAllGroups(bindUser, bindPassword string, page *int, attr []string) ([]*Group, error) {
	p := 10
	if page != nil {
		p = *page
	}

	fmt.Println(p)

	if len(attr) == 0 {
		attr = defaultGroupAttr()
	}

	req := ldap.NewSearchRequest(
		gm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		attr,
		nil,
	)

	resp, err := gm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search groups: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no groups found in domain: %s", gm.baseDN)
	}

	var groups []*Group
	for _, ent := range resp.Entries {
		group := gm.entryToGroup(ent)
		if group != nil {
			groups = append(groups, group)
		}
	}

	if len(groups) == 0 {
		fmt.Printf("no groups parsed for domain: %s\n", gm.baseDN)
	}

	return groups, nil
}

// GetGroupBySAMAccountName retrieves a group by its sAMAccountName
func (gm *GroupManager) GetGroupBySAMAccountName(samAccountName, bindUser, bindPassword string) (*Group, error) {
	searchFilter := fmt.Sprintf("(&(objectClass=group)(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName))
	req := ldap.NewSearchRequest(
		gm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		defaultGroupAttr(),
		nil,
	)

	resp, err := gm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search group by sAMAccountName: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no group found with sAMAccountName: %s", samAccountName)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple groups found with sAMAccountName: %s\n", samAccountName)
	}

	group := gm.entryToGroup(resp.Entries[0])
	return group, nil
}

// GetGroupByDN retrieves a group by its distinguishedName
func (gm *GroupManager) GetGroupByDN(dn, bindUser, bindPassword string) (*Group, error) {
	req := ldap.NewSearchRequest(
		dn, // Search directly at the DN
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		defaultGroupAttr(),
		nil,
	)

	resp, err := gm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to search group by DN: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no group found with DN: %s", dn)
	}

	if len(resp.Entries) > 1 {
		fmt.Printf("multiple groups found with DN: %s\n", dn)
	}

	group := gm.entryToGroup(resp.Entries[0])
	return group, nil
}

// FindGroups searches for groups using a custom LDAP filter
func (gm *GroupManager) FindGroups(filter, bindUser, bindPassword string, attr []string) ([]*Group, error) {
	if len(attr) == 0 {
		attr = defaultGroupAttr()
	}

	if !strings.HasPrefix(filter, "(&") && !strings.HasPrefix(filter, "(|") && !strings.HasPrefix(filter, "(") {
		filter = fmt.Sprintf("(&(objectClass=group)(%s))", filter)
	}

	req := ldap.NewSearchRequest(
		gm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attr,
		nil,
	)

	resp, err := gm.conn.Search(bindUser, bindPassword, req)
	if err != nil {
		return nil, fmt.Errorf("failed to find groups: %v", err)
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("no groups found with filter: %s", filter)
	}

	var groups []*Group
	for _, ent := range resp.Entries {
		group := gm.entryToGroup(ent)
		groups = append(groups, group)
	}

	return groups, nil
}

// CreateGroup adds a new group to Active Directory
func (gm *GroupManager) CreateGroup(group *Group, bindUser, bindPassword string) error {
	fmt.Println("Adding group:")
	fmt.Println(group)

	// Validate required fields
	if group.SAMAccountName == "" {
		return fmt.Errorf("sAMAccountName is a required field")
	}
	if group.DistinguishedName == "" {
		return fmt.Errorf("distinguishedName is a required field")
	}
	if group.Type == 0 {
		return fmt.Errorf("groupType is a required field")
	}

	// Build LDAP attributes
	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "group"}},
		{Type: "sAMAccountName", Vals: []string{group.SAMAccountName}},
		{Type: "groupType", Vals: []string{fmt.Sprintf("%d", group.Type)}},
	}

	if group.Name != "" {
		attrs = append(attrs, ldap.Attribute{Type: "name", Vals: []string{group.Name}})
	}
	if group.DisplayName != "" {
		attrs = append(attrs, ldap.Attribute{Type: "displayName", Vals: []string{group.DisplayName}})
	}
	if group.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: "description", Vals: []string{group.Description}})
	}
	if group.Email != "" {
		attrs = append(attrs, ldap.Attribute{Type: "mail", Vals: []string{group.Email}})
	}
	if group.ManagedBy != "" {
		attrs = append(attrs, ldap.Attribute{Type: "managedBy", Vals: []string{group.ManagedBy}})
	}
	if len(group.Members) > 0 {
		attrs = append(attrs, ldap.Attribute{Type: "member", Vals: group.Members})
	}

	// Create the LDAP add request
	req := ldap.NewAddRequest(group.DistinguishedName, nil)
	req.Attributes = attrs

	// Get LDAP connection
	conn, err := gm.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer gm.conn.ReleaseConnection(conn)

	// Execute the add request
	if err := conn.Add(req); err != nil {
		return fmt.Errorf("failed to create group: %v", err)
	}

	fmt.Printf("Group created successfully\n")
	return nil
}

func (gm *GroupManager) DeleteGroup(dn, bindUser, bindPassword string) error {
	req := ldap.NewDelRequest(dn, nil)

	conn, err := gm.conn.GetConnection(bindUser, bindPassword)
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %v", err)
	}
	defer gm.conn.ReleaseConnection(conn)

	if err := conn.Delete(req); err != nil {
		return fmt.Errorf("failed to delete group: %v", err)
	}

	fmt.Printf("Group deleted successfully\n")
	return nil
}

func (gm *GroupManager) entryToGroup(g *ldap.Entry) *Group {
	group := &Group{
		RawAttributes: make(map[string][]string),
	}

	for _, attr := range g.Attributes {
		group.RawAttributes[attr.Name] = attr.Values
	}

	getSingleValue := func(attr string) string {
		v := g.GetAttributeValue(attr)
		if len(v) > 0 {
			return v
		}
		return ""
	}

	// Helper to parse time
	parseTime := func(t string) string {
		if t == "" {
			return ""
		}
		parsedTime, err := time.Parse("20060102150405.0Z", t)
		if err != nil {
			return t // Return raw string if parsing fails
		}
		return parsedTime.Format(time.RFC3339)
	}

	// Helper to parse groupType
	parseGroupType := func(v string) GroupType {
		if v == "" {
			return 0
		}
		var gt int
		_, err := fmt.Sscanf(v, "%d", &gt)
		if err != nil {
			return 0
		}
		return GroupType(gt)
	}

	// Helper to determine scope and category
	setScopeAndCategory := func(gt GroupType) (scope, category string) {
		if gt&GroupTypeSecurity != 0 {
			category = "Security"
		} else {
			category = "Distribution"
		}

		switch {
		case gt&GroupTypeGlobal != 0:
			scope = "Global"
		case gt&GroupTypeDomainLocal != 0:
			scope = "DomainLocal"
		case gt&GroupTypeUniversal != 0:
			scope = "Universal"
		default:
			scope = "Unknown"
		}
		return scope, category
	}

	group.DN = g.DN
	group.Name = getSingleValue(string(GroupAttrName))
	group.SAMAccountName = getSingleValue(string(GroupAttrSAMAccountName))
	group.DistinguishedName = getSingleValue(string(GroupAttrDistinguishedName))
	group.DisplayName = getSingleValue(string(GroupAttrDisplayName))
	group.Description = getSingleValue(string(GroupAttrDescription))
	group.Email = getSingleValue(string(GroupAttrMail))
	group.ManagedBy = getSingleValue(string(GroupAttrManagedBy))
	group.Members = g.GetAttributeValues(string(GroupAttrMember))
	group.MemberOf = g.GetAttributeValues(string(GroupAttrMemberOf))
	group.WhenCreated = parseTime(getSingleValue(string(GroupAttrWhenCreated)))
	group.WhenChanged = parseTime(getSingleValue(string(GroupAttrWhenChanged)))
	group.ObjectGUID = getSingleValue(string(GroupAttrObjectGUID))
	group.ObjectSID = getSingleValue(string(GroupAttrObjectSID))

	group.Type = parseGroupType(getSingleValue(string(GroupAttrGroupType)))
	group.Scope, group.GroupCategory = setScopeAndCategory(group.Type)

	return group
}

// defaultGroupAttr returns the default attributes to fetch for groups
func defaultGroupAttr() []string {
	return []string{
		string(GroupAttrName),
		string(GroupAttrSAMAccountName),
		string(GroupAttrDistinguishedName),
		string(GroupAttrDisplayName),
		string(GroupAttrDescription),
		string(GroupAttrGroupType),
		string(GroupAttrMember),
		string(GroupAttrMemberOf),
		string(GroupAttrMail),
		string(GroupAttrManagedBy),
		string(GroupAttrWhenCreated),
		string(GroupAttrWhenChanged),
		string(GroupAttrObjectGUID),
		string(GroupAttrObjectSID),
	}
}
