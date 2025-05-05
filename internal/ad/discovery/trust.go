package discovery

import (
	"fmt"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

type TrustDirection int

const (
	TrustDirectionInbound       TrustDirection = 1
	TrustDirectionOutbound      TrustDirection = 2
	TrustDirectionBidirectional TrustDirection = 3
)

type TrustType int

const (
	TrustTypeWindows  TrustType = 1
	TrustTypeForest   TrustType = 2
	TrustTypeExternal TrustType = 3
	TrustTypeRealms   TrustType = 4
)

type TrustRelationship struct {
	SourceDomain    string
	TargetDomain    string
	TrustDirection  TrustDirection
	TrustType       TrustType
	TrustAttributes map[string]interface{}
	IsActive        bool
	IsTransitive    bool
	ForestTrust     string
	CreatedAt       string
	ModifiedTime    string
}

func (tr *TrustRelationship) String() string {
	dirStr := "UNKNOWN"
	switch tr.TrustDirection {
	case TrustDirectionInbound:
		dirStr = "Inbound"
	case TrustDirectionOutbound:
		dirStr = "Outbound"
	case TrustDirectionBidirectional:
		dirStr = "Bidirectional"
	}

	typStr := "UNKNOWN"
	switch tr.TrustType {
	case TrustTypeWindows:
		typStr = "Windows"
	case TrustTypeForest:
		typStr = "Forest"
	case TrustTypeExternal:
		typStr = "External"
	case TrustTypeRealms:
		typStr = "Realm"
	}

	return fmt.Sprintf("%s -> %s [%s, %s, Active: %t, Transitive: %t] \n",
		tr.SourceDomain, tr.TargetDomain, dirStr, typStr, tr.IsActive, tr.IsTransitive)
}

type TrustDiscovery struct {
	conn     *connection.Manager
	cache    map[string][]*TrustRelationship
	mu       sync.RWMutex
	cacheTTL time.Duration
}

func (td *TrustDiscovery) GetNewTrustDiscovery(conn *connection.Manager) *TrustDiscovery {
	return &TrustDiscovery{
		conn:     conn,
		cache:    make(map[string][]*TrustRelationship),
		cacheTTL: 5 * time.Minute,
	}
}

func (td *TrustDiscovery) GetDomainTrust(username, password, dn string) ([]*TrustRelationship, error) {
	cached := td.getCache(dn)
	if cached != nil {
		fmt.Printf("Found TrustRelationship (%d) for domain: %s inside of cache \n", len(cached), dn)
		return cached, nil
	}

	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"cn", "trustPartner", "trustDirection", "trustType", "trustAttributes", "whenCreated", "whenChanged"},
		nil,
	)

	resp, err := td.conn.Search(username, password, req)
	if err != nil {
		return nil, fmt.Errorf("GetDomainTrust:: %v", err)
	}

	domainName := extractDomainNameFromDN(dn)
	if len(domainName) < 1 {
		return nil, fmt.Errorf("invalid domain name provided")
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("record not found, entries is zero")
	}

	relationship := make([]*TrustRelationship, 0, len(resp.Entries))
	for _, ent := range resp.Entries {
		docs, err := parseTrustEntry(ent, domainName)
		if err != nil {
			fmt.Printf("error parsing trust-entries: %v \n", err)
			continue
		}

		relationship = append(relationship, docs)
	}

	td.setCache(dn, relationship)
	return relationship, nil
}

func (td *TrustDiscovery) ClearCache() {
	td.mu.Lock()
	defer td.mu.Unlock()

	td.cache = make(map[string][]*TrustRelationship)
	fmt.Println("TrustDiscovery cache cleared")
}

func (td *TrustDiscovery) setCache(k string, v []*TrustRelationship) {
	td.mu.Lock()
	defer td.mu.Unlock()

	td.cache[k] = v
}

func (td *TrustDiscovery) getCache(k string) []*TrustRelationship {
	td.mu.RLock()
	defer td.mu.Unlock()

	v, ok := td.cache[k]
	if !ok {
		return nil
	}

	return v
}

func parseTrustEntry(ent *ldap.Entry, dn string) (*TrustRelationship, error) {
	tp := ent.GetAttributeValue("trustPartner")
	if tp == "" {
		return nil, fmt.Errorf("trusted partner is empty")
	}

	td := ent.GetAttributeValue("trustDirection")
	var trustDirection TrustDirection
	if td != "" {
		var tdint int
		_, err := fmt.Sscanf(td, "%d", &tdint)
		if err != nil {
			return nil, fmt.Errorf("unable to parse trustDirection: %v", err)
		}

		trustDirection = TrustDirection(tdint)
	}

	tt := ent.GetAttributeValue("trustType")
	var trustType TrustType
	if tt != "" {
		var ttint int
		_, err := fmt.Sscanf(tt, "%d", &ttint)
		if err != nil {
			return nil, fmt.Errorf("unable to parse trustType: %v", err)
		}

		trustType = TrustType(ttint)
	}

	ta := ent.GetAttributeValue("trustAttributes")
	parseTA := parseTrustAttribute(ta)

	resp := &TrustRelationship{
		SourceDomain:    dn,
		TargetDomain:    tp,
		TrustDirection:  trustDirection,
		TrustType:       trustType,
		TrustAttributes: parseTA,
		IsTransitive:    isTransitiveTrust(parseTA),
		IsActive:        trustDirection != 0,
		CreatedAt:       ent.GetAttributeValue("whenCreated"),
		ModifiedTime:    ent.GetAttributeValue("whenChanged"),
	}

	return resp, nil
}

func parseTrustAttribute(v string) map[string]interface{} {
	attributes := make(map[string]interface{})

	if v == "" {
		return attributes
	}

	var attrInt int
	_, err := fmt.Sscanf(v, "%d", &attrInt)
	if err != nil {
		return attributes
	}

	if attrInt&0x00000001 != 0 {
		attributes["TRUST_ATTRIBUTE_NON_TRANSITIVE"] = true
	}
	if attrInt&0x00000002 != 0 {
		attributes["TRUST_ATTRIBUTE_UPLEVEL_ONLY"] = true
	}
	if attrInt&0x00000004 != 0 {
		attributes["TRUST_ATTRIBUTE_QUARANTINED_DOMAIN"] = true
	}
	if attrInt&0x00000008 != 0 {
		attributes["TRUST_ATTRIBUTE_FOREST_TRANSITIVE"] = true
	}
	if attrInt&0x00000010 != 0 {
		attributes["TRUST_ATTRIBUTE_CROSS_ORGANIZATION"] = true
	}
	if attrInt&0x00000020 != 0 {
		attributes["TRUST_ATTRIBUTE_WITHIN_FOREST"] = true
	}
	if attrInt&0x00000040 != 0 {
		attributes["TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL"] = true
	}
	if attrInt&0x00000080 != 0 {
		attributes["TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION"] = true
	}
	if attrInt&0x00000200 != 0 {
		attributes["TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION"] = true
	}
	if attrInt&0x00000400 != 0 {
		attributes["TRUST_ATTRIBUTE_PIM_TRUST"] = true
	}
	return attributes
}

func isTransitiveTrust(attr map[string]interface{}) bool {
	if _, found := attr["TRUST_ATTRIBUTE_NON_TRANSITIVE"]; found {
		return false
	}

	if _, found := attr["TRUST_ATTRIBUTE_FOREST_TRANSITIVE"]; found {
		return true
	}

	return false
}
