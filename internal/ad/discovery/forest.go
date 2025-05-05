package discovery

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

type ForestInfo struct {
	Name                string
	RootDomain          string
	ForestFunctionLevel string
	DomainNamingMaster  string
	GlobalCatalogs      []string
	SchemaMaster        string
	DomainCount         int
	Sites               []string
	SchemaVersion       string
	CreationTime        time.Time
	ExtraAttributes     map[string][]string
}

type ForestDiscovery struct {
	connManager *connection.Manager
	cache       map[string]*ForestInfo
	cachemu     sync.RWMutex
	cachettl    time.Duration
}

func NewForestDiscovery(conn *connection.Manager) *ForestDiscovery {
	return &ForestDiscovery{
		connManager: conn,
		cache:       make(map[string]*ForestInfo),
		cachemu:     sync.RWMutex{},
		cachettl:    30 * time.Minute,
	}
}

func (fd *ForestDiscovery) DiscoverForest(username, password, dm string) (*ForestInfo, error) {
	cacheKey := fmt.Sprintf("%s-%s", username, dm)
	if docs := fd.getCache(cacheKey); docs != nil {
		fmt.Println("Found forest information in cache")
		return docs, nil
	}

	domainComponent := extractDomainComponent(dm)
	if domainComponent == "" {
		return nil, fmt.Errorf("invalid configuration DN format")
	}

	forestInfo := &ForestInfo{
		ExtraAttributes: make(map[string][]string),
	}

	if err := fd.discoverRootDomain(username, password, dm, forestInfo); err != nil {
		return nil, err
	}

	if err := fd.discoverForestConfig(username, password, dm, forestInfo); err != nil {
		fmt.Println("unable to discover forest configuration")
	}

	if err := fd.discoverGlobalCatalog(username, password, dm, forestInfo); err != nil {
		fmt.Println("unable to discover global catalog")
	}

	if err := fd.discoverSites(username, password, dm, forestInfo); err != nil {
		fmt.Println("unable to discover new sites for forest")
	}

	if err := fd.discoverSchemaVersion(username, password, dm, forestInfo); err != nil {
		fmt.Println("unable to discover schema version for forest")
	}

	fd.setCache(cacheKey, forestInfo)
	return forestInfo, nil
}

func (fd *ForestDiscovery) discoverRootDomain(
	bindUser, bindPwd, configDN string,
	forestInfo *ForestInfo,
) error {
	// forest search request
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{
			"rootDomainNamingContext",
			"configurationNamingContext",
			"forestFunctionalLevel",
			"domainFunctionality",
			"dsServiceName",
			"dnsHostName",
		}, nil,
	)

	searchResp, err := fd.connManager.Search(bindUser, bindPwd, searchReq)
	if err != nil {
		fmt.Println("Error while getting forest discovery search")
		return err
	}

	if len(searchResp.Entries) == 0 {
		return fmt.Errorf("forest search request failed, no entry found")
	}

	entry := searchResp.Entries[0]

	rootDomainNC := entry.GetAttributeValue("rootDomainNamingContext")
	if rootDomainNC != "" {
		forestInfo.RootDomain = extractDomainNameFromDN(rootDomainNC)
		forestInfo.Name = forestInfo.RootDomain
	}

	forestInfo.ForestFunctionLevel = mapFunctionalLevel(entry.GetAttributeValue("forestFunctionalLevel"))
	dnsHostName := entry.GetAttributeValue("dnsHostName")

	if dnsHostName != "" {
		parts := strings.Split(dnsHostName, ".")
		if len(parts) > 1 {
			forestInfo.Name = strings.Join(parts[1:], ".")
		}
	}

	return nil
}

func (fd *ForestDiscovery) discoverForestConfig(
	username, password, configDN string, forestInfo *ForestInfo,
) error {
	baseSearch := fmt.Sprintf("CN=Partitions,%s", configDN)
	searchReq := ldap.NewSearchRequest(
		baseSearch,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"fSMORoleOwner", "whencreated", "netbiosname", "uPSchemaNcName", "masteredBy"},
		nil,
	)

	searchResp, err := fd.connManager.Search(username, password, searchReq)
	if err != nil {
		return err
	}

	if len(searchResp.Entries) == 0 {
		return fmt.Errorf("no entries found for given searchRequest")
	}

	entry := searchResp.Entries[0]
	fsmoRoleOwner := entry.GetAttributeValue("fSMORoleOwner")
	if fsmoRoleOwner != "" {
		forestInfo.DomainNamingMaster = extractCNFromDN(fsmoRoleOwner)
	}

	whenCreated := entry.GetAttributeValue("whencreated")
	if whenCreated != "" {
		t, err := time.Parse("20060102150405.0Z", whenCreated)
		if err == nil {
			forestInfo.CreationTime = t
		}
	}

	schemaNC := entry.GetAttributeValue("uPSchemaNcName")
	if schemaNC != "" {
		schemaReq := ldap.NewSearchRequest(
			schemaNC,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"fSMORoleOwner"},
			nil,
		)

		schemaResp, err := fd.connManager.Search(username, password, schemaReq)
		if err == nil && len(schemaResp.Entries) > 0 {
			schemaMaster := schemaResp.Entries[0].GetAttributeValue("fSMORoleOwner")
			if schemaMaster != "" {
				forestInfo.SchemaMaster = extractCNFromDN(schemaMaster)
			}
		}
	}

	return nil
}

func (fd *ForestDiscovery) discoverGlobalCatalog(
	username, password, configDN string, forestInfo *ForestInfo,
) error {
	baseSearch := fmt.Sprintf("CN=Sites,%s", configDN)
	catalogRequest := ldap.NewSearchRequest(
		baseSearch,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=nTDSDSA)(options:1.2.840.113556.1.4.803:=1))",
		[]string{"distinguishedName", "dNSHostName"},
		nil,
	)

	catalogResp, err := fd.connManager.Search(username, password, catalogRequest)
	if err != nil {
		return err
	}

	for _, ent := range catalogResp.Entries {
		hostname := ent.GetAttributeValue("dNSHostName")
		if hostname != "" {
			forestInfo.GlobalCatalogs = append(forestInfo.GlobalCatalogs, hostname)
		}
	}

	return nil
}

func (fd *ForestDiscovery) discoverSites(
	username, password, configDN string,
	forestInfo *ForestInfo,
) error {
	searchDN := fmt.Sprintf("CN=Sites,%s", configDN)
	searchReq := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=site)",
		[]string{"cn", "distinguishedName"},
		nil,
	)

	resp, err := fd.connManager.Search(username, password, searchReq)
	if err != nil {
		return err
	}

	for _, ent := range resp.Entries {
		val := ent.GetAttributeValue("cn")
		if val != "" {
			forestInfo.Sites = append(forestInfo.Sites, val)
		}
	}

	fmt.Printf("Total discovered site in forest: %d \n", len(forestInfo.Sites))
	return nil
}

func (fd *ForestDiscovery) discoverSchemaVersion(
	username, password, configDN string,
	forestInfo *ForestInfo,
) error {
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"schemaNamingContext"},
		nil,
	)

	resp, err := fd.connManager.Search(username, password, searchReq)
	if err != nil {
		return err
	}

	schemaCTX := resp.Entries[0].GetAttributeValue("schemaNamingContext")
	if schemaCTX == "" {
		return fmt.Errorf("schemaNamingContext is empty, so discarding schema version detection")
	}

	versionReq := ldap.NewSearchRequest(
		schemaCTX,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectVersion"},
		nil,
	)

	versionResp, err := fd.connManager.Search(username, password, versionReq)
	if err != nil {
		return err
	}

	objVersion := versionResp.Entries[0].GetAttributeValue("objectVersion")
	forestInfo.SchemaVersion = objVersion

	fmt.Printf("Schema version: %s \n", objVersion)
	return nil
}

func (fd *ForestDiscovery) GetDomain(username, password, configDN string) (int, error) {
	baseSearch := fmt.Sprintf("CN=Partitions,%s", configDN)
	searchReq := ldap.NewSearchRequest(
		baseSearch,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=crossRef)",
		[]string{"nCName"},
		nil,
	)

	resp, err := fd.connManager.Search(username, password, searchReq)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, ent := range resp.Entries {
		val := ent.GetAttributeValue("nCName")
		if strings.Contains(val, "DC=") {
			count++
		}
	}
	return count, nil
}

func (fd *ForestDiscovery) ClearCache() {
	fd.cachemu.Lock()
	defer fd.cachemu.Unlock()

	fd.cache = make(map[string]*ForestInfo)
	fmt.Println("Forest-discovery cache has been cleaned")
}

func (fd *ForestDiscovery) getCache(k string) *ForestInfo {
	fd.cachemu.RLock()
	defer fd.cachemu.Unlock()

	v, ok := fd.cache[k]
	if !ok {
		return nil
	}
	return v
}

func (fd *ForestDiscovery) setCache(k string, v *ForestInfo) {
	fd.cachemu.Lock()
	defer fd.cachemu.Unlock()

	fd.cache[k] = v
}

func extractDomainComponent(v string) string {
	parts := strings.Split(v, ",")
	var domainParts []string

	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			domainParts = append(domainParts, part)
		}
	}
	return strings.Join(domainParts, ",")
}

func extractDomainNameFromDN(v string) string {
	if len(v) < 1 {
		return v
	}

	parts := strings.Split(v, ",")
	var domainParts []string

	for _, part := range parts {
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			val := strings.TrimPrefix(part, "DC=")
			val = strings.TrimPrefix(val, "dc=")
			domainParts = append(domainParts, val)
		}
	}
	return strings.Join(domainParts, ".")
}

func extractCNFromDN(v string) string {
	if strings.HasPrefix(strings.ToUpper(v), "CN=") {
		parts := strings.Split(v, ",")
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "CN=")
		}
	}
	return v
}

func mapFunctionalLevel(v string) string {
	win := "Windows"
	switch v {
	case "0":
		return fmt.Sprintf("%s 2000", win)
	case "1":
		return fmt.Sprintf("%s 2003 (Mixed/Interim)", win)
	case "2":
		return fmt.Sprintf("%s 2003", win)
	case "3":
		return fmt.Sprintf("%s 2008", win)
	case "4":
		return fmt.Sprintf("%s 2008 R2", win)
	case "5":
		return fmt.Sprintf("%s 2012", win)
	case "6":
		return fmt.Sprintf("%s 2012 R2", win)
	case "7":
		return fmt.Sprintf("%s 2016", win)
	case "8":
		return fmt.Sprintf("%s 2019/22", win)
	default:
		return fmt.Sprintf("Unknown functional level: [%s]", v)
	}
}
