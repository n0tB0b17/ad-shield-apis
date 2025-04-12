package discovery

import (
	"fmt"
	"strings"
	"sync"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/go-ldap/ldap/v3"
)

type Domain struct {
	Name              string
	NetBIOSName       string
	DistinguishedName string
	DomainController  []string
	ForestName        string
	IsForestRoot      bool
	FunctionalLevel   string
	TrustedDomain     []string
	Metadata          map[string]interface{}
}

type DomainDiscovery struct {
	conn  *connection.Manager
	cache map[string]*Domain
	mu    sync.RWMutex
}

func NewDomainDiscovery(conn *connection.Manager) *DomainDiscovery {
	return &DomainDiscovery{
		conn:  conn,
		cache: make(map[string]*Domain),
	}
}

func (dd *DomainDiscovery) GetDomain(username, password, dn string) (*Domain, error) {
	cached := dd.getCache(dn)
	if cached != nil {
		fmt.Println("Domain found in cache")
		return cached, nil
	}

	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=domain)(distinguishedName="+ldap.EscapeFilter(dn)+"))",
		[]string{
			"name",
			"distinguishedName",
			"objectGUID",
			"msDS-Behavior-Version",
			"ms-DS-MachineAccountQuota",
			"netBIOSName",
		},
		nil,
	)

	resp, err := dd.conn.Search(username, password, searchReq)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("search query returned 0 entries")
	}

	entry := resp.Entries[0]
	domain := &Domain{
		Name:              entry.GetAttributeValue("name"),
		DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		NetBIOSName:       entry.GetAttributeValue("netBIOSName"),
		DomainController:  []string{},
		ForestName:        "",
		IsForestRoot:      false,
		FunctionalLevel:   mapFunctionalLevel(entry.GetAttributeValue("msDS-Behavior-Version")),
		TrustedDomain:     []string{},
		Metadata:          make(map[string]interface{}),
	}

	if quota := entry.GetAttributeValue("ms-DS-MachineAccountQuota"); quota != "" {
		domain.Metadata["machineAccountQuota"] = quota
	}

	if err := dd.populateDomainControllers(username, password, domain); err != nil {
		fmt.Println("unable to populate domain controller for searched domain")
	}

	dd.setCache(dn, domain)
	return domain, nil
}

func (dd *DomainDiscovery) EnumerateDomain(username, password, forestRootDN string) ([]*Domain, error) {
	req := ldap.NewSearchRequest(
		"CN=Partitions,CN=Configuration,"+forestRootDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=crossRef)",
		[]string{"name", "dnsRoot", "nCName", "trustParent", "systemFlags"},
		nil,
	)

	resp, err := dd.conn.Search(username, password, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("got empty entries while searching enumerated domains")
	}

	var domains []*Domain
	var wg sync.WaitGroup
	domainsChan := make(chan *Domain, len(resp.Entries))
	errorsChan := make(chan error, len(resp.Entries))

	for _, ent := range resp.Entries {
		sysFlag := ent.GetAttributeValue("systemFlags")
		if sysFlag == "" {
			continue
		}

		// more on flags
		domainName := ent.GetAttributeValue("nCName")
		if domainName == "" {
			continue
		}

		wg.Add(1)
		go func(dn string) {
			defer wg.Done()
			domain, err := dd.GetDomain(username, password, domainName)
			if err != nil {
				errorsChan <- err
				return
			}

			if forestRootDN == dn {
				domain.IsForestRoot = true
				domain.ForestName = domain.Name
			} else {
				// if forest is not root, get the name of root domain name
				forestRoot, err := dd.GetDomain(username, password, forestRootDN)
				if err == nil {
					domain.ForestName = forestRoot.Name
				}
			}

			domainsChan <- domain
		}(domainName)
	}

	wg.Wait()
	close(domainsChan)
	close(errorsChan)

	for errr := range errorsChan {
		fmt.Printf("EnumerateDomain's err:> %v", errr)
	}

	for domain := range domainsChan {
		domains = append(domains, domain)
	}

	return domains, nil
}

func (dd *DomainDiscovery) GetTrustedDomain(username, password, dn string) ([]string, error) {
	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"name", "flatName", "trustPartner", "trustDirection", "trustType"},
		nil,
	)

	resp, err := dd.conn.Search(username, password, searchReq)
	if err != nil {
		return nil, err
	}

	if len(resp.Entries) > 0 {
		return nil, fmt.Errorf("resp length is zero")
	}

	var trustedDomain []string
	for _, ent := range resp.Entries {
		trustDN := ent.GetAttributeValue("trustPartner")
		if trustDN != "" {
			trustedDomain = append(trustedDomain, trustDN)
		}
	}

	return trustedDomain, nil
}

// take domain name (xxx.com) as argument and get basic information from it.
func (dd *DomainDiscovery) GetDomainInfo(username, password, domainName string) (*Domain, error) {
	if domainName == "" {
		return nil, fmt.Errorf("empty domain name")
	}

	parts := strings.Split(domainName, ".")
	var dc []string
	for _, part := range parts {
		dc = append(dc, fmt.Sprintf("DC=%s", part))
	}

	dn := strings.Join(dc, ",")

	domain, err := dd.GetDomain(username, password, dn)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var trustedDomainErr, forestErr error

	// get trusted information
	wg.Add(1)
	go func() {
		defer wg.Done()
		trusted, err := dd.GetTrustedDomain(username, password, dn)
		if err != nil {
			trustedDomainErr = err
			return
		}

		domain.TrustedDomain = trusted
	}()

	// get forest information
	wg.Add(1)
	go func() {
		defer wg.Done()

		searchReq := ldap.NewSearchRequest(
			"CN=Partitions,CN=Configuration,"+dn,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"forestFunctionality", "fSMORoleOwner"},
			nil,
		)

		searchResp, err := dd.conn.Search(username, password, searchReq)
		if err != nil {
			forestErr = err
			return
		}

		if len(searchResp.Entries) > 1 {
			entry := searchResp.Entries[0]
			if level := entry.GetAttributeValue("forestFunctionality"); level != "" {
				domain.Metadata["forestFunctionalityLevel"] = mapFunctionalLevel(level)
			}

			if fmRole := entry.GetAttributeValue("fSMORoleOwner"); fmRole != "" {
				// If this domain owns the Schema Master FSMO role, it's the forest root
				domain.IsForestRoot = strings.Contains(fmRole, dn)
				if domain.IsForestRoot {
					domain.ForestName = domain.Name
				}
			}
		}
	}()

	wg.Wait()
	if trustedDomainErr != nil {
		fmt.Println("unable to fetch trustedDomain information while getting domain information")
	}

	if forestErr != nil {
		fmt.Println("unable to fetch forest information while getting domain information")
	}

	fmt.Printf("successfully fetched domain information")

	return domain, nil
}

func (dd *DomainDiscovery) populateDomainControllers(username, password string, domain *Domain) error {
	searchReq := ldap.NewSearchRequest(
		domain.DistinguishedName,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"name", "dNSHostName", "distinguishedName"},
		nil,
	)

	resp, err := dd.conn.Search(username, password, searchReq)
	if err != nil {
		return err
	}

	if len(resp.Entries) == 0 {
		return fmt.Errorf("entries is zero")
	}

	for _, ent := range resp.Entries {
		dnsHost := ent.GetAttributeValue("dNSHostName")
		if dnsHost != "" {
			domain.DomainController = append(domain.DomainController, dnsHost)
		}
	}

	return nil
}

func (dd *DomainDiscovery) ClearCache() {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	dd.cache = make(map[string]*Domain)
	fmt.Println("Domain cache cleared")
}

func (dd *DomainDiscovery) setCache(k string, v *Domain) {
	dd.mu.Lock()
	defer dd.mu.Unlock()

	dd.cache[k] = v
}

func (dd *DomainDiscovery) getCache(k string) *Domain {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	exist, ok := dd.cache[k]
	if !ok {
		return nil
	}

	return exist
}
