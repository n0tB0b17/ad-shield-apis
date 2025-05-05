package db

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type GeoInfo struct {
	Country      string  `json:"country" bson:"country"`
	CountryCode  string  `json:"country_code" bson:"country_code"`
	Region       string  `json:"region" bson:"region"`
	City         string  `json:"city" bson:"city"`
	Zip          string  `json:"zip" bson:"zip"`
	Latitude     float64 `json:"latitude" bson:"latitude"`
	Longitude    float64 `json:"longitude" bson:"longitude"`
	Timezone     string  `json:"timezone" bson:"timezone"`
	ISP          string  `json:"isp" bson:"isp"`
	Organization string  `json:"organization" bson:"organization"`
	ASN          string  `json:"asn" bson:"asn"`
}

type LookupResult struct {
	ID        bson.ObjectID `json:"id" bson:"_id,omit"`
	Target    string        `json:"target" bson:"target"`
	IP        string        `json:"ip" bson:"ip"`
	GeoInfo   *GeoInfo      `json:"geo_info" bson:"geo_info"`
	Hostnames []string      `json:"hostnames" bson:"hostnames"`
	CreatedAt time.Time     `json:"created_at" bson:"created_at"`
	CreatedBy bson.ObjectID `json:"created_by" bson:"createdy_by"`
}

type LookupStore struct {
	col    *mongo.Collection
	logger logger.Logger
}

func NewLookupStore(c *mongo.Client, dbName string, logger logger.Logger) *LookupStore {
	col := c.Database(dbName).Collection("ip_lookup")
	return &LookupStore{
		col:    col,
		logger: logger,
	}
}

func (il *LookupStore) AddNewIPLookUpData(ctx context.Context, docs LookupResult) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	if docs.CreatedBy.IsZero() {
		return fmt.Errorf("user id is invalid")
	}

	resp, err := il.col.InsertOne(ctx, docs)
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("document already exist in collection ip_lookup")
	}

	if err != nil {
		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to insert as database returned acknowledgement of false")
	}

	return nil
}

func (il *LookupStore) GetAllIPLookupHistory(ctx context.Context, limit, skip int64) ([]LookupResult, error) {
	var lookupResp []LookupResult
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := il.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &lookupResp); err != nil {
		return nil, nil
	}

	return lookupResp, nil
}

func (il *LookupStore) GetAIPLookupByID(ctx context.Context, id bson.ObjectID) (*LookupResult, error) {
	var docs LookupResult
	if err := il.col.FindOne(ctx, bson.M{"_id": id}).Decode(&docs); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &docs, nil
}

func (il *LookupStore) DeleteIPLookup(ctx context.Context, id bson.ObjectID) error {
	resp, err := il.col.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}

	if resp.DeletedCount == 0 {
		return fmt.Errorf("unable to delete document with provided ID")
	}

	return nil
}

type LookupAnalysisResult struct {
	TotalLookups  int64          `json:"total_lookups"`
	UniqueTargets int            `json:"unique_targets"`
	UniqueIPs     int            `json:"unique_ips"`
	RecentLookups []LookupResult `json:"recent_lookups"`

	Countries     []CountryCount `json:"countries"`
	Cities        []CityCount    `json:"cities"`
	ISPs          []ISPCount     `json:"isps"`
	Organizations []OrgCount     `json:"organizations"`
	ASNs          []ASNCount     `json:"asns"`

	LookupsByHour  []HourlyCount  `json:"lookups_by_hour"`
	LookupsByDay   []DailyCount   `json:"lookups_by_day"`
	LookupsByMonth []MonthlyCount `json:"lookups_by_month"`

	CommonHostnames   []HostnameCount `json:"common_hostnames"`
	AvgHostnamesPerIP float64         `json:"avg_hostnames_per_ip"`
}

type CountryCount struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Count       int    `json:"count"`
}

type CityCount struct {
	City    string `json:"city"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type ISPCount struct {
	ISP   string `json:"isp"`
	Count int    `json:"count"`
}

type OrgCount struct {
	Organization string `json:"organization"`
	Count        int    `json:"count"`
}

type ASNCount struct {
	ASN   string `json:"asn"`
	Count int    `json:"count"`
}

type HourlyCount struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type DailyCount struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type HostnameCount struct {
	Hostname string `json:"hostname"`
	Count    int    `json:"count"`
}

func (il *LookupStore) GenerateAnalysis(ctx context.Context) (*LookupAnalysisResult, error) {
	// Get all lookup results
	lookups, err := il.GetAllIPLookupHistory(ctx, 0, 0)
	if err != nil {
		il.logger.Error("failed to get lookup results for analysis: " + err.Error())
		return nil, fmt.Errorf("failed to get lookup results: %v", err)
	}

	if len(lookups) == 0 {
		return &LookupAnalysisResult{}, nil
	}

	result := &LookupAnalysisResult{
		TotalLookups:    int64(len(lookups)),
		RecentLookups:   make([]LookupResult, 0),
		Countries:       make([]CountryCount, 0),
		Cities:          make([]CityCount, 0),
		ISPs:            make([]ISPCount, 0),
		Organizations:   make([]OrgCount, 0),
		ASNs:            make([]ASNCount, 0),
		LookupsByHour:   make([]HourlyCount, 24),
		LookupsByDay:    make([]DailyCount, 0),
		LookupsByMonth:  make([]MonthlyCount, 0),
		CommonHostnames: make([]HostnameCount, 0),
	}

	// Initialize hourly counts
	for i := 0; i < 24; i++ {
		result.LookupsByHour[i] = HourlyCount{Hour: i, Count: 0}
	}

	daysOfWeek := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	for _, day := range daysOfWeek {
		result.LookupsByDay = append(result.LookupsByDay, DailyCount{Day: day, Count: 0})
	}

	uniqueTargets := make(map[string]bool)
	uniqueIPs := make(map[string]bool)
	countryCounts := make(map[string]map[string]int)
	cityCounts := make(map[string]map[string]int)
	ispCounts := make(map[string]int)
	orgCounts := make(map[string]int)
	asnCounts := make(map[string]int)
	hostnameCounts := make(map[string]int)
	totalHostnames := 0

	for _, lookup := range lookups {
		// Track unique targets and IPs
		uniqueTargets[lookup.Target] = true
		uniqueIPs[lookup.IP] = true

		// Track recent lookups (last 10)
		if len(result.RecentLookups) < 10 {
			result.RecentLookups = append(result.RecentLookups, lookup)
		} else {
			// Replace the oldest if this one is newer
			for i, rl := range result.RecentLookups {
				if lookup.CreatedAt.After(rl.CreatedAt) {
					result.RecentLookups[i] = lookup
					break
				}
			}
		}

		// Track temporal patterns
		hour := lookup.CreatedAt.Hour()
		result.LookupsByHour[hour].Count++
		day := lookup.CreatedAt.Weekday().String()
		for i, d := range result.LookupsByDay {
			if d.Day == day {
				result.LookupsByDay[i].Count++
				break
			}
		}

		// Track monthly lookups
		monthYear := lookup.CreatedAt.Format("2006-01")
		found := false
		for i, m := range result.LookupsByMonth {
			if m.Month == monthYear {
				result.LookupsByMonth[i].Count++
				found = true
				break
			}
		}
		if !found {
			result.LookupsByMonth = append(result.LookupsByMonth, MonthlyCount{
				Month: monthYear,
				Count: 1,
			})
		}

		// Process geographic information if available
		if lookup.GeoInfo != nil {
			geo := lookup.GeoInfo

			// Track countries
			if geo.CountryCode != "" && geo.Country != "" {
				if _, exists := countryCounts[geo.CountryCode]; !exists {
					countryCounts[geo.CountryCode] = make(map[string]int)
				}
				countryCounts[geo.CountryCode][geo.Country]++
			}

			// Track cities
			if geo.City != "" && geo.Country != "" {
				if _, exists := cityCounts[geo.Country]; !exists {
					cityCounts[geo.Country] = make(map[string]int)
				}
				cityCounts[geo.Country][geo.City]++
			}

			// Track ISPs
			if geo.ISP != "" {
				ispCounts[geo.ISP]++
			}

			// Track organizations
			if geo.Organization != "" {
				orgCounts[geo.Organization]++
			}

			// Track ASNs
			if geo.ASN != "" {
				asnCounts[geo.ASN]++
			}
		}

		// Process hostnames
		for _, hostname := range lookup.Hostnames {
			hostnameCounts[hostname]++
			totalHostnames++
		}
	}

	// Set general statistics
	result.UniqueTargets = len(uniqueTargets)
	result.UniqueIPs = len(uniqueIPs)

	// Process countries
	for countryCode, countries := range countryCounts {
		for country, count := range countries {
			result.Countries = append(result.Countries, CountryCount{
				Country:     country,
				CountryCode: countryCode,
				Count:       count,
			})
		}
	}
	sort.Slice(result.Countries, func(i, j int) bool {
		return result.Countries[i].Count > result.Countries[j].Count
	})
	if len(result.Countries) > 10 {
		result.Countries = result.Countries[:10]
	}

	// Process cities
	for country, cities := range cityCounts {
		for city, count := range cities {
			result.Cities = append(result.Cities, CityCount{
				City:    city,
				Country: country,
				Count:   count,
			})
		}
	}
	sort.Slice(result.Cities, func(i, j int) bool {
		return result.Cities[i].Count > result.Cities[j].Count
	})
	if len(result.Cities) > 10 {
		result.Cities = result.Cities[:10]
	}

	// Process ISPs
	for isp, count := range ispCounts {
		result.ISPs = append(result.ISPs, ISPCount{
			ISP:   isp,
			Count: count,
		})
	}
	sort.Slice(result.ISPs, func(i, j int) bool {
		return result.ISPs[i].Count > result.ISPs[j].Count
	})
	if len(result.ISPs) > 10 {
		result.ISPs = result.ISPs[:10]
	}

	// Process organizations
	for org, count := range orgCounts {
		result.Organizations = append(result.Organizations, OrgCount{
			Organization: org,
			Count:        count,
		})
	}
	sort.Slice(result.Organizations, func(i, j int) bool {
		return result.Organizations[i].Count > result.Organizations[j].Count
	})
	if len(result.Organizations) > 10 {
		result.Organizations = result.Organizations[:10]
	}

	// Process ASNs
	for asn, count := range asnCounts {
		result.ASNs = append(result.ASNs, ASNCount{
			ASN:   asn,
			Count: count,
		})
	}
	sort.Slice(result.ASNs, func(i, j int) bool {
		return result.ASNs[i].Count > result.ASNs[j].Count
	})
	if len(result.ASNs) > 10 {
		result.ASNs = result.ASNs[:10]
	}

	// Process hostnames
	for hostname, count := range hostnameCounts {
		result.CommonHostnames = append(result.CommonHostnames, HostnameCount{
			Hostname: hostname,
			Count:    count,
		})
	}
	sort.Slice(result.CommonHostnames, func(i, j int) bool {
		return result.CommonHostnames[i].Count > result.CommonHostnames[j].Count
	})
	if len(result.CommonHostnames) > 10 {
		result.CommonHostnames = result.CommonHostnames[:10]
	}

	// Calculate average hostnames per IP
	if len(uniqueIPs) > 0 {
		result.AvgHostnamesPerIP = float64(totalHostnames) / float64(len(uniqueIPs))
	}

	// Sort monthly lookups
	sort.Slice(result.LookupsByMonth, func(i, j int) bool {
		return result.LookupsByMonth[i].Month < result.LookupsByMonth[j].Month
	})

	// Sort recent lookups by time (newest first)
	sort.Slice(result.RecentLookups, func(i, j int) bool {
		return result.RecentLookups[i].CreatedAt.After(result.RecentLookups[j].CreatedAt)
	})

	return result, nil
}
