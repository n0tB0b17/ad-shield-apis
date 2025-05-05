package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type ClientAnalysisResult struct {
	TotalClients      int             `json:"total_clients"`
	NewestClient      *ADClient       `json:"newest_client"`
	OldestClient      *ADClient       `json:"oldest_client"`
	RecentlyUpdated   []ADClient      `json:"recently_updated"`
	OrganizationTypes []TypeCount     `json:"organization_types"`
	MostCommonHQ      []LocationCount `json:"most_common_headquarters"`
	AdminEmailDomains []DomainCount   `json:"admin_email_domains"`
	CommonColors      struct {
		PrimaryColors   []ColorCount `json:"primary_colors"`
		SecondaryColors []ColorCount `json:"secondary_colors"`
	} `json:"common_colors"`
	ClientsByCreationMonth []MonthlyCount `json:"clients_by_creation_month"`
	ClientsByCreationYear  []YearlyCount  `json:"clients_by_creation_year"`
	GrowthRate             float64        `json:"growth_rate"`
}

type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type LocationCount struct {
	Location string `json:"location"`
	Count    int    `json:"count"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type ColorCount struct {
	Color string `json:"color"`
	Count int    `json:"count"`
}

type MonthlyCount struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

type YearlyCount struct {
	Year  string `json:"year"`
	Count int    `json:"count"`
}

type ADClient struct {
	ID                bson.ObjectID `bson:"_id,omit" json:"id"`
	ClientName        string        `bson:"client_name" json:"client_name"`
	Description       string        `bson:"description" json:"description"`
	OrganizationType  string        `bson:"organization_type" json:"organization_type"`
	Headquarter       string        `bson:"headquarter" json:"headquarter"`
	AdminName         string        `bson:"admin_name" json:"admin_name"`
	AdminEmail        string        `bson:"admin_email" json:"admin_email"`
	Password          string        `bson:"password" json:"password"`
	ContactNumber     uint64        `bson:"contact_number" json:"contact_number"`
	PrimaryColorHex   string        `bson:"primary_color" json:"primary_color"`
	SecondaryColorHex string        `bson:"secondary_color" json:"secondary_color"`
	CreatedAt         time.Time     `bson:"created_at,omit" json:"created_at,omitempty"`
	UpdatedAt         time.Time     `bson:"updated_at,omit" json:"updated_at,omitempty"`
}

type ClientStore struct {
	c      *mongo.Collection
	logger logger.Logger
}

func NewClientStore(client *mongo.Client, dbname string, logger logger.Logger) *ClientStore {
	c := client.Database(dbname).Collection("clients")
	idxModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "client_name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := c.Indexes().CreateOne(ctx, idxModel)
	if err != nil {
		logger.Debug(fmt.Sprintf("error while creating new client index: %v \n", err))
		fmt.Printf("error while creating client index: %v \n", err)
		return nil
	}

	return &ClientStore{
		c:      c,
		logger: logger,
	}
}

func (cs *ClientStore) AddNewClient(ctx context.Context, client ADClient) error {
	if client.ID.IsZero() {
		client.ID = bson.NewObjectID()
	}

	resp, err := cs.c.InsertOne(ctx, client)

	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("client already exist, no need to create new client")
	}
	if err != nil {
		cs.logger.Error(fmt.Sprintf("error while adding client: %s to collection \n", client.ClientName))
		fmt.Printf("error while adding new client: %v \n", err)
		return err
	}

	if !resp.Acknowledged {
		cs.logger.Warn(fmt.Sprintf("acknowledgment false while adding client: %s \n", client.ClientName))
		return fmt.Errorf("user not added, false acknowledgement")
	}

	return nil
}

func (cs *ClientStore) GetClientByID(ctx context.Context, id bson.ObjectID) (*ADClient, error) {
	var client ADClient
	if err := cs.c.FindOne(ctx, bson.M{"_id": id}).Decode(&client); err != nil {
		if err == mongo.ErrNoDocuments {
			cs.logger.Info(fmt.Sprintf("invalid id provided to search for client: %s \n", id.String()))
			return nil, nil
		}

		return nil, err
	}

	return &client, nil
}

func (cs *ClientStore) GetAllClients(ctx context.Context, limit, skip int64) ([]ADClient, error) {
	var adClients []ADClient
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := cs.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &adClients); err != nil {
		cs.logger.Info("unable to decode all clients from cursor")
		return nil, err
	}

	return adClients, nil
}

func (cs *ClientStore) DeleteClient(ctx context.Context, id bson.ObjectID) error {
	resp, err := cs.c.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		cs.logger.Debug(fmt.Sprintf("unable to delete client of id: %s | err:> %v \n", id.String(), err))
		return err
	}

	if resp.DeletedCount == 0 {
		cs.logger.Debug("client not deleted, deletion failed")
		return fmt.Errorf("client not deleted, deletion failed")
	}

	return nil
}

func (cs *ClientStore) GenerateAnalysis(ctx context.Context) (*ClientAnalysisResult, error) {
	// Get all clients
	clients, err := cs.GetAllClients(ctx, 0, 0)
	if err != nil {
		cs.logger.Error("failed to get clients for analysis: " + err.Error())
		return nil, fmt.Errorf("failed to get clients: %v", err)
	}

	if len(clients) == 0 {
		return &ClientAnalysisResult{}, nil
	}

	result := &ClientAnalysisResult{
		TotalClients:      len(clients),
		RecentlyUpdated:   make([]ADClient, 0),
		OrganizationTypes: make([]TypeCount, 0),
		MostCommonHQ:      make([]LocationCount, 0),
		AdminEmailDomains: make([]DomainCount, 0),
	}

	// Initialize color counts
	result.CommonColors.PrimaryColors = make([]ColorCount, 0)
	result.CommonColors.SecondaryColors = make([]ColorCount, 0)

	// Data structures for tracking statistics
	orgTypeCounts := make(map[string]int)
	hqCounts := make(map[string]int)
	domainCounts := make(map[string]int)
	primaryColorCounts := make(map[string]int)
	secondaryColorCounts := make(map[string]int)
	monthlyCounts := make(map[string]int)
	yearlyCounts := make(map[string]int)

	// Track newest/oldest clients
	var newestClient, oldestClient *ADClient
	var recentlyUpdated []ADClient

	for i, client := range clients {
		// Track newest/oldest clients
		if oldestClient == nil || client.CreatedAt.Before(oldestClient.CreatedAt) {
			oldestClient = &clients[i]
		}
		if newestClient == nil || client.CreatedAt.After(newestClient.CreatedAt) {
			newestClient = &clients[i]
		}

		// Track recently updated (last 5)
		if len(recentlyUpdated) < 5 {
			recentlyUpdated = append(recentlyUpdated, client)
		} else {
			// Replace the oldest if this one is newer
			for j, ru := range recentlyUpdated {
				if client.UpdatedAt.After(ru.UpdatedAt) {
					recentlyUpdated[j] = client
					break
				}
			}
		}

		// Organization statistics
		orgTypeCounts[client.OrganizationType]++
		hqCounts[client.Headquarter]++

		// Admin email domain analysis
		emailParts := strings.Split(client.AdminEmail, "@")
		if len(emailParts) > 1 {
			domain := strings.ToLower(emailParts[1])
			domainCounts[domain]++
		}

		// Color analysis
		primaryColorCounts[strings.ToLower(client.PrimaryColorHex)]++
		secondaryColorCounts[strings.ToLower(client.SecondaryColorHex)]++

		// Temporal analysis
		monthYear := client.CreatedAt.Format("2006-01")
		monthlyCounts[monthYear]++
		year := client.CreatedAt.Format("2006")
		yearlyCounts[year]++
	}

	// Set newest/oldest clients
	result.NewestClient = newestClient
	result.OldestClient = oldestClient

	// Sort and set recently updated clients
	sort.Slice(recentlyUpdated, func(i, j int) bool {
		return recentlyUpdated[i].UpdatedAt.After(recentlyUpdated[j].UpdatedAt)
	})
	result.RecentlyUpdated = recentlyUpdated

	// Process organization types
	for orgType, count := range orgTypeCounts {
		result.OrganizationTypes = append(result.OrganizationTypes, TypeCount{
			Type:  orgType,
			Count: count,
		})
	}
	sort.Slice(result.OrganizationTypes, func(i, j int) bool {
		return result.OrganizationTypes[i].Count > result.OrganizationTypes[j].Count
	})

	// Process headquarters
	for hq, count := range hqCounts {
		result.MostCommonHQ = append(result.MostCommonHQ, LocationCount{
			Location: hq,
			Count:    count,
		})
	}
	sort.Slice(result.MostCommonHQ, func(i, j int) bool {
		return result.MostCommonHQ[i].Count > result.MostCommonHQ[j].Count
	})
	if len(result.MostCommonHQ) > 5 {
		result.MostCommonHQ = result.MostCommonHQ[:5]
	}

	// Process email domains
	for domain, count := range domainCounts {
		result.AdminEmailDomains = append(result.AdminEmailDomains, DomainCount{
			Domain: domain,
			Count:  count,
		})
	}
	sort.Slice(result.AdminEmailDomains, func(i, j int) bool {
		return result.AdminEmailDomains[i].Count > result.AdminEmailDomains[j].Count
	})
	if len(result.AdminEmailDomains) > 5 {
		result.AdminEmailDomains = result.AdminEmailDomains[:5]
	}

	// Process colors
	for color, count := range primaryColorCounts {
		result.CommonColors.PrimaryColors = append(result.CommonColors.PrimaryColors, ColorCount{
			Color: color,
			Count: count,
		})
	}
	sort.Slice(result.CommonColors.PrimaryColors, func(i, j int) bool {
		return result.CommonColors.PrimaryColors[i].Count > result.CommonColors.PrimaryColors[j].Count
	})
	if len(result.CommonColors.PrimaryColors) > 5 {
		result.CommonColors.PrimaryColors = result.CommonColors.PrimaryColors[:5]
	}

	for color, count := range secondaryColorCounts {
		result.CommonColors.SecondaryColors = append(result.CommonColors.SecondaryColors, ColorCount{
			Color: color,
			Count: count,
		})
	}
	sort.Slice(result.CommonColors.SecondaryColors, func(i, j int) bool {
		return result.CommonColors.SecondaryColors[i].Count > result.CommonColors.SecondaryColors[j].Count
	})
	if len(result.CommonColors.SecondaryColors) > 5 {
		result.CommonColors.SecondaryColors = result.CommonColors.SecondaryColors[:5]
	}

	// Process monthly counts
	for monthYear, count := range monthlyCounts {
		result.ClientsByCreationMonth = append(result.ClientsByCreationMonth, MonthlyCount{
			Month: monthYear,
			Count: count,
		})
	}
	sort.Slice(result.ClientsByCreationMonth, func(i, j int) bool {
		return result.ClientsByCreationMonth[i].Month < result.ClientsByCreationMonth[j].Month
	})

	// Process yearly counts
	for year, count := range yearlyCounts {
		result.ClientsByCreationYear = append(result.ClientsByCreationYear, YearlyCount{
			Year:  year,
			Count: count,
		})
	}
	sort.Slice(result.ClientsByCreationYear, func(i, j int) bool {
		return result.ClientsByCreationYear[i].Year < result.ClientsByCreationYear[j].Year
	})

	// Calculate growth rate if we have enough data
	if len(result.ClientsByCreationYear) >= 2 {
		latestYear := result.ClientsByCreationYear[len(result.ClientsByCreationYear)-1]
		previousYear := result.ClientsByCreationYear[len(result.ClientsByCreationYear)-2]
		if previousYear.Count > 0 {
			result.GrowthRate = (float64(latestYear.Count) - float64(previousYear.Count)) / float64(previousYear.Count) * 100
		}
	}

	return result, nil
}
