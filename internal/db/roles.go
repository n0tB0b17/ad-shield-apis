package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type RoleAnalysisResult struct {
	TotalRoles      int     `json:"total_roles"`
	NewestRole      *Roles  `json:"newest_role"`
	OldestRole      *Roles  `json:"oldest_role"`
	RecentlyUpdated []Roles `json:"recently_updated"`
	PermissionUsage struct {
		MostCommonPermissions []PermissionCount `json:"most_common_permissions"`
		AvgPermissionsPerRole float64           `json:"avg_permissions_per_role"`
		MaxPermissionsInRole  int               `json:"max_permissions_in_role"`
	} `json:"permission_usage"`
	RolesByCreationMonth []MonthlyCount `json:"roles_by_creation_month"`
	RolesByUpdateMonth   []MonthlyCount `json:"roles_by_update_month"`
	RoleNamePatterns     []PatternCount `json:"role_name_patterns"`
}

type PermissionCount struct {
	Permission string `json:"permission"`
	Count      int    `json:"count"`
}

type Roles struct {
	ID          bson.ObjectID `bson:"_id,omit" json:"_id"`
	Name        string        `bson:"name" json:"name"`
	Description string        `bson:"description" json:"description"`
	Permissions []string      `bson:"permissions" json:"permissions"`
	CreatedAt   time.Time     `bson:"created_at,omit" json:"created_at"`
	UpdatedAt   time.Time     `bson:"updated_at,omit" json:"updated_at"`
}

type RoleStore struct {
	c *mongo.Collection
}

func NewRoleStore(client *mongo.Client, dbname string) *RoleStore {
	col := client.Database(dbname).Collection("roles")
	nameIDX := mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, nameIDX)
	if err != nil {
		fmt.Printf("error while creating new index for db: %s | err: %v \n", dbname, err.Error())
		return nil
	}

	return &RoleStore{
		c: col,
	}
}

func (ra *RoleStore) GetAllRoles(ctx context.Context, limit, skip int64) ([]Roles, error) {
	var roles []Roles
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := ra.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

func (ra *RoleStore) AddRoles(ctx context.Context, role Roles) error {
	if role.ID.IsZero() {
		role.ID = bson.NewObjectID()
	}

	resp, err := ra.c.InsertOne(ctx, role)
	if err != nil {
		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to insert role to database")
	}

	return nil
}

func (ra *RoleStore) GetARoleWithID(ctx context.Context, id bson.ObjectID) (*Roles, error) {
	var role Roles
	if err := ra.c.FindOne(ctx, bson.M{"_id": id}).Decode(&role); err != nil {

		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &role, nil
}

func (ra *RoleStore) DeleteRoleWithID(ctx context.Context, id bson.ObjectID) error {
	resp, err := ra.c.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}

	if resp.DeletedCount == 0 {
		return fmt.Errorf("deletedCount is zero, unable to delete role")
	}
	return nil
}

func (rs *RoleStore) GenerateAnalysis(ctx context.Context) (*RoleAnalysisResult, error) {
	// Get all roles
	roles, err := rs.GetAllRoles(ctx, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %v", err)
	}

	if len(roles) == 0 {
		return &RoleAnalysisResult{}, nil
	}

	result := &RoleAnalysisResult{
		TotalRoles:           len(roles),
		RecentlyUpdated:      make([]Roles, 0),
		RolesByCreationMonth: make([]MonthlyCount, 0),
		RolesByUpdateMonth:   make([]MonthlyCount, 0),
		RoleNamePatterns:     make([]PatternCount, 0),
	}

	// Initialize permission usage
	result.PermissionUsage.MostCommonPermissions = make([]PermissionCount, 0)
	result.PermissionUsage.MaxPermissionsInRole = 0
	totalPermissions := 0

	// Data structures for tracking statistics
	permissionCounts := make(map[string]int)
	namePatternCounts := make(map[string]int)
	creationMonthCounts := make(map[string]int)
	updateMonthCounts := make(map[string]int)
	var newestRole, oldestRole *Roles
	var recentlyUpdated []Roles

	for i, role := range roles {
		// Track newest/oldest roles
		if oldestRole == nil || role.CreatedAt.Before(oldestRole.CreatedAt) {
			oldestRole = &roles[i]
		}
		if newestRole == nil || role.CreatedAt.After(newestRole.CreatedAt) {
			newestRole = &roles[i]
		}

		// Track recently updated (last 5)
		if len(recentlyUpdated) < 5 {
			recentlyUpdated = append(recentlyUpdated, role)
		} else {
			// Replace the oldest if this one is newer
			for j, ru := range recentlyUpdated {
				if role.UpdatedAt.After(ru.UpdatedAt) {
					recentlyUpdated[j] = role
					break
				}
			}
		}

		// Track permissions
		permissionCount := len(role.Permissions)
		if permissionCount > result.PermissionUsage.MaxPermissionsInRole {
			result.PermissionUsage.MaxPermissionsInRole = permissionCount
		}
		totalPermissions += permissionCount

		for _, permission := range role.Permissions {
			permissionCounts[permission]++
		}

		// Track role name patterns (first 3 characters)
		if len(role.Name) >= 3 {
			pattern := strings.ToLower(role.Name[:3])
			namePatternCounts[pattern]++
		}

		// Track creation months
		creationMonth := role.CreatedAt.Format("2006-01")
		creationMonthCounts[creationMonth]++

		// Track update months
		updateMonth := role.UpdatedAt.Format("2006-01")
		updateMonthCounts[updateMonth]++
	}

	// Set general statistics
	result.NewestRole = newestRole
	result.OldestRole = oldestRole

	// Sort and set recently updated roles
	sort.Slice(recentlyUpdated, func(i, j int) bool {
		return recentlyUpdated[i].UpdatedAt.After(recentlyUpdated[j].UpdatedAt)
	})
	result.RecentlyUpdated = recentlyUpdated

	// Process permissions
	for permission, count := range permissionCounts {
		result.PermissionUsage.MostCommonPermissions = append(result.PermissionUsage.MostCommonPermissions, PermissionCount{
			Permission: permission,
			Count:      count,
		})
	}
	sort.Slice(result.PermissionUsage.MostCommonPermissions, func(i, j int) bool {
		return result.PermissionUsage.MostCommonPermissions[i].Count > result.PermissionUsage.MostCommonPermissions[j].Count
	})
	if len(result.PermissionUsage.MostCommonPermissions) > 10 {
		result.PermissionUsage.MostCommonPermissions = result.PermissionUsage.MostCommonPermissions[:10]
	}

	// Calculate average permissions per role
	result.PermissionUsage.AvgPermissionsPerRole = float64(totalPermissions) / float64(len(roles))

	// Process role name patterns
	for pattern, count := range namePatternCounts {
		result.RoleNamePatterns = append(result.RoleNamePatterns, PatternCount{
			Pattern: pattern,
			Count:   count,
		})
	}
	sort.Slice(result.RoleNamePatterns, func(i, j int) bool {
		return result.RoleNamePatterns[i].Count > result.RoleNamePatterns[j].Count
	})
	if len(result.RoleNamePatterns) > 5 {
		result.RoleNamePatterns = result.RoleNamePatterns[:5]
	}

	// Process creation months
	for month, count := range creationMonthCounts {
		result.RolesByCreationMonth = append(result.RolesByCreationMonth, MonthlyCount{
			Month: month,
			Count: count,
		})
	}
	sort.Slice(result.RolesByCreationMonth, func(i, j int) bool {
		return result.RolesByCreationMonth[i].Month < result.RolesByCreationMonth[j].Month
	})

	// Process update months
	for month, count := range updateMonthCounts {
		result.RolesByUpdateMonth = append(result.RolesByUpdateMonth, MonthlyCount{
			Month: month,
			Count: count,
		})
	}
	sort.Slice(result.RolesByUpdateMonth, func(i, j int) bool {
		return result.RolesByUpdateMonth[i].Month < result.RolesByUpdateMonth[j].Month
	})

	return result, nil
}
