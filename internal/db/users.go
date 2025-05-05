package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type UserAnalysisResult struct {
	TotalUsers          int     `json:"total_users"`
	NewestUser          *Users  `json:"newest_user"`
	OldestUser          *Users  `json:"oldest_user"`
	RecentlyActiveUsers []Users `json:"recently_active_users"`

	NamePatterns struct {
		CommonFirstNames []NameCount    `json:"common_first_names"`
		CommonLastNames  []NameCount    `json:"common_last_names"`
		UserNamePatterns []PatternCount `json:"username_patterns"`
	} `json:"name_patterns"`

	EmailDomains []DomainCount `json:"email_domains"`

	SignupsByHour  []HourlyCount  `json:"signups_by_hour"`
	SignupsByDay   []DailyCount   `json:"signups_by_day"`
	SignupsByMonth []MonthlyCount `json:"signups_by_month"`
	GrowthRate     float64        `json:"growth_rate"`

	RoleDistribution []RoleCount `json:"role_distribution"`
}

// Supporting structs for analysis results
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type PatternCount struct {
	Pattern string `json:"pattern"`
	Count   int    `json:"count"`
}

type RoleCount struct {
	RoleID bson.ObjectID `json:"role_id"`
	Count  int           `json:"count"`
}

type Users struct {
	ID            bson.ObjectID `bson:"_id,omit" json:"id"`
	UserName      string        `bson:"user_name" json:"user_name"`
	FirstName     string        `bson:"first_name" json:"first_name"`
	LastName      string        `bson:"last_name" json:"last_name"`
	Email         string        `bson:"email" json:"email"`
	Password      string        `bson:"password" json:"password"`
	ContactNumber uint64        `bson:"contact_number" json:"contact_number"`
	RoleID        bson.ObjectID `bson:"role_id" json:"role_id"`
	CreatedAt     time.Time     `bson:"created_at,omit" json:"created_at"`
	UpdatedAt     time.Time     `bson:"updated_at,omit" json:"updated_at"`
}

type UserStore struct {
	c *mongo.Collection
}

func NewUserStore(client *mongo.Client, dbName string) *UserStore {
	col := client.Database(dbName).Collection("users")
	usernameModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, usernameModel)
	if err != nil {
		fmt.Printf("error while creating user model: %v \n", err)
		return nil
	}

	return &UserStore{
		c: col,
	}
}

func (us *UserStore) AddUserToDB(ctx context.Context, user Users) error {
	if user.ID.IsZero() {
		user.ID = bson.NewObjectID()
	}

	resp, err := us.c.InsertOne(ctx, user)

	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("user already exist, try with unique username")
	}

	if err != nil {
		return err
	}
	if !resp.Acknowledged {
		return fmt.Errorf("unable to add user, acknowlege: %t", resp.Acknowledged)
	}

	return nil
}

func (us *UserStore) GetAllUsersFromDB(ctx context.Context, limit, skip int64) ([]Users, error) {
	var users []Users
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := us.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

func (us *UserStore) LoginUser(ctx context.Context, user models.ReqUserLogin) (*Users, error) {
	var u Users

	if err := us.c.FindOne(ctx, bson.M{"user_name": user.UserName, "password": user.Password}).Decode(&u); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &u, nil
}

func (us *UserStore) GetUserByID(ctx context.Context, id bson.ObjectID) (*Users, error) {
	var u Users

	if err := us.c.FindOne(ctx, bson.M{"_id": id}).Decode(&u); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &u, nil
}

func (us *UserStore) DeleteUser(ctx context.Context, id bson.ObjectID) error {
	resp, err := us.c.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		fmt.Println("error while deleting user")
		return err
	}

	if resp.DeletedCount == 0 {
		fmt.Println("unable to delete user, resp count is zero")
		return fmt.Errorf("user not deleted as server responed with deletedCount of zero")
	}

	return nil
}

func (us *UserStore) UpdateUser(ctx context.Context, id bson.ObjectID, u Users) error {
	u.UpdatedAt = time.Now()

	up := bson.M{
		"$set": bson.M{
			"user_name":      u.UserName,
			"first_name":     u.FirstName,
			"last_name":      u.LastName,
			"email":          u.Email,
			"contact_number": u.ContactNumber,
			"role_id":        u.RoleID,
			"updated_at":     u.UpdatedAt,
		},
	}

	if u.Password != "" {
		up["$set"].(bson.M)["password"] = u.Password
	}

	resp, err := us.c.UpdateOne(ctx, bson.M{"_id": id}, up)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("update failed: username already exist")
		}

		return fmt.Errorf("error updating user: %v", err)
	}

	if resp.MatchedCount == 0 {
		return fmt.Errorf("no user found for id: %s", id.Hex())
	}

	return nil
}

func (us *UserStore) GenerateAnalysis(ctx context.Context) (*UserAnalysisResult, error) {
	// Get all users
	users, err := us.GetAllUsersFromDB(ctx, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %v", err)
	}

	if len(users) == 0 {
		return &UserAnalysisResult{}, nil
	}

	result := &UserAnalysisResult{
		TotalUsers:          len(users),
		RecentlyActiveUsers: make([]Users, 0),
		EmailDomains:        make([]DomainCount, 0),
		SignupsByHour:       make([]HourlyCount, 24),
		SignupsByDay:        make([]DailyCount, 0),
		SignupsByMonth:      make([]MonthlyCount, 0),
		RoleDistribution:    make([]RoleCount, 0),
	}

	// Initialize name patterns
	result.NamePatterns.CommonFirstNames = make([]NameCount, 0)
	result.NamePatterns.CommonLastNames = make([]NameCount, 0)
	result.NamePatterns.UserNamePatterns = make([]PatternCount, 0)

	// Initialize hourly counts
	for i := 0; i < 24; i++ {
		result.SignupsByHour[i] = HourlyCount{Hour: i, Count: 0}
	}

	// Initialize day of week counts
	daysOfWeek := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	for _, day := range daysOfWeek {
		result.SignupsByDay = append(result.SignupsByDay, DailyCount{Day: day, Count: 0})
	}

	// Data structures for tracking statistics
	firstNameCounts := make(map[string]int)
	lastNameCounts := make(map[string]int)
	userNamePatterns := make(map[string]int)
	domainCounts := make(map[string]int)
	roleCounts := make(map[bson.ObjectID]int)
	var newestUser, oldestUser *Users
	var recentlyActiveUsers []Users

	for i, user := range users {
		// Track newest/oldest users
		if oldestUser == nil || user.CreatedAt.Before(oldestUser.CreatedAt) {
			oldestUser = &users[i]
		}
		if newestUser == nil || user.CreatedAt.After(newestUser.CreatedAt) {
			newestUser = &users[i]
		}

		// Track recently active (based on UpdatedAt)
		if len(recentlyActiveUsers) < 5 {
			recentlyActiveUsers = append(recentlyActiveUsers, user)
		} else {
			// Replace the oldest if this one is newer
			for j, ru := range recentlyActiveUsers {
				if user.UpdatedAt.After(ru.UpdatedAt) {
					recentlyActiveUsers[j] = user
					break
				}
			}
		}

		// Track first names
		if user.FirstName != "" {
			firstNameCounts[user.FirstName]++
		}

		// Track last names
		if user.LastName != "" {
			lastNameCounts[user.LastName]++
		}

		// Track username patterns (first 3 chars)
		if len(user.UserName) >= 3 {
			pattern := user.UserName[:3]
			userNamePatterns[pattern]++
		}

		// Track email domains
		emailParts := strings.Split(user.Email, "@")
		if len(emailParts) > 1 {
			domain := strings.ToLower(emailParts[1])
			domainCounts[domain]++
		}

		// Track role distribution
		if !user.RoleID.IsZero() {
			roleCounts[user.RoleID]++
		}

		// Track temporal patterns
		hour := user.CreatedAt.Hour()
		result.SignupsByHour[hour].Count++
		day := user.CreatedAt.Weekday().String()
		for i, d := range result.SignupsByDay {
			if d.Day == day {
				result.SignupsByDay[i].Count++
				break
			}
		}

		// Track monthly signups
		monthYear := user.CreatedAt.Format("2006-01")
		found := false
		for i, m := range result.SignupsByMonth {
			if m.Month == monthYear {
				result.SignupsByMonth[i].Count++
				found = true
				break
			}
		}
		if !found {
			result.SignupsByMonth = append(result.SignupsByMonth, MonthlyCount{
				Month: monthYear,
				Count: 1,
			})
		}
	}

	// Set general statistics
	result.NewestUser = newestUser
	result.OldestUser = oldestUser

	// Sort and set recently active users
	sort.Slice(recentlyActiveUsers, func(i, j int) bool {
		return recentlyActiveUsers[i].UpdatedAt.After(recentlyActiveUsers[j].UpdatedAt)
	})
	result.RecentlyActiveUsers = recentlyActiveUsers

	// Process first names
	for name, count := range firstNameCounts {
		result.NamePatterns.CommonFirstNames = append(result.NamePatterns.CommonFirstNames, NameCount{
			Name:  name,
			Count: count,
		})
	}
	sort.Slice(result.NamePatterns.CommonFirstNames, func(i, j int) bool {
		return result.NamePatterns.CommonFirstNames[i].Count > result.NamePatterns.CommonFirstNames[j].Count
	})
	if len(result.NamePatterns.CommonFirstNames) > 5 {
		result.NamePatterns.CommonFirstNames = result.NamePatterns.CommonFirstNames[:5]
	}

	// Process last names
	for name, count := range lastNameCounts {
		result.NamePatterns.CommonLastNames = append(result.NamePatterns.CommonLastNames, NameCount{
			Name:  name,
			Count: count,
		})
	}
	sort.Slice(result.NamePatterns.CommonLastNames, func(i, j int) bool {
		return result.NamePatterns.CommonLastNames[i].Count > result.NamePatterns.CommonLastNames[j].Count
	})
	if len(result.NamePatterns.CommonLastNames) > 5 {
		result.NamePatterns.CommonLastNames = result.NamePatterns.CommonLastNames[:5]
	}

	// Process username patterns
	for pattern, count := range userNamePatterns {
		result.NamePatterns.UserNamePatterns = append(result.NamePatterns.UserNamePatterns, PatternCount{
			Pattern: pattern,
			Count:   count,
		})
	}
	sort.Slice(result.NamePatterns.UserNamePatterns, func(i, j int) bool {
		return result.NamePatterns.UserNamePatterns[i].Count > result.NamePatterns.UserNamePatterns[j].Count
	})
	if len(result.NamePatterns.UserNamePatterns) > 5 {
		result.NamePatterns.UserNamePatterns = result.NamePatterns.UserNamePatterns[:5]
	}

	// Process email domains
	for domain, count := range domainCounts {
		result.EmailDomains = append(result.EmailDomains, DomainCount{
			Domain: domain,
			Count:  count,
		})
	}
	sort.Slice(result.EmailDomains, func(i, j int) bool {
		return result.EmailDomains[i].Count > result.EmailDomains[j].Count
	})
	if len(result.EmailDomains) > 5 {
		result.EmailDomains = result.EmailDomains[:5]
	}

	// Process roles
	for roleID, count := range roleCounts {
		result.RoleDistribution = append(result.RoleDistribution, RoleCount{
			RoleID: roleID,
			Count:  count,
		})
	}
	sort.Slice(result.RoleDistribution, func(i, j int) bool {
		return result.RoleDistribution[i].Count > result.RoleDistribution[j].Count
	})

	// Sort monthly signups
	sort.Slice(result.SignupsByMonth, func(i, j int) bool {
		return result.SignupsByMonth[i].Month < result.SignupsByMonth[j].Month
	})

	// Calculate growth rate if we have enough data
	if len(result.SignupsByMonth) >= 2 {
		latestMonth := result.SignupsByMonth[len(result.SignupsByMonth)-1]
		previousMonth := result.SignupsByMonth[len(result.SignupsByMonth)-2]
		if previousMonth.Count > 0 {
			result.GrowthRate = (float64(latestMonth.Count) - float64(previousMonth.Count)) / float64(previousMonth.Count) * 100
		}
	}

	return result, nil
}
