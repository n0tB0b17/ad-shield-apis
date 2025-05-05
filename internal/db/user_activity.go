package db

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type ActivityCount struct {
	Key   string `bson:"_id" json:"key"`
	Count int    `bson:"count" json:"count"`
}

type TimePoint struct {
	Date  string `bson:"_id" json:"date"` // YYYY-MM-DD
	Count int    `bson:"count" json:"count"`
}

type HourlyActivity struct {
	Hour  int `bson:"_id" json:"hour"` // 0-23
	Count int `bson:"count" json:"count"`
}

type DayOfWeekActivity struct {
	DayOfWeek int `bson:"_id" json:"day_of_week"` //  1 = Sunday, 7 = Saturday
	Count     int `bson:"count" json:"count"`
}

type IPActivityCount struct {
	IPAddress string `bson:"_id" json:"ip_address"`
	Count     int    `bson:"count" json:"count"`
}

type UserAgentActivityCount struct {
	UserAgent string `bson:"_id" json:"user_agent"`
	Count     int    `bson:"count" json:"count"`
}

type UserActivityStats struct {
	UserID                  bson.ObjectID            `json:"user_id"`
	StartDate               time.Time                `json:"start_date"`
	EndDate                 time.Time                `json:"end_date"`
	TotalActivityCount      int64                    `json:"total_activity_count"`
	FirstActivityTimestamp  *time.Time               `json:"first_activity_timestamp,omitempty"`
	LastActivityTimestamp   *time.Time               `json:"last_activity_timestamp,omitempty"`
	ActionDistribution      []ActivityCount          `json:"action_distribution"`
	UniqueActionCount       int                      `json:"unique_action_count"`
	ActivityTimeline        []TimePoint              `json:"activity_timeline"`
	HourlyDistribution      []HourlyActivity         `json:"hourly_distribution"`
	DayOfWeekDistribution   []DayOfWeekActivity      `json:"day_of_week_distribution"`
	UniqueIPAddressCount    int                      `json:"unique_ip_address_count"`
	UniqueIPAddresses       []string                 `json:"unique_ip_addresses"`
	IPAddressDistribution   []IPActivityCount        `json:"ip_address_distribution"`
	UniqueUserAgentCount    int                      `json:"unique_user_agent_count"`
	UniqueUserAgents        []string                 `json:"unique_user_agents"`
	UserAgentDistribution   []UserAgentActivityCount `json:"user_agent_distribution"`
	AverageActivitiesPerDay float64                  `json:"average_activities_per_day"`
}

type UserActivity struct {
	ID        bson.ObjectID `bson:"_id,omit" json:"id"`
	UserID    bson.ObjectID `bson:"user_id" json:"user_id"`
	Action    string        `bson:"action" json:"action"`
	Timestamp time.Time     `bson:"timestamp" json:"timestamp"`
	IPAddress string        `bson:"ip_address" json:"ip_address"`
	UserAgent string        `bson:"user_agent" json:"user_agent"`
}

type UserActivityStore struct {
	c      *mongo.Collection
	logger logger.Logger
}

func NewUserActivityStore(c *mongo.Client, dbname string, logger logger.Logger) *UserActivityStore {
	col := c.Database(dbname).Collection("user_activity")
	userTimeIDX := mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "timestamp", Value: -1}, {Key: "action", Value: 1}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, userTimeIDX)
	if err != nil {
		logger.Warn("unable to create index for userActivity collection")
		return nil
	}

	return &UserActivityStore{
		c:      col,
		logger: logger,
	}
}

func (uas *UserActivityStore) RecordActivity(ctx context.Context, activity UserActivity) error {
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}

	if activity.ID.IsZero() {
		activity.ID = bson.NewObjectID()
	}

	resp, err := uas.c.InsertOne(ctx, activity)
	if err != nil {
		uas.logger.Error(fmt.Sprintf("error while adding new activity record: %v", activity))
		return err
	}

	if !resp.Acknowledged {
		uas.logger.Debug(fmt.Sprintf("activity not added, acknowledgement false: %v", activity))
	}

	return nil
}

func (uas *UserActivityStore) GetUserActivity(
	ctx context.Context,
	id bson.ObjectID,
	startDate, endDate time.Time,
) ([]UserActivity, error) {
	filter := bson.M{
		"user_id": id,
		"timestamp": bson.M{
			"$gte": startDate, "$lte": endDate,
		},
	}

	opts := options.Find().SetSort(bson.M{"timestamp": -1})
	cursor, err := uas.c.Find(ctx, filter, opts)
	if err != nil {
		fmt.Printf("error while searching for user-activity: %v \n", err)
		uas.logger.Debug(fmt.Sprintf("error while searching for user activity: %v", err))
		return nil, err
	}

	defer cursor.Close(ctx)
	var activity []UserActivity
	if err := cursor.All(ctx, &activity); err != nil {
		fmt.Printf("error while passing value for user-activity: %v \n", err)
		uas.logger.Debug(fmt.Sprintf("error while decoding user activity data to array: %v", err))
		return nil, err
	}

	return activity, nil
}

func (uas *UserActivityStore) GetUserActivityStats(
	ctx context.Context,
	userID bson.ObjectID,
	startDate, endDate time.Time,
) (*UserActivityStats, error) {

	matchStage := bson.D{
		{Key: "$match", Value: bson.M{
			"user_id": userID,
			"timestamp": bson.M{
				"$gte": startDate,
				"$lte": endDate,
			},
		}},
	}

	facetStage := bson.D{
		{Key: "$facet", Value: bson.M{
			"totalCount": []bson.D{
				{{Key: "$count", Value: "count"}},
			},
			"timeBounds": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":             nil,
					"firstActivityTS": bson.M{"$min": "$timestamp"},
					"lastActivityTS":  bson.M{"$max": "$timestamp"},
				}}},
			},
			"actionDistribution": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":   "$action",
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"count": -1}}},
			},
			"uniqueActions": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":     nil,
					"actions": bson.M{"$addToSet": "$action"},
				}}},
			},
			"activityTimeline": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":   bson.M{"$dateToString": bson.M{"format": "%Y-%m-%d", "date": "$timestamp", "timezone": "UTC"}},
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"_id": 1}}},
			},
			"hourlyDistribution": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":   bson.M{"$hour": bson.M{"date": "$timestamp", "timezone": "UTC"}},
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"_id": 1}}},
			},
			"dayOfWeekDistribution": []bson.D{
				{{Key: "$group", Value: bson.M{
					// Note: 1=Sun, 7=Sat
					"_id":   bson.M{"$dayOfWeek": bson.M{"date": "$timestamp", "timezone": "UTC"}},
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"_id": 1}}},
			},
			"uniqueIPs": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id": nil,
					"ips": bson.M{"$addToSet": "$ip_address"},
				}}},
			},
			"ipDistribution": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":   "$ip_address",
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"count": -1}}},
			},
			"uniqueUserAgents": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":    nil,
					"agents": bson.M{"$addToSet": "$user_agent"},
				}}},
			},
			"userAgentDistribution": []bson.D{
				{{Key: "$group", Value: bson.M{
					"_id":   "$user_agent",
					"count": bson.M{"$sum": 1},
				}}},
				{{Key: "$sort", Value: bson.M{"count": -1}}},
			},
		}},
	}

	type facetResult struct {
		TotalCount []struct {
			Count int64 `bson:"count"`
		} `bson:"totalCount"`
		TimeBounds []struct {
			First time.Time `bson:"firstActivityTS"`
			Last  time.Time `bson:"lastActivityTS"`
		} `bson:"timeBounds"`
		ActionDistribution []ActivityCount `bson:"actionDistribution"`
		UniqueActions      []struct {
			Actions []string `bson:"actions"`
		} `bson:"uniqueActions"`
		ActivityTimeline      []TimePoint         `bson:"activityTimeline"`
		HourlyDistribution    []HourlyActivity    `bson:"hourlyDistribution"`
		DayOfWeekDistribution []DayOfWeekActivity `bson:"dayOfWeekDistribution"`
		UniqueIPs             []struct {
			IPs []string `bson:"ips"`
		} `bson:"uniqueIPs"`
		IPDistribution   []IPActivityCount `bson:"ipDistribution"`
		UniqueUserAgents []struct {
			Agents []string `bson:"agents"`
		} `bson:"uniqueUserAgents"`
		UserAgentDistribution []UserAgentActivityCount `bson:"userAgentDistribution"`
	}

	pipeline := mongo.Pipeline{matchStage, facetStage}
	cursor, err := uas.c.Aggregate(ctx, pipeline)
	if err != nil {
		uas.logger.Error(fmt.Sprintf("aggregation failed for user %s: %v", userID.Hex(), err))
		return nil, fmt.Errorf("aggregation failed: %w", err)
	}
	defer cursor.Close(ctx)

	var rawResults []facetResult
	if err = cursor.All(ctx, &rawResults); err != nil {
		uas.logger.Error(fmt.Sprintf("decoding aggregation result failed for user %s: %v", userID.Hex(), err))
		return nil, fmt.Errorf("decoding failed: %w", err)
	}

	stats := &UserActivityStats{
		UserID:                  userID,
		StartDate:               startDate,
		EndDate:                 endDate,
		TotalActivityCount:      0,
		ActionDistribution:      []ActivityCount{},
		UniqueActionCount:       0,
		ActivityTimeline:        []TimePoint{},
		HourlyDistribution:      []HourlyActivity{},
		DayOfWeekDistribution:   []DayOfWeekActivity{},
		UniqueIPAddressCount:    0,
		UniqueIPAddresses:       []string{},
		IPAddressDistribution:   []IPActivityCount{},
		UniqueUserAgentCount:    0,
		UniqueUserAgents:        []string{},
		UserAgentDistribution:   []UserAgentActivityCount{},
		AverageActivitiesPerDay: 0.0,
	}

	if len(rawResults) == 0 {
		return stats, nil
	}

	result := rawResults[0]

	if len(result.TotalCount) > 0 {
		stats.TotalActivityCount = result.TotalCount[0].Count
	}
	if len(result.TimeBounds) > 0 {
		first := result.TimeBounds[0].First
		last := result.TimeBounds[0].Last
		stats.FirstActivityTimestamp = &first
		stats.LastActivityTimestamp = &last
	}

	stats.ActionDistribution = result.ActionDistribution
	if len(result.UniqueActions) > 0 {
		stats.UniqueActionCount = len(result.UniqueActions[0].Actions)
	}

	stats.ActivityTimeline = result.ActivityTimeline
	stats.HourlyDistribution = result.HourlyDistribution
	stats.DayOfWeekDistribution = result.DayOfWeekDistribution

	if len(result.UniqueIPs) > 0 {
		stats.UniqueIPAddresses = result.UniqueIPs[0].IPs
		stats.UniqueIPAddressCount = len(stats.UniqueIPAddresses)
	}
	stats.IPAddressDistribution = result.IPDistribution

	if len(result.UniqueUserAgents) > 0 {
		stats.UniqueUserAgents = result.UniqueUserAgents[0].Agents
		stats.UniqueUserAgentCount = len(stats.UniqueUserAgents)
	}
	stats.UserAgentDistribution = result.UserAgentDistribution

	numberOfActiveDays := len(stats.ActivityTimeline)
	if numberOfActiveDays > 0 && stats.TotalActivityCount > 0 {
		stats.AverageActivitiesPerDay = math.Round((float64(stats.TotalActivityCount)/float64(numberOfActiveDays))*100) / 100 // Round to 2 decimal places
	} else {
		stats.AverageActivitiesPerDay = 0.0
	}

	if stats.ActionDistribution == nil {
		stats.ActionDistribution = []ActivityCount{}
	}
	if stats.ActivityTimeline == nil {
		stats.ActivityTimeline = []TimePoint{}
	}
	if stats.HourlyDistribution == nil {
		stats.HourlyDistribution = []HourlyActivity{}
	}
	if stats.DayOfWeekDistribution == nil {
		stats.DayOfWeekDistribution = []DayOfWeekActivity{}
	}
	if stats.UniqueIPAddresses == nil {
		stats.UniqueIPAddresses = []string{}
	}
	if stats.IPAddressDistribution == nil {
		stats.IPAddressDistribution = []IPActivityCount{}
	}
	if stats.UniqueUserAgents == nil {
		stats.UniqueUserAgents = []string{}
	}
	if stats.UserAgentDistribution == nil {
		stats.UserAgentDistribution = []UserAgentActivityCount{}
	}

	return stats, nil
}
