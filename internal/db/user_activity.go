package db

import (
	"context"
	"fmt"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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
	userIDX := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	timeIDX := mongo.IndexModel{
		Keys:    bson.D{{Key: "timestamp", Value: -1}},
		Options: options.Index().SetUnique(true),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateMany(ctx, []mongo.IndexModel{userIDX, timeIDX})
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
