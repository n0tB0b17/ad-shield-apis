package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type ServiceResult struct {
	Addr    string `bson:"address" json:"address"`
	Port    int    `bson:"port" json:"port"`
	Status  string `bson:"status" json:"status"`
	Service string `bson:"service" json:"service"`
	Version string `bson:"version" json:"version"`
}

type PortScanHistory struct {
	ID                 bson.ObjectID   `bson:"_id,omit" json:"_id"`
	UserID             bson.ObjectID   `bson:"user_id,omit" json:"user_id"`
	TargetAddress      string          `bson:"target_address" json:"target_address"`
	RequestedPortRange string          `bson:"requested_port_range" json:"requested_port_range"`
	ScanStartTime      time.Time       `bson:"scan_start_time" json:"scan_start_time"`
	ScanEndTime        time.Time       `bson:"scan_end_time" json:"scan_end_time"`
	ScanDuration       time.Duration   `bson:"scan_duration" json:"scan_duration"`
	Status             string          `bson:"status" json:"status"`
	ScanDetail         []ServiceResult `bson:"scan_result_detail" json:"scan_result_detail"`
	CreatedAt          time.Time       `bson:"created_at" json:"created_at"`
}

type ServiceStore struct {
	c *mongo.Collection
}

func NewServiceStore(client *mongo.Client, dbname string) *ServiceStore {
	col := client.Database(dbname).Collection("port_scan")

	return &ServiceStore{
		c: col,
	}
}

func (s *ServiceStore) GetAllServiceDetectedHistory(ctx context.Context, limit, skip int64) ([]PortScanHistory, error) {
	var resp []PortScanHistory
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := s.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *ServiceStore) AddDetectedService(ctx context.Context, docs PortScanHistory) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	resp, err := s.c.InsertOne(ctx, docs)
	if err != nil {
		fmt.Println("error while adding service to db")
		fmt.Println(err.Error())
		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to add service detection data for address: %s", docs.TargetAddress)
	}

	return nil
}

func (s *ServiceStore) GetDetectedServiceByID(ctx context.Context, id bson.ObjectID) (*PortScanHistory, error) {
	var serviceHistory PortScanHistory
	if err := s.c.FindOne(ctx, bson.M{"_id": id}).Decode(&serviceHistory); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}
	return &serviceHistory, nil
}
