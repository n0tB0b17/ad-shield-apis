package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type PCAPMetaData struct {
	ID               bson.ObjectID `bson:"_id,omit" json:"id"`
	OriginalFileName string        `bson:"original_file_name" json:"original_file_name"`
	StoredFileName   string        `bson:"stored_file_name" json:"stored_file_name"`
	StoragePath      string        `bson:"storage_path" json:"storage_path"`
	FileSizeBytes    int64         `bson:"file_size_bytes" json:"file_size_bytes"`
	FileHash         string        `bson:"file_hash" json:"file_hash"`
	ContentType      string        `bson:"content_type" json:"content_type"`
	UploadedBy       bson.ObjectID `bson:"uploaded_by" json:"uploaded_by"`
	UploadedAt       time.Time     `bson:"uploaded_at" json:"uploaded_at"`
	LastAnalyzedTime *time.Time    `bson:"last_analyzed_time, omit"`
}

type PCAPStore struct {
	c *mongo.Collection
}

func NewPCAPStore(client *mongo.Client, dbname string) *PCAPStore {
	dbClient := client.Database(dbname).Collection("pcap_metadata")

	idxModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "stored_file_name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := dbClient.Indexes().CreateOne(ctx, idxModel)
	if err != nil {
		fmt.Printf("error while creating new index: %v", err)
		return nil
	}

	return &PCAPStore{
		c: dbClient,
	}
}

func (ps *PCAPStore) AddNewPCAP(ctx context.Context, docs PCAPMetaData) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	resp, err := ps.c.InsertOne(ctx, docs)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("file already exist")
		}

		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to add to database, server acknowledged with false")
	}

	return nil
}

func (ps *PCAPStore) GetAllPCAP(ctx context.Context, limit, skip int64) ([]PCAPMetaData, error) {
	var docs []PCAPMetaData
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := ps.c.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}

	return docs, nil
}

func (ps *PCAPStore) GetPCAPByID(ctx context.Context, id bson.ObjectID) (*PCAPMetaData, error) {
	var meta PCAPMetaData
	if err := ps.c.FindOne(ctx, bson.M{"_id": id}).Decode(&meta); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &meta, nil
}
