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
