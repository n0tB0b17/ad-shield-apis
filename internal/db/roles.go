package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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
