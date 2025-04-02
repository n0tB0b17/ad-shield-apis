package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Users struct {
	ID            string    `bson:"_id" json:"id"`
	UserName      string    `bson:"user_name" json:"user_name"`
	FirstName     string    `bson:"first_name" json:"first_name"`
	LastName      string    `bson:"last_name" json:"last_name"`
	Email         string    `bson:"email" json:"email"`
	Password      string    `bson:"password" json:"password"`
	ContactNumber int64     `bson:"contact_number" json:"contact_number"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time `bson:"updated_at" json:"updated_at"`
}

type UserStore struct {
	collection *mongo.Collection
}

func NewUserStore(client *mongo.Client, dbName string) *UserStore {
	col := client.Database(dbName).Collection("users")
	idxModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_name", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, idxModel)
	if err != nil {
		fmt.Printf("error while creating user model: %v \n", err)
	}

	return &UserStore{
		collection: col,
	}
}
