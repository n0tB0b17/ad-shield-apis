package db

import (
	"context"
	"fmt"
	"time"

	"github.com/bob17/adpis/internal/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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
