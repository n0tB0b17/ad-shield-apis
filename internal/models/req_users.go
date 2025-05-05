package models

import "go.mongodb.org/mongo-driver/v2/bson"

type ReqUserRegistration struct {
	UserName      string        `json:"user_name"`
	FirstName     string        `json:"first_name"`
	LastName      string        `json:"last_name"`
	Email         string        `json:"email"`
	RoleID        bson.ObjectID `json:"role_id"`
	ContactNumber uint64        `json:"contact_number,omitempty"`
	Password      string        `json:"password"`
}

type ReqUserLogin struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
}
