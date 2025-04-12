package models

import "go.mongodb.org/mongo-driver/v2/bson"

type ReqPortScan struct {
	PortRange string        `json:"port_range"`
	Address   string        `json:"address"`
	UserID    bson.ObjectID `json:"user_id"`
}
