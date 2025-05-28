package models

import "go.mongodb.org/mongo-driver/v2/bson"

type RequestReportGenerate struct {
	UserId      bson.ObjectID `json:"user_id"`
	ContentType string        `json:"content_type"`
	ContentId   bson.ObjectID `json:"content_id"`
	FileName    string        `json:"file_name"`
}
