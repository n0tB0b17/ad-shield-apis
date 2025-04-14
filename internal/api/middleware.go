package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) InitializeStores(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.dbName != "" {
			fmt.Printf("Current DBName is: %s \n\n", a.dbName)
			a.userStore = db.NewUserStore(a.mongoClient, a.dbName)
			a.roleStore = db.NewRoleStore(a.mongoClient, a.dbName)
			a.serviceDetectionStore = db.NewServiceStore(a.mongoClient, a.dbName)
			a.pcapStore = db.NewPCAPStore(a.mongoClient, a.dbName)
		}

		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) ValidateIfRealClientID(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["client_id"]

		clientID, err := bson.ObjectIDFromHex(id)
		if err != nil {
			responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"message":     "invalid id",
				"description": "please provide valid objectID to fetch client",
				"status":      "failed",
				"error":       err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := a.clientStore.GetClientByID(ctx, clientID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "internal error",
				"description": err.Error(),
				"status":      "failed",
			})
			return
		}

		if client == nil {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "client not found",
				"description": "client doesn't exist for given query ID",
				"status":      "failed",
			})

			return
		}

		a.dbName = fmt.Sprintf("%s_adshield", client.ClientName)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) Logger(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Debug(fmt.Sprintf("Go request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path))
		log.Printf("Got request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path)
		nxt.ServeHTTP(w, r)
	})
}
