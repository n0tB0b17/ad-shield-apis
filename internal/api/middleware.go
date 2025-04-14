package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

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
