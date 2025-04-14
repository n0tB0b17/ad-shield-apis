package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/models"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleClientAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method POST to create new client",
			"status":      "failed",
		})

		return
	}

	var adClient models.ReqClientAdd
	if err := json.NewDecoder(r.Body).Decode(&adClient); err != nil {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "invalid body",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	newClient := db.ADClient{
		ID:                bson.NewObjectID(),
		ClientName:        adClient.ClientName,
		Description:       adClient.Description,
		OrganizationType:  adClient.OrganizationType,
		Headquarter:       adClient.HeadQuarter,
		AdminName:         adClient.AdminUserName,
		AdminEmail:        adClient.AdminEmail,
		Password:          adClient.AdminPassword,
		ContactNumber:     adClient.ContactNumber,
		PrimaryColorHex:   adClient.PrimaryColorHex,
		SecondaryColorHex: adClient.SecondaryColorHex,
		CreatedAt:         time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.clientStore.AddNewClient(ctx, newClient); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": "check server logs for more information",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	// create database for client with clientName
	dbName := fmt.Sprintf("%s_adshield", strings.TrimSpace(newClient.ClientName))
	roleStore := db.NewRoleStore(a.mongoClient, dbName)
	roleCtx, roleCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer roleCancel()
	role := db.Roles{
		ID:          bson.NewObjectID(),
		Name:        "admin",
		Description: "this role was created when client purchase ad-shield service",
		Permissions: []string{"all"},
		CreatedAt:   time.Now(),
	}

	if err := roleStore.AddRoles(roleCtx, role); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error while creating role",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	userStore := db.NewUserStore(a.mongoClient, dbName)
	userCtx, userCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer userCancel()

	// register new user with admin role
	if err := userStore.AddUserToDB(userCtx, db.Users{
		ID:            bson.NewObjectID(),
		RoleID:        role.ID,
		UserName:      newClient.AdminName,
		Password:      newClient.Password,
		Email:         newClient.AdminEmail,
		ContactNumber: newClient.ContactNumber,
		FirstName:     "", // can update later
		LastName:      "", // can update later
		CreatedAt:     time.Now(),
	}); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error while creating user",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "client created",
		"description": "given information for client has been saved",
		"status":      "success",
		"docs":        newClient,
	})
}

func (a *APIServer) handleGetAllClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to access all clients",
			"status":      "failed",
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	limit := int64(10)
	skip := int64(0)
	clients, err := a.clientStore.GetAllClients(ctx, limit, skip)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	if len(clients) == 0 {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "client not found",
			"description": "you broke, you're project has no client, LOL",
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("Total: %d client fetched", len(clients)),
		"description": "successfully fetched all clients",
		"status":      "success",
		"docs":        clients,
	})
}

func (a *APIServer) handleGetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET and pass client id to get a single client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

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

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetch client: %s", client.ClientName),
		"description": "successfully fetched client with provided query ID",
		"status":      "success",
		"docs":        client,
	})

}
func (a *APIServer) handleDeleteClient(w http.ResponseWriter, r *http.Request) {}
func (a *APIServer) handleUpdateClient(w http.ResponseWriter, r *http.Request) {}
