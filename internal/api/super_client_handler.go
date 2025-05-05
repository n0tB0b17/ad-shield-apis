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

	clientName := strings.ReplaceAll(adClient.ClientName, " ", "_")
	newClient := db.ADClient{
		ID:                bson.NewObjectID(),
		ClientName:        clientName,
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
		responseWithJSON(w, http.StatusOK, map[string]interface{}{
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

func (a *APIServer) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method provided, try method DELETE to delete client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]
	cid, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid url",
			"description": "invalid url detected, make sure to pass proper clientID",
			"status":      "failed",
		})
		return
	}

	if err := a.clientStore.DeleteClient(r.Context(), cid); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "client deleted",
		"description": fmt.Sprintf("client has been deleted for given ID: %s", clientID),
		"status":      "success",
	})
}

func (a *APIServer) handleUpdateClient(w http.ResponseWriter, r *http.Request) {}

func (a *APIServer) handleGenerateBasicAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	clientStore := db.NewClientStore(a.mongoClient, "god_adshield", a.logger)
	resp, err := clientStore.GenerateAnalysis(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully fetched",
		"description": "client fetched",
		"status":      "success",
		"stats":       resp,
	})
}

func (a *APIServer) handleBasicAnalysisRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	roleStore := db.NewRoleStore(a.mongoClient, dbName)
	roles, err := roleStore.GetAllRoles(r.Context(), 100, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched total of: %d roles from client: %s", len(roles), client.ClientName),
		"description": "successfully fetched all roles for given clientID",
		"status":      "success",
		"roles":       roles,
	})

}

func (a *APIServer) handleGetAllStatsFromRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	roleStore := db.NewRoleStore(a.mongoClient, dbName)
	stats, err := roleStore.GenerateAnalysis(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched stats from client: %s", client.ClientName),
		"description": "successfully fetched all stats for given clientID",
		"status":      "success",
		"stats":       stats,
	})
}

func (a *APIServer) handleGetClientPCAPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	pcapStore := db.NewPCAPStore(a.mongoClient, dbName)
	metas, err := pcapStore.GenerateAnalysis(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched pcap-meta-data from client: %s", client.ClientName),
		"description": "successfully fetched alll stats for client",
		"status":      "success",
		"stats":       metas,
	})
}

func (a *APIServer) handleBasicAnalysisPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	pcapStore := db.NewPCAPStore(a.mongoClient, dbName)
	metas, err := pcapStore.GetAllPCAP(r.Context(), 100, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched total of: %d pcap-meta-data from client: %s", len(metas), client.ClientName),
		"description": "successfully fetched all pcap-meta-data for given clientID",
		"status":      "success",
		"pcaps":       metas,
	})
}

func (a *APIServer) handleBasicAnalysisServiceDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	serviceStore := db.NewServiceStore(a.mongoClient, dbName)
	services, err := serviceStore.GetAllServiceDetectedHistory(r.Context(), 100, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched total of: %d services from client: %s", len(services), client.ClientName),
		"description": "successfully fetched all services for given clientID",
		"status":      "success",
		"roles":       services,
	})
}

func (a *APIServer) handleGetIPLookupStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	lookupStore := db.NewLookupStore(a.mongoClient, dbName, a.logger)
	lookups, err := lookupStore.GenerateAnalysis(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched lookups stats from client: %s", client.ClientName),
		"description": "successfully fetched all lookups for given clientID",
		"status":      "success",
		"stats":       lookups,
	})
}

func (a *APIServer) handleBasicAnalysisIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	lookupStore := db.NewLookupStore(a.mongoClient, dbName, a.logger)
	lookups, err := lookupStore.GetAllIPLookupHistory(r.Context(), 100, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched total of: %d lookups from client: %s", len(lookups), client.ClientName),
		"description": "successfully fetched all lookups for given clientID",
		"status":      "success",
		"lookups":     lookups,
	})
}

func (a *APIServer) handleBasicAnalysisUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	userStore := db.NewUserStore(a.mongoClient, dbName)
	users, err := userStore.GetAllUsersFromDB(r.Context(), 100, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("Total number of users: %d for client: %s", len(users), client.ClientName),
		"description": "successfully fetched all users for given clientID",
		"status":      "success",
		"users":       users,
	})
}

func (a *APIServer) handleGetAllStatsFromUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	userStore := db.NewUserStore(a.mongoClient, dbName)
	stats, err := userStore.GenerateAnalysis(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("Stats generated for client: %s", client.ClientName),
		"description": "successfully generated all users stats for given clientID",
		"status":      "success",
		"stats":       stats,
	})
}

func (a *APIServer) handleGetAllStatsFromService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch analysis for client",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]

	id, err := bson.ObjectIDFromHex(clientID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid client id",
			"description": "provided clientID is invalid",
			"status":      "failed",
		})
		return
	}

	client, err := a.clientStore.GetClientByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	dbName := fmt.Sprintf("%s_adshield", client.ClientName)
	serviceStore := db.NewServiceStore(a.mongoClient, dbName)
	services, err := serviceStore.AnalyzeAll(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("fetched service's stats from client: %s", client.ClientName),
		"description": "successfully fetched all services for given clientID",
		"status":      "success",
		"stats":       services,
	})
}
