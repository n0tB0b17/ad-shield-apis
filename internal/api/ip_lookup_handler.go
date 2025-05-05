package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/geo"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/bob17/adpis/pkg/utils"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method for IP-lookup, try method POST",
			"status":      "failed",
		})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	claims := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)

	geoCfg := geo.NewGeoConfig(req.Domain)
	geoService := geo.NewGeoService(geoCfg)
	resp, err := geoService.Lookup()
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	resp.CreatedBy = userID
	resp.CreatedAt = time.Now()

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "ip_lookup_req",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	_ = a.ipLookupStore.AddNewIPLookUpData(r.Context(), *resp)
	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "lookup succeeded",
		"description": fmt.Sprintf("successfully lookuped for domain/ip: %s", req.Domain),
		"status":      "success",
		"docs":        resp,
	})
}

func (a *APIServer) handleGetAllIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch all iplook history data",
			"status":      "failed",
		})

		return
	}

	resp, err := a.ipLookupStore.GetAllIPLookupHistory(r.Context(), 10, 0)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	if len(resp) == 0 {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "ip history not found",
			"description": "there is no data for ip-lookup",
			"status":      "failed",
		})

		return
	}

	claims := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claims.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_ip_lookup_history",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully fetched history",
		"description": "check following docs to access all ip history",
		"status":      "success",
		"docs":        resp,
	})
}

func (a *APIServer) handleGetAIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "bad method",
			"description": "try GET method to get ip history by id",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	lookupID := vars["id"]

	id, err := bson.ObjectIDFromHex(lookupID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid id",
			"description": "id provided in URL path is seems to be invalid, try with proper one",
			"status":      "failed",
		})
		return
	}

	resp, err := a.ipLookupStore.GetAIPLookupByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	if resp == nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "document not found",
			"description": "ip-lookup document cannot be found",
			"status":      "failed",
		})
		return
	}

	claims := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claims.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_ip_lookup",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully fetched",
		"description": "check docs section for ip-lookup history data",
		"status":      "success",
		"docs":        resp,
	})
}

func (a *APIServer) handleDeleteIPLookupData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method DELETE to delete history data of IP-lookup",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	ipLookupID := vars["id"]
	id, err := bson.ObjectIDFromHex(ipLookupID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid id",
			"description": "given id in path is invalid, try with valid id to delete data",
			"status":      "failed",
		})

		return
	}

	if err := a.ipLookupStore.DeleteIPLookup(r.Context(), id); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	claims := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claims.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "delete_ip_lookup_docs",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "deleted iplookup history",
		"description": fmt.Sprintf("iplookup history data for id: %s has been deleted successfully \n", ipLookupID),
		"status":      "success",
	})
}
