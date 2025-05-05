package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/logger"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/bob17/adpis/internal/scanner"
	"github.com/bob17/adpis/internal/service"
	"github.com/bob17/adpis/pkg/utils"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "given method is invalid, try method DELETE to delete detected service history",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	serviceID := vars["id"]

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)

	id, err := bson.ObjectIDFromHex(serviceID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid service id",
			"description": "invalid service id provided, try with proper service detected id",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	if err := a.serviceDetectionStore.DeleteServiceByID(r.Context(), id); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	userID, _ := bson.ObjectIDFromHex(claim.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "delete_port_scan_docs",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully deleted",
		"description": fmt.Sprintf("delete service detection of id: %s", serviceID),
		"status":      "success",
	})
}

func (a *APIServer) handleGetServiceByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to get a service detected by id, try method GET",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	serviceID := vars["id"]

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)

	id, err := bson.ObjectIDFromHex(serviceID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid service id",
			"description": "invalid service id provided, try with proper service detected id",
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	history, err := a.serviceDetectionStore.GetDetectedServiceByID(r.Context(), id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})
	}

	userID, _ := bson.ObjectIDFromHex(claim.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_scan_service",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully fetched service",
		"description": "check docs for history of service detection",
		"status":      "success",
		"docs":        history,
	})
}

func (a *APIServer) HandlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to handle port scan, try method POST",
			"status":      "failed",
		})
		return
	}

	var in models.ReqPortScan
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "invalid body",
			"description": "invalid request body provided",
			"status":      "failed",
		})
		return
	}

	resp := getScanPortResult(in, a.logger)
	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successful",
		"description": "ports has been scan for given ip address and port range",
		"status":      "success",
		"docs":        resp,
	})
}

func (a *APIServer) HandleServiceDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to handle port scan, try method POST",
			"status":      "failed",
		})
		return
	}

	var in models.ReqPortScan
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": "invalid request body provided",
			"status":      "failed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "auth failed",
			"description": "auth_claim key not fetched",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("server responded with error: %v", err),
			"status":      "failed",
		})
		return
	}

	if user == nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "user not found",
			"description": "for given userID, user cannot be found in database",
			"status":      "failed",
		})

		return
	}

	startTime := time.Now()
	resp := getServiceDetectionResult(in, a.logger)
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	docs := db.PortScanHistory{
		ID:                 bson.NewObjectID(),
		UserID:             user.ID,
		TargetAddress:      in.Address,
		RequestedPortRange: in.PortRange,
		ScanStartTime:      startTime,
		ScanEndTime:        endTime,
		ScanDuration:       duration,
		Status:             "success",
		ScanDetail:         resp,
		CreatedAt:          time.Now(),
	}

	addContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.serviceDetectionStore.AddDetectedService(addContext, docs); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal errord",
			"description": fmt.Sprintf("server responded with error: %v", err),
			"status":      "failed",
			"err":         err.Error(),
		})
		return
	}

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "port_scan_req",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":     "successful added to database",
		"description": fmt.Sprintf("service detection for given port-range on address: %s", docs.TargetAddress),
		"status":      "success",
		"docs":        docs,
	})
}

func (a *APIServer) handleGetAllDetectedServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to fetch all detected services, maybe try GET",
			"status":      "failed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	limit := int64(100)
	skip := int64(0)

	services, err := a.serviceDetectionStore.GetAllServiceDetectedHistory(ctx, limit, skip)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("server response with error message: %v", err),
			"status":      "failed",
		})

		return
	}

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "auth failed",
			"description": "auth_claim key not fetched",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_scanned_service_history",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("successfully fetched: %d ", len(services)),
		"description": "fetched all history of data from database",
		"status":      "success",
		"docs":        services,
	})
}

func (a *APIServer) handleFetchStatsForAllHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch history information of service detection",
			"status":      "failed",
		})
		return
	}

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claim.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_all_port_scan_stats",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	resp, err := a.serviceDetectionStore.AnalyzeAll(r.Context())
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "stats fetched",
		"description": "successfully fetched all stats for service detection collection",
		"status":      "success",
		"stats":       resp,
	})
}

func (a *APIServer) handleFetchStatsForUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch history information of service detection",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["userID"]
	userPID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid id",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claim.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_port_scan_stats_by_user_id",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	resp, err := a.serviceDetectionStore.AnalysisByUserID(r.Context(), userPID)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "stats fetched",
		"description": fmt.Sprintf("successfully fetched stats for service id: %s", id),
		"status":      "success",
		"stats":       resp,
	})
}

func (a *APIServer) handleFetchStatsByServiceID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method GET to fetch history information of service detection",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	serviceID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid id",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	userID, _ := bson.ObjectIDFromHex(claim.UserID)

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "fetch_port_scan_stats_by_id",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	resp, err := a.serviceDetectionStore.AnalyzeAService(r.Context(), serviceID)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "stats fetched",
		"description": fmt.Sprintf("successfully fetched stats for service id: %s", id),
		"status":      "success",
		"stats":       resp,
	})
}

// scan open ports
func getScanPortResult(in models.ReqPortScan, l logger.Logger) []scanner.ScanResult {
	scanner := scanner.NewPortScanner(l, 5*time.Second, 10)
	resp := scanner.Scan(in.Address, in.PortRange)
	return resp
}

// detect service for open ports
func getServiceDetectionResult(in models.ReqPortScan, l logger.Logger) []db.ServiceResult {
	resp := getScanPortResult(in, l)
	portScanResp := make(chan scanner.ScanResult, len(resp))
	detectionResp := make([]db.ServiceResult, len(portScanResp))

	go func() {
		defer close(portScanResp)
		for _, result := range resp {
			portScanResp <- result
		}
	}()

	srvc := service.NewNMAPServiceDetector(l, 15*time.Second, 10)
	detectResp := srvc.Detect(portScanResp)

	for detected := range detectResp {
		if detected.Status == "open" {
			detectionResp = append(detectionResp, detected)
		}
	}

	return detectionResp
}
