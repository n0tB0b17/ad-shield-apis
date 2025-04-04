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
	"github.com/bob17/adpis/internal/scanner"
	"github.com/bob17/adpis/internal/service"
	"go.mongodb.org/mongo-driver/v2/bson"
)

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

	if in.UserID.Hex() == "000000000000000000000000" || !isValidObjectID(in.UserID.Hex()) {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid userid",
			"description": "provided userID is invalid, try authenticating and scan with proper user",
			"status":      "failed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// validate if user exist in databsae
	user, err := a.userStore.GetUserByID(ctx, in.UserID)
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

	if err := a.serviceDetectionStore.AddDetectedService(ctx, docs); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("server responded with error: %v", err),
			"status":      "failed",
		})
		return
	}

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

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("successfully fetched: %d ", len(services)),
		"description": "fetched all history of data from database",
		"status":      "success",
		"docs":        services,
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
