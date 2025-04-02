package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/internal/scanner"
	"github.com/bob17/adpis/internal/service"
)

func (a *APIServer) HandlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}

	var in models.ReqPortScan
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "Invalid body provided", http.StatusNotFound)
		return
	}

	resp := getScanPortResult(in, a.logger)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *APIServer) HandleServiceDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}

	var in models.ReqPortScan
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "Invalid body", http.StatusNotFound)
		return
	}

	resp := getServiceDetectionResult(in, a.logger)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// scan open ports
func getScanPortResult(in models.ReqPortScan, l logger.Logger) []scanner.ScanResult {
	scanner := scanner.NewPortScanner(l, 5*time.Second, 10)
	resp := scanner.Scan(in.Address, in.PortRange)
	return resp
}

// detect service for open ports
func getServiceDetectionResult(in models.ReqPortScan, l logger.Logger) []service.ServiceResult {
	resp := getScanPortResult(in, l)
	portScanResp := make(chan scanner.ScanResult, len(resp))
	detectionResp := make([]service.ServiceResult, len(portScanResp))

	go func() {
		defer close(portScanResp)
		for _, result := range resp {
			portScanResp <- result
		}
	}()

	srvc := service.NewNMAPServiceDetector(l, 10*time.Second, 10)
	detectResp := srvc.Detect(portScanResp)

	for detected := range detectResp {
		detectionResp = append(detectionResp, detected)
	}

	return detectionResp
}
