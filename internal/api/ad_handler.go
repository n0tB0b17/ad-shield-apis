package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/bob17/adpis/internal/models"
)

// func (a *APIServer) handleADAuthentication() {

// }

func (a *APIServer) handleADHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to check health of connection",
			"status":      "failed",
		})

		return
	}

	var req models.ReqADServerHealthCheck
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to decode body",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	cfg := connection.GetConnConfig(req.Address)
	cm := connection.GetConnectionManager(cfg)

	if err := cm.CheckHealth(); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "health check failed",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	stats := cm.GetStats()
	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully health-checked",
		"description": fmt.Sprintf("health check for active directory server at: %s", req.Address),
		"status":      "success",
		"stats":       stats,
	})
}
