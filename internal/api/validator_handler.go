package api

import (
	"net/http"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/pkg/utils"
)

func (a *APIServer) handleGetInfoBasedOnToken(w http.ResponseWriter, r *http.Request) {
	client, exist := r.Context().Value(utils.CLIENT_KEY).(*db.ADClient)
	if !exist {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "client not found",
			"description": "clientID provided in bearer token is invalid",
			"status":      "failed",
		})

		return
	}

	user, exist := r.Context().Value(utils.USER_KEY).(*db.Users)
	if !exist {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "user not found",
			"description": "user provided in bearer token is invalid",
			"status":      "failed",
		})
		return
	}

	role, exist := r.Context().Value(utils.ROLE_KEY).(*db.Roles)
	if !exist {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "role not found",
			"description": "token provided in header is likely invalid",
			"status":      "failed",
		})

		return
	}
	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "good to go",
		"description": "client and user is good, no fishy activity detected",
		"status":      "success",
		"docs": map[string]interface{}{
			"client": client,
			"user":   user,
			"role":   role,
		},
	})
}
