package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/ad/auth"
	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/bob17/adpis/internal/ad/objects"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/pkg/utils"
)

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
	if cm == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "manager not found",
			"description": "connection manager not found, health check failed",
			"status":      "failed",
		})
	}

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

func (a *APIServer) handleADAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to check health of connection",
			"status":      "failed",
		})

		return
	}

	var authReq models.ReqADAuth
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to decode body",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	cfg := connection.GetConnConfig(authReq.Address)
	cm := connection.GetConnectionManager(cfg)
	if cm == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "manager not found",
			"description": "connection manager not found, health check failed",
			"status":      "failed",
		})

		return
	}

	userlogon := fmt.Sprintf("%s@%s", authReq.Username, authReq.DomainName)
	baseDN := utils.ConvertDomainToDN(authReq.DomainName)
	authCfg := auth.NewAuthDefaultConfig(baseDN)
	authenticator, err := auth.NewAuthenticator(cm, authCfg)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "authenticator not found",
			"description": "authenticator didn't found while trying to authenticate user",
			"status":      "failed",
			"error":       err.Error(),
		})

		return
	}

	session, err := authenticator.Authenticate(authCfg.BindUser, authCfg.BindPwd, authReq.Username, authReq.Password)
	if err != nil {
		responseWithJSON(w, http.StatusNetworkAuthenticationRequired, map[string]interface{}{
			"message":     fmt.Sprintf("authentication failed for user: %s", userlogon),
			"description": "username or password invalid for logging user",
			"status":      "failed",
			"error":       err.Error(),
		})

		return
	}

	fmt.Printf("Authentication successful, session-id: %s \n", session.ID)
	fmt.Printf("Session will expires at: %s \n", session.ExpiresAt.Format(time.RFC3339))
	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "Session created",
		"description": "user sesssion has been created successfully, you can now perform operations",
		"status":      "success",
	})
}

func (a *APIServer) handleGetAllUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to access users, please send address of AD server",
			"status":      "failed",
		})
		return
	}

	var reqBody models.ReqADObjectFetch
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "unable to decode",
			"description": "request body could not be decoded",
			"status":      "failed",
		})
		return
	}

	cfg := connection.GetConnConfig(reqBody.Address)
	cm := connection.GetConnectionManager(cfg)
	if cm == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "manager not found",
			"description": "connection manager not found, health check failed",
			"status":      "failed",
		})

		return
	}

	baseDN := utils.ConvertDomainToDN(reqBody.DomainName)
	authCfg := auth.NewAuthDefaultConfig(baseDN)
	userManager := objects.NewUserManager(cm, baseDN)
	users, err := userManager.GetAllUsers(authCfg.BindUser, authCfg.BindPwd, nil, []string{})
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "users not found",
			"description": fmt.Sprintf("internal server while getting all users for domain: %s", baseDN),
			"status":      "failed",
			"error":       err.Error(),
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "user fetched successfully",
		"description": fmt.Sprintf("user fetch, total number of users are: %d", len(users)),
		"status":      "success",
		"users":       users,
	})
}

func (a *APIServer) handleUserByDN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to access users, please send address of AD server",
			"status":      "failed",
		})
		return
	}

	var req models.ReqADObjectFetchWithDN
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "unable to decode",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	cfg := connection.GetConnConfig(req.Address)
	cm := connection.GetConnectionManager(cfg)
	if cm == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "manager not found",
			"description": "connection manager not found, health check failed",
			"status":      "failed",
		})

		return
	}

	baseDN := utils.ConvertDomainToDN(req.DomainName)
	authCfg := auth.NewAuthDefaultConfig(baseDN)
	userManager := objects.NewUserManager(cm, baseDN)

	user, err := userManager.GetUserByDN(req.DN, authCfg.BindUser, authCfg.BindPwd)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     fmt.Sprintf("unable to get user by DN: %s", req.DN),
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "fetched successfully",
		"description": fmt.Sprintf("user found with DN: %s", req.DN),
		"status":      "success",
		"user":        user,
	})
}

func (a *APIServer) handleCreateNewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to access users, please send address of AD server",
			"status":      "failed",
		})
		return
	}
}
