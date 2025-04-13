package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bob17/adpis/internal/ad/auth"
	"github.com/bob17/adpis/internal/ad/connection"
	"github.com/bob17/adpis/internal/ad/objects"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/pkg/utils"
)

func (a *APIServer) handleCreateNewOU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to access users, please send address of AD server",
			"status":      "failed",
		})
		return
	}

	var req models.ReqCreateNewOU
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
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

		return
	}

	baseDN := utils.ConvertDomainToDN(req.DomainName)
	authCfg := auth.NewAuthDefaultConfig(baseDN)

	ouManager := objects.NewOUManager(cm, baseDN)
	if err := ouManager.CreateOU(nil, authCfg.BindUser, authCfg.BindPwd); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully created",
		"description": fmt.Sprintf("OU created with DN: %s for domain: %s", req.DistinguishedName, baseDN),
		"status":      "success",
	})
}

func (a *APIServer) handleGetAllOU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to access users, please send address of AD server",
			"status":      "failed",
		})
		return
	}

	var req models.ReqADObjectFetch
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "unable to decode",
			"description": "request body could not be decoded",
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

	ouManager := objects.NewOUManager(cm, baseDN)
	ous, err := ouManager.GetAllOUs(authCfg.BindUser, authCfg.BindPwd, nil, []string{})
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "failed to get ous",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("successfully fetched: %d OUs", len(ous)),
		"description": fmt.Sprintf("fetch organizational units for domain: %s", req.DomainName),
		"status":      "success",
		"docs":        ous,
	})
}

func (a *APIServer) handleGetOUByDN(w http.ResponseWriter, r *http.Request) {
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
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "unable to decode",
			"description": "request body could not be decoded",
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

	ouManager := objects.NewOUManager(cm, baseDN)
	ou, err := ouManager.GetOUByDN(req.DN, authCfg.BindUser, authCfg.BindPwd)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "failed to load OU by DN",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully fetched ou",
		"description": fmt.Sprintf("OU with DN: %s fetched successfully", req.DN),
		"status":      "success",
		"docs":        ou,
	})
}
