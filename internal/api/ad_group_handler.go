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

func (a *APIServer) handleCreateNewGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method to create group, try post",
			"status":      "failed",
		})
		return
	}

	var req models.ReqCreateNewGroup
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
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
	groupManager := objects.NewGroupManager(cm, baseDN)

	grp := &objects.Group{
		DistinguishedName: req.DistinguishedName,
		DN:                baseDN,
		Description:       req.Description,
		SAMAccountName:    req.SAMAccountName,
		Name:              req.Name,
		DisplayName:       req.DisplayName,
		Type:              objects.GroupType(req.Type),
	}

	if err := groupManager.CreateGroup(grp, authCfg.BindUser, authCfg.BindPwd); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "group not created",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "Successfully created",
		"description": fmt.Sprintf("new group created with distinguishuedName: %s", req.DistinguishedName),
		"status":      "success",
	})

}

func (a *APIServer) handleGetAllGroups(w http.ResponseWriter, r *http.Request) {
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
	groupManager := objects.NewGroupManager(cm, baseDN)
	groups, err := groupManager.GetAllGroups(authCfg.BindUser, authCfg.BindPwd, nil, []string{})
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     fmt.Sprintf("unable to fetch groups from domain: %s", baseDN),
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     fmt.Sprintf("Total group: %d fetched", len(groups)),
		"description": fmt.Sprintf("all group fetch from domain: %s", req.DomainName),
		"status":      "success",
		"docs":        groups,
	})

}

func (a *APIServer) handleGetUserByDN(w http.ResponseWriter, r *http.Request) {
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

	groupManager := objects.NewGroupManager(cm, baseDN)
	grp, err := groupManager.GetGroupByDN(req.DN, authCfg.BindUser, authCfg.BindPwd)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "Failed to get group",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successful search",
		"description": "search for group by DN is successfully",
		"status":      "success",
		"docs":        grp,
	})
}
