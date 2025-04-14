package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/internal/rbac"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleAddRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "to add new roles, please try METHOD post",
			"status":      "failed",
		})

		return
	}

	var role models.ReqRoles
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid body",
			"description": "invalid request body provided",
			"status":      "failed",
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addRole := db.Roles{
		ID:          bson.NewObjectID(),
		Name:        role.Name,
		Description: role.Description,
		Permissions: role.Permissions,
		CreatedAt:   time.Now(),
	}

	if err := a.roleStore.AddRoles(ctx, addRole); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("unable to add new roles to server, err: %v", err),
			"status":      "failed",
		})

		return
	}

	claims, ok := r.Context().Value("auth_claim").(*rbac.Claims)
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
		Action:    "add_new_role",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":     "Role added",
		"description": fmt.Sprintf("successfully added new role named: %s", addRole.Name),
		"status":      "success",
		"role":        addRole,
	})
}

func (a *APIServer) handleGetAllRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try GET method to fetch all roles",
			"status":      "failed",
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	limit := int64(100)
	skip := int64(0)
	roles, err := a.roleStore.GetAllRoles(ctx, limit, skip)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("server error while fetching roles, error: %v", err),
			"status":      "failed",
		})

		return
	}

	if roles == nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "roles not found",
			"description": "currently database has no role, create one and try fetching",
			"status":      "failed",
		})

		return
	}

	claims, ok := r.Context().Value("auth_claim").(*rbac.Claims)
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
		Action:    "get_all_roles",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"message":     fmt.Sprintf("total roles: %d", len(roles)),
		"description": "successfully fetched all roles from database",
		"status":      "success",
		"role":        roles,
	})
}
