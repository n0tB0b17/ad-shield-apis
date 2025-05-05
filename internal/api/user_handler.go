package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/models"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/bob17/adpis/pkg/utils"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) handleUserRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to add new user, maybe try METHOD post",
			"status":      "failed",
		})

		return
	}

	var user models.ReqUserRegistration
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "unable to decode body",
			"description": fmt.Sprintf("invalid body provided, as server is unable to decode: %v", err),
			"status":      "failed",
		})
		return
	}

	isValid := isUserValid(user)
	if !isValid {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": fmt.Sprintf("invalid body provided, as server is unable to decode: %v", err),
			"status":      "failed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	roleDoc, err := a.roleStore.GetARoleWithID(ctx, user.RoleID)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("unable to fetch role to assign for added user, err: %v", err),
			"status":      "failed",
		})
		return
	}

	if roleDoc == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "role not found",
			"description": "give role objectID didn't match with our collection",
			"status":      "failed",
		})
		return
	}

	userName := strings.ReplaceAll(user.UserName, " ", "_")
	dbUser := db.Users{
		ID:            bson.NewObjectID(),
		UserName:      userName,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		RoleID:        user.RoleID,
		Password:      user.Password,
		ContactNumber: user.ContactNumber,
		CreatedAt:     time.Now(),
	}

	err = a.userStore.AddUserToDB(ctx, dbUser)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("error while registering user: %v \n", err),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":     "User registered",
		"descriptipn": fmt.Sprintf("new user with username of: %s has been registered", dbUser.UserName),
		"status":      "success",
		"user":        dbUser,
	})
}

func (a *APIServer) handleGetAllRegisteredUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to get all registered user, try METHOD get",
			"status":      "failed",
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	limit := int64(100)
	skip := int64(0)
	users, err := a.userStore.GetAllUsersFromDB(ctx, limit, skip)

	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error",
			"description": fmt.Sprintf("server throw error: %v", err),
			"status":      "failed",
		})
		return
	}

	if users == nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "no users",
			"description": "server cannot find any users at the moment",
			"status":      "failed",
		})

		return
	}

	responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"message":     fmt.Sprintf("total registered users: %d", len(users)),
		"description": "registered users fetched",
		"status":      "success",
		"users":       users,
	})
}

func (a *APIServer) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "to login, please try METHOD post",
			"status":      "failed",
		})
		return
	}

	var userLogin models.ReqUserLogin
	if err := json.NewDecoder(r.Body).Decode(&userLogin); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": fmt.Sprintf("in-order to login, please provide correct request body, err: %v", err),
			"status":      "failed",
		})

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user, err := a.userStore.LoginUser(ctx, userLogin)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": fmt.Sprintf("error while logging user: %s", err),
			"status":      "failed",
		})

		return
	}

	if user == nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "user not found",
			"description": fmt.Sprintf("user doesn't exist for given credentials: %v", userLogin),
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	client_id := vars["client_id"]

	token, expTime, err := rbac.GenerateToken(user, client_id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "unable to generate jwt token",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	actCtx, actCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer actCancel()

	activity := db.UserActivity{
		UserID:    user.ID,
		Action:    "login",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	err = a.userActivityStore.RecordActivity(actCtx, activity)
	if err != nil {
		fmt.Println("unable to record activity, check file log for more information")
	}

	responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"message":     "logged-in",
		"description": "user with provided information has been logged in",
		"status":      "success",
		"docs": map[string]interface{}{
			"token":    token,
			"expireAt": expTime,
			"user":     user,
		},
	})
}

func (a *APIServer) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to logout of application, please try METHOD get",
			"status":      "failed",
		})
		return
	}

	claims, ok := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	if !ok {
		responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"message":     "unauthorized",
			"description": "user not authenticated",
			"status":      "failed",
		})
		return
	}

	userID, _ := bson.ObjectIDFromHex(claims.UserID)
	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "logout",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "logged-out",
		"description": "user has been successfully logged out",
		"status":      "success",
	})
}

func (a *APIServer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		responseWithJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message":     "invalid method",
			"description": "invalid method provided to delete user",
			"status":      "failed",
		})

		return
	}

	claim := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
	vars := mux.Vars(r)
	id := vars["id"]

	clientId, err := bson.ObjectIDFromHex(id)
	if err != nil {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "invalid id",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	if err := a.userStore.DeleteUser(r.Context(), clientId); err != nil {
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
		Action:    "user_deleted",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully deleted",
		"description": fmt.Sprintf("user with id: %s has been deleted by user: %s", id, claim.ID),
		"status":      "success",
	})
}

func (a *APIServer) handleGetUserByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "to get user by id, please try METHOD get",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	_id := vars["id"]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := bson.ObjectIDFromHex(_id)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     fmt.Sprintf("invalid id: %s", _id),
			"description": fmt.Sprintf("invalid id provided: %v", err),
			"status":      "failed",
		})
		return
	}
	user, err := a.userStore.GetUserByID(ctx, id)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal server error",
			"description": fmt.Sprintf("error while getting user by id: %v", err),
			"status":      "failed",
		})
		return
	}

	if user == nil {
		responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"message":     "user not found",
			"description": fmt.Sprintf("user doesn't exist for given id: %v", id),
			"status":      "failed",
		})
		return
	}
	responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"message":     "user found",
		"description": fmt.Sprintf("user with id: %s has been found", id.Hex()),
		"status":      "success",
		"user":        user,
	})
}

func (a *APIServer) handleGetUserStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		return
	}

	timeframe := r.URL.Query().Get("timeframe")
	if timeframe == "" {
		timeframe = "daily"
	}

	var startDate, endDate time.Time
	now := time.Now()

	switch timeframe {
	case "daily":
		startDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		endDate = startDate.Add(24 * time.Hour)
	case "weekly":
		dayFromSunday := int(now.Weekday())
		startDate = time.Date(now.Year(), now.Month(), now.Day()-dayFromSunday, 0, 0, 0, 0, now.Location())
		endDate = startDate.Add(7 * 24 * time.Hour)
	case "monthly":
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 1, 0)
	default:
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid timeframe provided",
			"description": "timeframe should be daily/weekly/monthly, other are ignored",
			"status":      "failed",
		})
		return
	}

	vars := mux.Vars(r)
	user_id := vars["id"]

	userID, err := bson.ObjectIDFromHex(user_id)
	if err != nil {
		responseWithJSON(w, http.StatusConflict, map[string]interface{}{
			"message":     "invalid id",
			"description": "user id provided in url seems to be invalid",
			"status":      "failed",
		})
		return
	}

	_ = a.userActivityStore.RecordActivity(r.Context(), db.UserActivity{
		UserID:    userID,
		Action:    "user_stat_req",
		Timestamp: time.Now(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	stats, err := a.userActivityStore.GetUserActivityStats(r.Context(), userID, startDate, endDate)
	if err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "stats not found",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "here is user stats",
		"description": "user activity stats fetched successfully",
		"status":      "success",
		"docs":        stats,
	})
}

func (a *APIServer) handleUpdateUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid method",
			"description": "try method PUT if you want to update user information",
			"status":      "failed",
		})

		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	userID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid userID in path",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	var user models.ReqUserRegistration
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"message":     "invalid body",
			"description": err.Error(),
			"status":      "failed",
		})

		return
	}

	updateUser := db.Users{
		UserName:      user.UserName,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		RoleID:        user.RoleID,
		ContactNumber: user.ContactNumber,
		Password:      user.Password,
	}

	if err := a.userStore.UpdateUser(r.Context(), userID, updateUser); err != nil {
		responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"message":     "internal error while updating user",
			"description": err.Error(),
			"status":      "failed",
		})
		return
	}

	responseWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "successfully updated",
		"description": fmt.Sprintf("user with username: %s has been updated", updateUser.UserName),
		"status":      "success",
	})
}

func isUserValid(usr models.ReqUserRegistration) bool {
	if usr.Email == "" || usr.Password == "" {
		return false
	}

	return isValidObjectID(usr.RoleID.Hex())
}

func isValidObjectID(id string) bool {
	_, err := bson.ObjectIDFromHex(id)
	return err == nil
}
