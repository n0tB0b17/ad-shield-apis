package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/models"
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

	dbUser := db.Users{
		ID:            bson.NewObjectID(),
		UserName:      user.UserName,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		RoleID:        user.RoleID,
		Password:      user.Password,
		ContactNumber: user.ContactNumber,
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

	responseWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"message":     "logged-in",
		"description": "user with provided information has been logged in",
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
