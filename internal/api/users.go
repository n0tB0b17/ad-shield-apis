package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/models"
)

func (a *APIServer) handleUserRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid http method", http.StatusBadRequest)
		return
	}

	var user models.ReqUserRegistration
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid body provided, as server is unable to decode: %v", err), http.StatusBadRequest)
		return
	}

	isValid := isUserValid(user)
	if !isValid {
		http.Error(w, "valid input not provided", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbUser := db.Users{
		UserName:      user.UserName,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		Password:      user.Password,
		ContactNumber: user.ContactNumber,
	}

	a.userStore.AddUserToDB(ctx, dbUser)

	resp := map[string]interface{}{
		"message":     "Testing",
		"descriptipn": "testing user registration endpoint",
		"status":      "testing",
		"user":        dbUser,
	}

	responseWithJSON(w, http.StatusCreated, resp)
}

func (a *APIServer) handleGetAllRegisteredUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	responseWithJSON(w, http.StatusMethodNotAllowed, nil)
}

func responseWithJSON(
	w http.ResponseWriter,
	code int,
	docs interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(docs)
}

func isUserValid(usr models.ReqUserRegistration) bool {
	if usr.Email == "" || usr.Password == "" {
		return false
	}

	return true
}
