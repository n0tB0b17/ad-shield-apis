package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (a *APIServer) handleUserRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid http method", http.StatusBadRequest)
		return
	}

	var user map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid body provided, as server is unable to decode: %v", err), http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"message":     "Testing",
		"descriptipn": "testing user registration endpoint",
		"status":      "testing",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}
