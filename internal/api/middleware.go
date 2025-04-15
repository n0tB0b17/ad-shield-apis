package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/bob17/adpis/internal/rbac"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (a *APIServer) InitializeStores(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.dbName != "" {
			a.userStore = db.NewUserStore(a.mongoClient, a.dbName)
			a.roleStore = db.NewRoleStore(a.mongoClient, a.dbName)
			a.serviceDetectionStore = db.NewServiceStore(a.mongoClient, a.dbName)
			a.pcapStore = db.NewPCAPStore(a.mongoClient, a.dbName)
			a.userActivityStore = db.NewUserActivityStore(a.mongoClient, a.dbName, a.logger)
		}

		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) ValidateIfRealClientID(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["client_id"]

		clientID, err := bson.ObjectIDFromHex(id)
		if err != nil {
			responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"message":     "invalid id",
				"description": "please provide valid objectID to fetch client",
				"status":      "failed",
				"error":       err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := a.clientStore.GetClientByID(ctx, clientID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "internal error",
				"description": err.Error(),
				"status":      "failed",
			})
			return
		}

		if client == nil {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "client not found",
				"description": "client doesn't exist for given query ID",
				"status":      "failed",
			})

			return
		}

		a.dbName = fmt.Sprintf("%s_adshield", client.ClientName)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) Logger(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Debug(fmt.Sprintf("Go request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path))
		log.Printf("Got request for IP: %s, URL: [%s]> %s", r.RemoteAddr, r.Method, r.URL.Path)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) Authorization(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"message":     "unauthorized",
				"description": "authorization header is missing",
				"status":      "failed",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"message":     "unauthorized",
				"description": "invalid authorization format, should be 'Bearer <token>'",
				"status":      "failed",
			})
			return
		}

		tokenStr := parts[1]
		claims := &rbac.Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
			}

			return []byte(rbac.JwtSecret), nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"message":     "unauthorized",
					"description": "invalid token signature",
					"status":      "failed",
				})

				return
			}

			if errors.Is(err, jwt.ErrTokenExpired) {
				if claims.UserID != "" {
					id, _ := bson.ObjectIDFromHex(claims.UserID)
					ctx := r.Context()

					_ = a.userActivityStore.RecordActivity(ctx, db.UserActivity{
						ID:        id,
						Action:    "token_expired",
						Timestamp: time.Now(),
						IPAddress: r.RemoteAddr,
						UserAgent: r.UserAgent(),
					})
				}

				responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"message":     "unauthorized",
					"description": "token has expired",
					"status":      "failed",
				})
				return
			}
		}

		if !token.Valid {
			responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"message":     "unauthorized",
				"description": "invalid token",
				"status":      "failed",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "auth_claim", claims)
		r = r.WithContext(ctx)
		nxt.ServeHTTP(w, r)
	})
}
