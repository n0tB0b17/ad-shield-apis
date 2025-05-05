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
	"github.com/bob17/adpis/pkg/utils"
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
			a.ipLookupStore = db.NewLookupStore(a.mongoClient, a.dbName, a.logger)
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

		ctx := context.WithValue(r.Context(), utils.CLAIMS_KEY, claims)
		r = r.WithContext(ctx)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) validateClientWithGivenToken(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, exist := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
		if !exist {
			responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"message":     "token invalid",
				"description": "provided token is invalid or expired, try with proper token",
				"status":      "failed",
			})

			return
		}

		vars := mux.Vars(r)
		client_id := vars["client_id"]

		if client_id != claims.ClientID {
			responseWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"message":     "unexpected error",
				"description": "clientID doesn't seems to be same",
				"status":      "failed",
			})

			return
		}

		clientID, _ := bson.ObjectIDFromHex(client_id)
		client, err := a.clientStore.GetClientByID(r.Context(), clientID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "client not found",
				"description": err.Error(),
				"status":      "failed",
			})

			return
		}

		if client == nil {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "client not found",
				"description": "client doesn't exist on database with given client_id in token",
				"status":      "failed",
			})

			return
		}

		ctx := context.WithValue(r.Context(), utils.CLIENT_KEY, client)
		r = r.WithContext(ctx)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) validateIfUserExistInClient(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, exist := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
		if !exist {
			responseWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"message":     "token invalid",
				"description": "provided token is invalid or expired, try with proper token",
				"status":      "failed",
			})

			return
		}

		userID, err := bson.ObjectIDFromHex(claims.UserID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "invalid id detected",
				"description": err.Error(),
				"status":      "failed",
			})

			return
		}

		client, exist := r.Context().Value(utils.CLIENT_KEY).(*db.ADClient)
		if !exist {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "client not found",
				"description": "for given clientId, client doesn't exist in database",
				"status":      "failed",
			})
			return
		}

		clientDBName := fmt.Sprintf("%s_adshield", client.ClientName)
		clientUserStore := db.NewUserStore(a.mongoClient, clientDBName)
		user, err := clientUserStore.GetUserByID(r.Context(), userID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "user not found",
				"description": err.Error(),
				"status":      "failed",
			})

			return
		}

		if user == nil {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "user not found",
				"description": "provided token for user doesn't exist on assigned client/tenant",
				"status":      "failed",
			})

			return
		}

		ctx := context.WithValue(r.Context(), utils.USER_KEY, user)
		r = r.WithContext(ctx)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) validateForPermissions(nxt http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claim, exist := r.Context().Value(utils.CLAIMS_KEY).(*rbac.Claims)
		if !exist {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "token invalid",
				"description": "token is not valid, try with proper token",
				"status":      "failed",
			})
			return
		}

		client, exist := r.Context().Value(utils.CLIENT_KEY).(*db.ADClient)
		if !exist {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "client not found",
				"description": "client cannot be found for given middleware",
				"status":      "failed",
			})

			return
		}

		dbName := fmt.Sprintf("%s_adshield", client.ClientName)
		roleStore := db.NewRoleStore(a.mongoClient, dbName)

		roleID, err := bson.ObjectIDFromHex(claim.RoleID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "internal error",
				"description": "invalid roleID detected inside of jwt token",
				"status":      "failed",
			})

			return
		}

		role, err := roleStore.GetARoleWithID(r.Context(), roleID)
		if err != nil {
			responseWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"message":     "internal server error",
				"description": err.Error(),
				"status":      "failed",
			})

			return
		}

		if role == nil {
			responseWithJSON(w, http.StatusNotFound, map[string]interface{}{
				"message":     "role not found",
				"description": fmt.Sprintf("role_id inside of token is not vaild: %s \n", roleID.String()),
				"status":      "failed",
			})

			return
		}

		ctx := context.WithValue(r.Context(), utils.ROLE_KEY, role)
		r = r.WithContext(ctx)
		nxt.ServeHTTP(w, r)
	})
}

func (a *APIServer) hasAccess(component, action string) func(http.Handler) http.Handler {
	return func(nxt http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, exist := r.Context().Value(utils.ROLE_KEY).(*db.Roles)
			if !exist {
				responseWithJSON(w, http.StatusForbidden, map[string]interface{}{
					"message":     "forbidden",
					"description": "role doesn't exist on user",
					"status":      "failed",
				})

				return
			}

			for _, permission := range roles.Permissions {
				if permission == "all" {
					nxt.ServeHTTP(w, r)
					return
				}
			}

			hasAccess := false
			for _, permission := range roles.Permissions {
				parts := strings.Split(permission, "_")
				if len(parts) >= 2 && parts[0] == component && parts[1] == action {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				responseWithJSON(w, http.StatusForbidden, map[string]interface{}{
					"message":     "unauthorized",
					"description": fmt.Sprintf("not allowed to access service: %s for action: %s", component, action),
					"status":      "failed",
				})

				return
			}

			nxt.ServeHTTP(w, r)
		})
	}
}
