package rbac

import (
	"fmt"
	"time"

	"github.com/bob17/adpis/internal/db"
	"github.com/golang-jwt/jwt/v5"
)

const (
	JwtSecret     = "test_secret"
	jwtExpiration = 2 * time.Hour
)

type Claims struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	RoleID   string `json:"role_id"`
	jwt.RegisteredClaims
}

func GenerateToken(user *db.Users, client_id string) (string, time.Time, error) {
	expTime := time.Now().Add(jwtExpiration)

	claims := &Claims{
		UserID:   user.ID.Hex(),
		RoleID:   user.RoleID.Hex(),
		ClientID: client_id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%v", user),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(JwtSecret))
	return tokenStr, expTime, err
}
