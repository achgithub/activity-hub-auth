package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for an authenticated user
type Claims struct {
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	IsAdmin bool     `json:"is_admin"`
	Roles   []string `json:"roles"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new JWT token for the given user
func GenerateJWT(email, name string, isAdmin bool, roles []string) (string, error) {
	secret := getJWTSecret()

	claims := Claims{
		Email:   email,
		Name:    name,
		IsAdmin: isAdmin,
		Roles:   roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "activity-hub",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(tokenString string) (*Claims, error) {
	secret := getJWTSecret()

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check expiration
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			return nil, fmt.Errorf("token expired")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// getJWTSecret retrieves the JWT secret from environment variable
// Falls back to a default for development (should be overridden in production)
func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Default secret for development only
		// MUST be overridden with JWT_SECRET environment variable in production
		secret = "activity-hub-dev-secret-change-in-production"
	}
	return secret
}
