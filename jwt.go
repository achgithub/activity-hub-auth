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

// SSEClaims represents claims for temporary SSE tokens
type SSEClaims struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"` // Same as email for consistency
	AppID  string `json:"app_id"`  // Which app this token is for
	GameID string `json:"game_id"` // Which game session
	Scope  string `json:"scope"`   // Always "sse"
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

// GenerateSSEToken creates a short-lived token specifically for SSE connections
// These tokens expire in 5 minutes and should be used immediately
func GenerateSSEToken(email, appID, gameID string) (string, error) {
	secret := getJWTSecret()

	claims := SSEClaims{
		Email:  email,
		UserID: email,
		AppID:  appID,
		GameID: gameID,
		Scope:  "sse",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "activity-hub-sse",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateSSEToken validates an SSE-specific token and returns the claims
func ValidateSSEToken(tokenString string) (*SSEClaims, error) {
	secret := getJWTSecret()

	token, err := jwt.ParseWithClaims(tokenString, &SSEClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid SSE token: %w", err)
	}

	if claims, ok := token.Claims.(*SSEClaims); ok && token.Valid {
		// Verify it's an SSE token
		if claims.Scope != "sse" {
			return nil, fmt.Errorf("token is not an SSE token")
		}

		// Check expiration
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			return nil, fmt.Errorf("SSE token expired")
		}

		// Check issuer
		if claims.Issuer != "activity-hub-sse" {
			return nil, fmt.Errorf("invalid SSE token issuer")
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid SSE token claims")
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
