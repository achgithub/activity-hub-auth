package auth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/lib/pq"
)

// Middleware validates a demo-token or impersonate-token and sets user in context.
// Returns func(http.Handler) http.Handler for use with gorilla/mux router.Use().
//
// Usage:
//
//	identityDB, _ := database.InitIdentityDatabase()
//	r.Use(auth.Middleware(identityDB))
func Middleware(identityDB *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Missing or invalid authorization", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := ResolveToken(identityDB, token)
			if err != nil {
				log.Printf("❌ Auth failed for %s %s: %v", r.Method, r.URL.Path, err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			log.Printf("✅ Authenticated: %s (impersonating=%v)", user.Email, user.IsImpersonating)
			ctx := context.WithValue(r.Context(), userContextKey, *user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SSEMiddleware validates a token from the query parameter (for EventSource compatibility).
// EventSource does not support custom headers so the token must be in the URL.
//
// Usage:
//
//	r.Use(auth.SSEMiddleware(identityDB))
func SSEMiddleware(identityDB *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "Missing authorization token", http.StatusUnauthorized)
				return
			}

			user, err := ResolveToken(identityDB, token)
			if err != nil {
				log.Printf("❌ SSE auth failed for %s: %v", r.URL.Path, err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			log.Printf("✅ SSE authenticated: %s", user.Email)
			ctx := context.WithValue(r.Context(), userContextKey, *user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns a middleware that enforces the user has a specific role.
// Must be used after Middleware or SSEMiddleware.
//
// Usage:
//
//	r.Use(auth.Middleware(identityDB))
//	r.Use(auth.RequireRole("game_admin"))
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !user.HasRole(role) {
				log.Printf("❌ RequireRole(%s): user %s missing role", role, user.Email)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminMiddleware validates that the authenticated user has is_admin = true.
// Must be used after Middleware or SSEMiddleware.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetUserFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !user.IsAdmin {
			log.Printf("❌ AdminMiddleware: user %s is not admin", user.Email)
			http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
			return
		}

		log.Printf("✅ Admin access granted: %s", user.Email)
		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext extracts the authenticated user from the request context.
// Returns (user, true) if found, (nil, false) otherwise.
func GetUserFromContext(ctx context.Context) (*AuthUser, bool) {
	user, ok := ctx.Value(userContextKey).(AuthUser)
	if !ok {
		return nil, false
	}
	return &user, true
}

// ResolveToken validates a token and returns the associated user.
// Supports demo-token-{email}, guest-token-{uuid}, and impersonate-{uuid} formats.
// This is the centralized token validation function - all token parsing must go through here.
func ResolveToken(identityDB *sql.DB, token string) (*AuthUser, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Validate token length to prevent malformed tokens
	if len(token) > 512 {
		return nil, fmt.Errorf("token exceeds maximum length")
	}

	if strings.HasPrefix(token, "impersonate-") {
		var impersonatedEmail, superUserEmail string
		err := identityDB.QueryRow(`
			SELECT impersonated_email, super_user_email
			FROM impersonation_sessions
			WHERE impersonation_token = $1 AND is_active = true
		`, token).Scan(&impersonatedEmail, &superUserEmail)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid or expired impersonation token")
		}
		if err != nil {
			return nil, fmt.Errorf("impersonation lookup: %w", err)
		}

		user, err := lookupUser(identityDB, impersonatedEmail)
		if err != nil {
			return nil, err
		}
		user.IsImpersonating = true
		user.ImpersonatedBy = superUserEmail
		return user, nil
	}

	if strings.HasPrefix(token, "guest-token-") {
		// Guest tokens are valid as-is; create a minimal user object
		guestID := strings.TrimPrefix(token, "guest-token-")
		return &AuthUser{
			Email:   "guest-" + guestID,
			Name:    "Guest",
			IsAdmin: false,
			Roles:   []string{},
		}, nil
	}

	if strings.HasPrefix(token, "demo-token-") {
		email := strings.TrimPrefix(token, "demo-token-")
		return lookupUser(identityDB, email)
	}

	return nil, fmt.Errorf("unrecognized token format")
}

// lookupUser fetches user details and roles from the identity database.
func lookupUser(identityDB *sql.DB, email string) (*AuthUser, error) {
	var user AuthUser
	var roles []string

	err := identityDB.QueryRow(`
		SELECT email, name, is_admin, COALESCE(roles, '{}')
		FROM users
		WHERE email = $1
	`, email).Scan(&user.Email, &user.Name, &user.IsAdmin, pq.Array(&roles))

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found: %s", email)
	}
	if err != nil {
		return nil, fmt.Errorf("user lookup: %w", err)
	}

	user.Roles = roles
	return &user, nil
}
