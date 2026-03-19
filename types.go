package auth

// AuthUser represents an authenticated user
type AuthUser struct {
	Email           string
	Name            string
	IsAdmin         bool
	Roles           []string
	IsImpersonating bool
	ImpersonatedBy  string // email of the super_user who started the session
}

// HasRole reports whether the user has the given role.
func (u *AuthUser) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Context key for storing authenticated user
type contextKey string

const userContextKey = contextKey("user")
