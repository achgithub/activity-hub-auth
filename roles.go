package auth

import "strings"

// TabAccessConfig defines the tab-based role hierarchy for an app
// Tabs are ordered left-to-right, with leftmost tabs having most privileges
// Having a role grants access to that tab and all tabs to its right
type TabAccessConfig struct {
	AppID string
	Tabs  []string // Ordered left-to-right: ["setup", "games", "reports"]
}

// HasTabAccess checks if user has access to a specific tab based on role hierarchy
//
// Convention:
//   - Tabs are ordered left-to-right from most privileged to least
//   - Role format: "app:tabname" (e.g., "lms:setup", "lms:games")
//   - Having "app:tabname" grants access to that tab + all tabs to the right
//   - Special role "app:all" grants access to all tabs
//
// Example (LMS):
//
//	tabs := []string{"setup", "games", "reports"}
//	lms:setup  → Can access all 3 tabs
//	lms:games  → Can access games + reports
//	lms:reports → Can access reports only
//	lms:all    → Can access all tabs
func (u *AuthUser) HasTabAccess(appID string, tabName string, tabOrder []string) bool {
	// Check for wildcard role
	if u.HasRole(appID + ":all") {
		return true
	}

	// Find position of requested tab
	requestedTabPos := -1
	for i, tab := range tabOrder {
		if tab == tabName {
			requestedTabPos = i
			break
		}
	}

	// Tab not found in order - deny access
	if requestedTabPos == -1 {
		return false
	}

	// Check if user has role for this tab or any tab to its left
	// Left tabs have more privileges and grant access to right tabs
	for i := 0; i <= requestedTabPos; i++ {
		role := appID + ":" + tabOrder[i]
		if u.HasRole(role) {
			return true
		}
	}

	return false
}

// HasAnyRole checks if user has any of the specified roles
func (u *AuthUser) HasAnyRole(roles []string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if user has all of the specified roles
func (u *AuthUser) HasAllRoles(roles []string) bool {
	for _, role := range roles {
		if !u.HasRole(role) {
			return false
		}
	}
	return true
}

// HasAppRole checks for app-specific role (allows partial match)
// hasAppRole("admin") will match "chess:admin" if user is in chess app context
func (u *AuthUser) HasAppRole(appID, rolePattern string) bool {
	// Check exact role with app prefix
	fullRole := appID + ":" + rolePattern
	if u.HasRole(fullRole) {
		return true
	}

	// Check if any role ends with the pattern (for wildcard matching)
	suffix := ":" + rolePattern
	for _, role := range u.Roles {
		if strings.HasSuffix(role, suffix) {
			return true
		}
	}

	return false
}

// GetAccessibleTabs returns list of tabs the user can access for an app
func (u *AuthUser) GetAccessibleTabs(appID string, tabOrder []string) []string {
	accessible := []string{}

	for _, tab := range tabOrder {
		if u.HasTabAccess(appID, tab, tabOrder) {
			accessible = append(accessible, tab)
		}
	}

	return accessible
}

// IsActivityHubAdmin checks if user has Activity Hub admin privileges
// Admin = has any ah_g_* group OR ah_r_user_manage OR ah_r_app_control
func (u *AuthUser) IsActivityHubAdmin() bool {
	// Check for any group membership (ah_g_*)
	for _, role := range u.Roles {
		if strings.HasPrefix(role, "ah_g_") {
			return true
		}
	}

	// Check for specific admin roles
	return u.HasAnyRole([]string{"ah_r_user_manage", "ah_r_app_control"})
}
