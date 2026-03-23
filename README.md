# activity-hub-auth

Authentication and authorization library for Activity Hub platform and mini-apps.

## Features

- Token validation (demo-token, guest-token, impersonate-token formats)
- User context management
- Role-based access control (RBAC)
- Admin middleware
- SSE (Server-Sent Events) compatible authentication

## Installation

```bash
go get github.com/achgithub/activity-hub-auth
```

## Usage

### Basic Authentication Middleware

```go
import "github.com/achgithub/activity-hub-auth"

// In your router setup
r.Use(auth.Middleware(identityDB))

// In your handler
user, ok := auth.GetUserFromContext(r.Context())
if !ok {
    // User not authenticated
}
```

### Role-Based Access Control

```go
// Require specific role
r.Use(auth.RequireRole("game_admin"))

// Or in handler
user, _ := auth.GetUserFromContext(r.Context())
if user.HasRole("admin") {
    // User has admin role
}
```

### Admin Middleware

```go
// Require admin privileges
r.Use(auth.AdminMiddleware)
```

### SSE Authentication

```go
// For EventSource endpoints (token in query parameter)
r.HandleFunc("/api/events", handleEvents).Methods("GET")
r.Use(auth.SSEMiddleware(identityDB))
```

### Manual Token Resolution

```go
user, err := auth.ResolveToken(db, token)
if err != nil {
    // Token invalid or expired
}
```

### Generating JWT Tokens

```go
// After successful login/registration
token, err := auth.GenerateJWT(user.Email, user.Name, user.IsAdmin, user.Roles)
if err != nil {
    // Failed to generate token
}

// Return token to client
json.NewEncoder(w).Encode(map[string]interface{}{
    "token": token,
    "user": user,
})
```

### Generating SSE Tokens

For Server-Sent Events (SSE) connections, use short-lived tokens:

```go
// Generate 5-minute SSE token for a specific game session
sseToken, err := auth.GenerateSSEToken(user.Email, "tic-tac-toe", gameID)
if err != nil {
    // Failed to generate SSE token
}

// Return to client
json.NewEncoder(w).Encode(map[string]interface{}{
    "sseToken": sseToken,
    "expiresIn": 300, // 5 minutes
})
```

Client usage:
```javascript
// Request SSE token first
const response = await fetch('/api/sse-token', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${mainJWT}` },
    body: JSON.stringify({ appId: 'tic-tac-toe', gameId: '123' })
});
const { sseToken } = await response.json();

// Use SSE token in EventSource
const eventSource = new EventSource(`/api/game/123/stream?token=${sseToken}`);
```

### Environment Variables

```bash
# JWT secret key (REQUIRED in production, has dev default)
export JWT_SECRET="your-secret-key-here"
```

## Token Formats

### JWT Token (Primary - 24 hours)
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sImV4cCI6MTcwOTQ1OTIwMH0.signature
```
Standard JWT token with email, name, roles, and expiration. Used for all authenticated API calls via Authorization header.

### SSE Token (Short-Lived - 5 minutes)
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJhcHBfaWQiOiJ0aWMtdGFjLXRvZSIsImdhbWVfaWQiOiIxMjMiLCJzY29wZSI6InNzZSIsImV4cCI6MTcwOTQ1OTUwMH0.signature
```
Temporary token specifically for SSE/EventSource connections. Contains app_id, game_id, and scope="sse". Passed via query parameter since EventSource cannot send custom headers.

### Guest Token
```
guest-token-{uuid}
```
Creates an anonymous guest user. No database lookup required.

### Impersonate Token
```
impersonate-{uuid}
```
Requires valid entry in `impersonation_sessions` table with `is_active = true`.

## Database Schema

The library expects the following tables:

### users
```sql
CREATE TABLE users (
    email TEXT PRIMARY KEY,
    name TEXT,
    is_admin BOOLEAN,
    roles TEXT[]
);
```

### impersonation_sessions (for impersonate tokens)
```sql
CREATE TABLE impersonation_sessions (
    impersonation_token TEXT PRIMARY KEY,
    impersonated_email TEXT,
    super_user_email TEXT,
    is_active BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Mini-App Integration

Mini-app backends should import and use this library for consistent authentication:

```bash
go get github.com/achgithub/activity-hub-auth
```

Then in your mini-app's main.go:

```go
import auth "github.com/achgithub/activity-hub-auth"

// Apply auth middleware
r.Use(auth.Middleware(identityDB))
```

## License

MIT
