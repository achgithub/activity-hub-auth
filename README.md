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

## Token Formats

### Demo Token
```
demo-token-user@example.com
```
Resolves to the user record in the database.

### Guest Token
```
guest-token-{uuid}
```
Creates an anonymous guest user.

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
