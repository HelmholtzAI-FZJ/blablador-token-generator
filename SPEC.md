# Token Authentication Infrastructure Specification

## 1. Project Overview

**Project Name:** Token Generator Service  
**Type:** Web Application (FastAPI)  
**Core Functionality:** A token-based authentication infrastructure that sits on top of Unity-IDM. Users authenticate via Unity-IDM OAuth2, then create/manage API tokens for their applications.  
**Target Users:** Researchers and developers who need API tokens for automated access to infrastructure.

---

## 2. Functionality Specification

### 2.1 Authentication Flow

1. User visits the web application
2. User clicks "Login with Unity-IDM"
3. Redirect to Unity-IDM OAuth2 authorization endpoint
4. After successful login, user is redirected back with authorization code
5. Exchange code for access token + refresh token
6. Store user session (JWT cookie)

### 2.2 Token Management (User Features)

**Create Token:**
- User provides a token name/description
- System generates a cryptographically secure random token (32 bytes, hex-encoded = 64 chars)
- Token is stored with: token_hash, name, user_id, created_at, expires_at (optional), last_used_at (optional)
- Token is displayed ONCE to user after creation (copy it or lose it)
- Token is never stored in plain text (store SHA-256 hash only)

**List Tokens:**
- User can see all their tokens (name, created_at, last_used_at, expires_at)
- Cannot see the actual token value (only hash)

**Revoke/Delete Token:**
- User can delete any of their tokens
- Deleted tokens are immediately invalidated

### 2.3 Token Validation (API for Client Apps)

**Validate Endpoint:** `POST /api/v1/auth/validate`
- Request body: `{ "token": "<token_value>" }`
- Response (valid): `{ "valid": true, "user_id": "user123", "expires_at": "2025-01-01T00:00:00Z" }`
- Response (invalid): `{ "valid": false, "error": "Token not found or revoked" }`

**Token format:** 64-character hex string (SHA-256 of 32 random bytes)

### 2.4 Admin Features

- Admin logs in via Unity-IDM (with admin role)
- Admin can view all tokens in the system
- Admin sees: token name, user_id, user email, created_at, last_used_at, expires_at
- Admin can revoke any token (but cannot see the actual token value)

### 2.5 Data Model

```
Users table:
- id (UUID, PK)
- unity_id (string, from Unity-IDM)
- email (string)
- name (string)
- is_admin (boolean)
- created_at (timestamp)

Tokens table:
- id (UUID, PK)
- user_id (UUID, FK)
- token_hash (string, SHA-256 of token)
- name (string)
- created_at (timestamp)
- expires_at (timestamp, nullable)
- last_used_at (timestamp, nullable)
- revoked_at (timestamp, nullable)
```

### 2.6 Configuration

All configuration via `config.yaml`:
- Unity-IDM OAuth2 settings (client_id, client_secret, authorize_url, token_url, userinfo_url)
- Database connection (SQLite for simplicity, or PostgreSQL)
- Application settings (host, port, secret_key)
- Token settings (expiration days, token length)

---

## 3. Technical Stack

- **Framework:** FastAPI (Python)
- **Database:** SQLite (simple) or PostgreSQL
- **Authentication:** OAuth2 with Unity-IDM
- **Token Storage:** SHA-256 hashed (never plain text)
- **Session:** JWT tokens in HTTP-only cookies

---

## 4. API Endpoints

### Public
- `GET /` - Home page (login button or dashboard)
- `GET /login` - Redirect to Unity-IDM OAuth
- `GET /callback` - OAuth callback handler

### Protected (User)
- `GET /dashboard` - User dashboard with token list
- `POST /tokens` - Create new token
- `DELETE /tokens/{token_id}` - Delete/revoke token

### Protected (API for client apps)
- `POST /api/v1/auth/validate` - Validate a token

### Protected (Admin)
- `GET /admin/tokens` - List all tokens (admin only)

---

## 5. Acceptance Criteria

1. User can log in via Unity-IDM OAuth2
2. User can create a token and see it once
3. User can list their tokens (without seeing the actual token)
4. User can delete/revoke their tokens
5. Client applications can validate tokens via API
6. Admin can view all tokens with user information
7. Tokens are stored as hashes, never in plain text
8. Configuration is externalized to config.yaml