# Security Audit — Token Generator

Last full audit: 2026-08-23. All fixes are committed individually on `main`.

## Endpoint Inventory

### Public (no auth)
| Method | Endpoint                 | Rate limit | Notes                              |
|--------|--------------------------|------------|------------------------------------|
| GET    | `/`                      | 30/min     | Home page                          |
| GET    | `/login`                 | 30/min     | OAuth redirect (sets state cookie) |
| GET    | `/oauth/openid/callback` | 10/min     | OAuth callback (state-verified)    |
| GET    | `/login/local`           | 30/min     | Local login form                   |
| POST   | `/login/local`           | 5/min      | Local login (CSRF-protected)       |
| POST   | `/logout`                | 10/min     | POST + CSRF (was a GET — fixed)    |

### Authenticated user (JWT cookie)
| Method | Endpoint                 | Rate limit |
|--------|--------------------------|------------|
| GET    | `/dashboard`             | 60/min     |
| POST   | `/tokens`                | 30/min     |
| GET    | `/tokens`                | 60/min     |
| DELETE | `/tokens/{id}`           | 30/min     |
| DELETE | `/tokens/{id}/permanent` | 30/min     |
| POST   | `/tokens/{id}/renew`     | 30/min     |

### Admin (JWT + `is_admin`)
| Method | Endpoint                       | Rate limit |
|--------|--------------------------------|------------|
| GET    | `/admin/tokens` (HTML)         | 60/min     |
| GET    | `/api/admin/tokens`            | 60/min     |
| DELETE | `/api/admin/tokens/{id}`       | 60/min     |
| DELETE | `/api/admin/tokens/{id}/permanent` | 60/min |
| DELETE | `/api/admin/tokens/revoked`    | 60/min     |
| GET    | `/api/admin/users`             | 60/min     |
| POST   | `/api/admin/users`             | 60/min     |
| PATCH  | `/api/admin/users/{id}`        | 60/min     |
| DELETE | `/api/admin/users/{id}`        | 60/min     |

### Token validation (bearer)
| Method | Endpoint                | Rate limit |
|--------|-------------------------|------------|
| POST   | `/api/v1/auth/validate` | 30/min     |

## Hardening applied (summary across both audit passes)

- **JWT secret**: rejected weak/short secrets at startup (min 32 chars).
- **CSRF**: double-submit cookie, `SameSite=strict`; state-changing routes
  (incl. `/logout`) require the `X-CSRF-Token` header. Constant-time compare.
- **Rate limiting**: every endpoint has a limit; per-IP via slowapi.
- **Cookies**: `HttpOnly`, `SameSite=strict`, `Secure` (configurable);
  session cookie TTL now derives from `jwt_expiration_hours`.
- **XSS**: `escapeHtml` on user-controlled values in dashboard + admin templates.
- **Input bounds**: bearer token capped at 256 chars (header + body);
  admin search capped at 128; `expires_at` parsed with error handling (400, not 500).
- **Token storage**: HMAC-SHA256 keyed hash (not plain SHA256).
- **DB failure handling**: commit/rollback with friendly 500 on all mutating paths.
- **Last-admin guard**: cannot demote or delete the last remaining admin.
- **Deletion tombstone**: deleted users are recorded in `deleted_users` so OAuth
  login cannot silently resurrect them; explicit admin re-creation lifts it.
- **No implicit admin demotion**: login only *promotes* via `admin_emails` config;
  it never demotes, so manual grants survive login.
- **Secrets**: never logged; DB file chmod 600 (SQLite); env override for secrets.

## Testing

Run: `pytest -q`. Security-focused tests live in `tests/test_security.py`:
JWT secret, CSRF, security headers, timing-safe compare, commit-error handling,
XSS, rate limits, last-admin guard, deletion tombstone, no-demotion-on-login.
