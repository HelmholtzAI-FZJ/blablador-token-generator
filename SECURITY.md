# Security Audit — Token Generator

Last full audit: 2026-10-09. All fixes are committed individually on `main`.

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
| POST   | `/account/delete`        | 5/min      |  ← self-service account deletion |

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
| POST   | `/api/v1/auth/validate` | configurable (default 600/min) |

## Hardening applied (summary across both audit passes)

- **JWT secret**: rejected weak/short secrets at startup (min 32 chars).
- **CSRF**: double-submit cookie, `SameSite=lax`; state-changing routes
  (incl. `/logout`) require the `X-CSRF-Token` header. Only `/login/local`
  accepts a form-field token, and only `/api/v1/*` skips CSRF for Bearer
  requests. Constant-time compare.
- **Rate limiting**: every endpoint has a limit; per-IP via slowapi. The client
  IP comes from `X-Forwarded-For` only when sent by `FORWARDED_ALLOW_IPS`
  (set it to the ingress controller's pod CIDR).
- **Cookies**: `HttpOnly`, `SameSite=lax`, `Secure` (configurable, on by default in Helm);
  session cookie TTL now derives from `jwt_expiration_hours`.
- **XSS**: `escapeHtml` (quotes included) on user-controlled values; values used
  by inline handlers go through `data-*` attributes. CSP header set.
- **OAuth account linking**: an email match is only linked to an account with no
  OAuth identity yet; emails flagged `email_verified: false` are never trusted
  for linking, admin promotion or email updates.
- **Container**: non-root user, locked + hash-verified dependencies.
- **Input bounds**: bearer token capped at 256 chars (header + body);
  admin search capped at 128; `expires_at` parsed with error handling (400, not 500).
- **Token storage**: HMAC-SHA256 keyed with `token_hash_key`, separate from the
  JWT `secret_key`, so rotating the session key keeps API tokens valid.
- **DB failure handling**: commit/rollback with friendly 500 on all mutating paths.
- **Session invalidation**: session JWTs carry the user's `session_epoch`; an
  admin password reset or admin-role change bumps it, ending all existing
  sessions of that user immediately.
- **Last-admin guard**: cannot demote or delete the last remaining admin.
- **Deletion tombstone**: deleted users are recorded in `deleted_users` so OAuth
  login cannot silently resurrect them; explicit admin re-creation lifts it.
- **No implicit admin demotion**: login only *promotes* via `admin_emails` config;
  it never demotes, so manual grants survive login.
- **Login timing equalized**: unknown users still trigger a bcrypt check against
  a dummy hash, so response time does not leak whether an email exists.
- **Self-service account deletion**: `POST /account/delete` (requires JWT session)
  revokes all tokens, writes a tombstone, deletes the account, and revokes the
  current session JWT.  Rate-limited to 5/min to prevent abuse.
- **Deleted-user token rejection**: if a token is validated after its owner's
  account was deleted, the request is rejected with `401 Token invalid: account
  has been deleted` and the attempt is logged as `revoked_token_used_by_deleted_account`
  so stale token usage is detectable.
- **Secrets**: never logged; DB file chmod 600 (SQLite); env override for secrets.

## Open items (2026-10-09 audit)

- Verify what Unity-IDM asserts in `email`/`email_verified`. If users can set an
  unverified email, an admin-created local account (no `unity_id`) can still be
  linked by an OAuth user presenting that email, and `admin_emails` promotion
  is only as strong as the IdP's email verification.
- Rate limits are in-memory, per worker and per pod (`replicaCount: 2`, 2
  workers), so effective limits are ~4x the configured value. Use a shared
  storage backend (Redis) for slowapi.
- SQLite on a `ReadWriteOnce` PVC with `replicaCount: 2`: the second pod cannot
  mount the volume on another node, and concurrent writers will hit locks. Use
  PostgreSQL or a single replica.

## Testing

Run: `pytest -q`. Security-focused tests live in `tests/test_security.py`:
JWT secret, CSRF, security headers, timing-safe compare, commit-error handling,
XSS, rate limits, last-admin guard, deletion tombstone, no-demotion-on-login,
login timing equalization, self-delete (revokes tokens), deleted-user token
rejection with audit log.
