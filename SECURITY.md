# Security — Token Generator

Last full audit: 2026-10-09. All fixes are committed individually on `main`.

## Endpoint Inventory

Rate limits come from the `rate_limits` config section (defaults shown).
Unauthenticated endpoints are limited per client IP, authenticated ones per
signed-in user, so many users behind one NAT address do not share a budget.

### Public (no auth)
| Method | Endpoint                 | Limit (key)                 | Notes                                   |
|--------|--------------------------|-----------------------------|-----------------------------------------|
| GET    | `/`                      | `pages` 120/min (IP)        | Home page                               |
| GET    | `/login`                 | `pages` 120/min (IP)        | OAuth redirect; state + PKCE cookies    |
| GET    | `/oauth/openid/callback` | `oauth_callback` 60/min (IP)| Checks state, sends PKCE verifier       |
| GET    | `/login/local`           | `pages` 120/min (IP)        | Local login form                        |
| POST   | `/login/local`           | `local_login` 10/min (IP)   | Form CSRF field, bcrypt                 |
| GET    | `/healthz`               | none                        | Liveness/readiness probe                |
| GET    | `/static/*`              | none                        | Page scripts                            |

### Authenticated user (session cookie)
| Method | Endpoint                 | Limit (key)                    |
|--------|--------------------------|--------------------------------|
| GET    | `/dashboard`             | `pages` 120/min (user)         |
| POST   | `/tokens`                | `tokens_write` 30/min (user)   |
| GET    | `/tokens`                | `tokens_read` 60/min (user)    |
| DELETE | `/tokens/{id}`           | `tokens_write` 30/min (user)   |
| DELETE | `/tokens/{id}/permanent` | `tokens_write` 30/min (user)   |
| POST   | `/tokens/{id}/renew`     | `tokens_write` 30/min (user)   |
| POST   | `/logout`                | `session` 30/min (user)        |
| POST   | `/account/delete`        | `account_delete` 5/min (user)  |

### Admin (session cookie + `is_admin`)
| Method | Endpoint                           | Limit (key)            |
|--------|------------------------------------|------------------------|
| GET    | `/admin/tokens` (HTML)             | `admin` 120/min (user) |
| POST   | `/admin/tokens/search` (HTML form) | `admin` 120/min (user) |
| GET    | `/api/admin/tokens`                | `admin` 120/min (user) |
| DELETE | `/api/admin/tokens/revoked`        | `admin` 120/min (user) |
| DELETE | `/api/admin/tokens/{id}`           | `admin` 120/min (user) |
| DELETE | `/api/admin/tokens/{id}/permanent` | `admin` 120/min (user) |
| GET    | `/api/admin/users`                 | `admin` 120/min (user) |
| POST   | `/api/admin/users`                 | `admin` 120/min (user) |
| PATCH  | `/api/admin/users/{id}`            | `admin` 120/min (user) |
| DELETE | `/api/admin/users/{id}`            | `admin` 120/min (user) |

### Token validation (bearer)
| Method | Endpoint                | Limit (key)                                                        |
|--------|-------------------------|--------------------------------------------------------------------|
| POST   | `/api/v1/auth/validate` | `token_validation` 600/min (IP); `token_validation_exempt` CIDRs unlimited |

## Controls

### Authentication and sessions
- **OAuth**: authorization code flow with `state` and PKCE (S256). Accounts
  are identified by the OAuth subject only; the asserted email is profile
  data and never links, blocks or collides with another account.
- **Admin promotion**: `admin_subjects` (preferred) or `admin_emails` when the
  provider sends `email_verified: true` (or `oauth.trust_provider_emails`).
  Login only promotes, never demotes.
- **Local accounts**: admin-created, unique lower-cased email, bcrypt, 8-72
  bytes with mixed case and digits. Password login is refused for accounts
  with an OAuth subject, and admins cannot give them a password. Unknown
  users still cost a bcrypt check (no timing oracle).
- **Session JWT**: HS256 with `secret_key` (≥32 chars, not a known default),
  `exp`/`sub` required, `jti` revocation on logout (expired entries purged),
  and a per-user `session_epoch` bumped on password or role changes.
- **Cookies**: `HttpOnly`, `SameSite=Lax`, `Secure` and `__Host-` prefixed by
  default (`secure_cookies: true`), so other `*.fz-juelich.de` hosts cannot
  plant or overwrite them. Set `secure_cookies: false` only for local http.

### Request handling
- **CSRF**: double-submit token. The HttpOnly cookie and the
  `<meta name="csrf-token">` value come from the same middleware decision;
  state-changing requests need the `X-CSRF-Token` header, except the two
  HTML forms (`/login/local`, `/admin/tokens/search`) that check a form
  field. Only `/api/v1/*` accepts Bearer requests without CSRF.
- **Comparisons**: secrets are compared in constant time on bytes (non-ASCII
  input is rejected, not a crash).
- **Body size**: bodies over `app.max_body_bytes` (64 KiB) are rejected with
  413 before parsing; the ingress allows 64k.
- **Rate limiting**: counters in Redis, shared by workers and replicas; if
  Redis is unreachable each process falls back to in-memory counters.
  Client IPs come from `X-Forwarded-For` only from `forwardedAllowIps`,
  which the Helm chart requires.
- **Headers**: CSP `script-src 'self'` (no inline scripts or handlers;
  enforced by a test), `frame-ancestors 'none'`, `form-action 'self'`,
  `object-src 'none'`, `base-uri 'none'`; HSTS; `nosniff`; `X-Frame-Options:
  DENY`; `Cache-Control: no-store` on everything but `/static`.
- **Output encoding**: Jinja autoescaping; scripts use `escapeHtml` and
  `data-*` attributes for user-controlled values.

### Tokens and data
- **API tokens**: 256-bit random (`token_length_bytes` ≥ 16 enforced),
  stored as HMAC-SHA256 with `token_hash_key` (separate from `secret_key`;
  never change it). At most `max_tokens_per_user` (100) per user.
- **Admin token search** is a POST form; plaintext tokens never appear in
  URLs, logs or the rendered page.
- **Deletion**: admin and self-service deletion remove the user, their tokens
  and revoked-session rows (FK cascades). A tombstone with keyed hashes of the
  subject/email (no plaintext) blocks the same identity from coming back
  until an admin re-creates the account.
- **Logs**: an audit log (`token_generator.audit`, `app.log_level`) records
  logins, failed local logins, token changes and admin actions without
  secrets. SQL parameters are never logged (`hide_parameters`).

### Deployment and supply chain
- **Image**: multi-stage, base and uv pinned by digest, locked hash-verified
  dependencies, only `app/` copied (allowlist `.dockerignore`), non-root.
- **Helm**: PostgreSQL (required for >1 replica) and Redis, non-root with
  read-only root filesystems, no service-account tokens, NetworkPolicies
  letting only the app reach them; secrets and `forwardedAllowIps` required.
- **CI**: tests on SQLite and PostgreSQL, pip-audit, Trivy image scan;
  actions pinned by SHA; Dependabot for uv, Docker and actions.

## Open items

- **Old OAuth client credentials on GitHub**: the original first commit
  (`9884d14`) with a `config.yaml` containing an OAuth client secret is still
  served by GitHub by hash. The credential has been rotated; ask GitHub
  Support to purge the unreferenced commits, and delete local
  `refs/original/*` backups.
- **No TLS to PostgreSQL/Redis inside the cluster**: mitigated by the
  NetworkPolicies and passwords.
- **App NetworkPolicy is off by default**: enable `networkPolicy.app` with
  the ingress controller and gateway as peers once those are known.
- **No schema migrations**: schema changes need a fresh database (fine
  before go-live; add Alembic before the first change after it).

## Testing

`pytest -q` runs against `tests/config.test.yaml` and a throwaway SQLite
database; set `TEST_DATABASE_URL` to run against PostgreSQL. Security tests
live in `tests/test_security.py` and `tests/test_secure_cookies.py` (the
latter boots the app with production cookie settings).
