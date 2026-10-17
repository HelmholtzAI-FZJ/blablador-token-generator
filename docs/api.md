# API reference

All responses are JSON. Errors have the form `{"detail": "<reason>"}`;
request-validation errors (`422`) carry a list of `{"loc", "msg", "type"}`
objects instead. Timestamps are ISO 8601 in UTC with an explicit `+00:00`
offset.

There are three groups of endpoints:

| Group | Authentication | Used by |
| --- | --- | --- |
| [Validation](#validate-a-token) `/api/v1/auth/validate` | the API token itself (`Authorization: Bearer`) | API gateways and services |
| [Token management](#token-management) `/tokens…` | browser session cookie **and** CSRF header | the dashboard |
| [Administration](#administration) `/api/admin/…` | administrator session cookie **and** CSRF header | the admin panel |

An API token cannot be used to manage tokens or accounts.

## Validate a token

```http
POST /api/v1/auth/validate
Authorization: Bearer blablador-6f1c…
```

The scheme name is case-insensitive; no request body is needed and no CSRF
token is involved.

=== "Valid token (200)"

    ```json
    {
      "valid": true,
      "user_id": "0b9a2c1e-5f8d-4c55-9a4e-2c8f0f5b7e11",
      "expires_at": "2027-01-14T21:25:02.399003+00:00",
      "error": null
    }
    ```

    `user_id` is the account's stable internal identifier. `expires_at` is
    `null` only for tokens created before expiry became mandatory.

=== "Invalid token (401)"

    ```http
    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Bearer

    {"detail": "Token not found or revoked"}
    ```

    Other reasons: `No token provided. Use Bearer token.`, `Token has
    expired`, `Token invalid: account has been deleted`.

| Status | Meaning | Gateway should |
| --- | --- | --- |
| `200` with `"valid": true` | Token is valid now | allow |
| `401` | Unknown, revoked, expired or missing token, or deleted account | deny |
| `429` | Rate limit reached (`Retry-After` header) | deny or retry later |
| `413`, `408` | Request body too large or too slow | fix the client |
| `503`, `500` | Service unavailable | **deny** (fail closed), retry with back-off |

Guidance for gateways:

- **Fail closed.** Treat everything except a `200` with `"valid": true` as a
  rejection.
- **Cache briefly, if at all.** A revoked token keeps working for as long as a
  gateway caches the positive answer. Keep any cache to seconds and purge it
  during incident response.
- **Exempt the gateway from IP rate limits.** Validation is limited per client
  address (600 per minute by default). List the gateway's source addresses in
  [`rate_limits.token_validation_exempt`](configuration.md#rate_limits).
- **Never log the token.** Log `user_id` instead.

Example with Python:

```python
import httpx

def token_owner(token: str) -> str | None:
    response = httpx.post(
        "https://tokens.example.org/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if response.status_code == 200 and response.json().get("valid") is True:
        return response.json()["user_id"]
    return None  # fail closed
```

## Token management

These endpoints serve the dashboard. They need the session cookie set at sign-in
and, for anything but `GET`, an `X-CSRF-Token` header equal to the CSRF cookie
(the value is also in the page's `<meta name="csrf-token">`). Without a session
they answer `401`.

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /tokens` | | Your tokens: `id`, `name`, `created_at`, `expires_at`, `last_used_at`, `revoked` |
| `POST /tokens` | `{"name": "...", "expires_in_days": 90}` or `{"name": "...", "expires_at": "<ISO 8601>"}` | The new token **including its value** (`token`), shown only now |
| `POST /tokens/{id}/renew` | optional `expires_in_days` or `expires_at` | New expiry; the value is unchanged. Without a body the original lifetime is applied again |
| `POST /tokens/{id}/rotate` | optional `expires_in_days` or `expires_at` | A new value (`token`); the old value stops working. Keeps the expiry unless given |
| `DELETE /tokens/{id}` | | Revokes the token |
| `DELETE /tokens/{id}/permanent` | | Deletes the token |
| `POST /tokens/revoke-all` | | Revokes all your tokens and ends all your sessions; returns `tokens_revoked` |
| `POST /account/delete` | | Deletes your account and its tokens; it cannot sign in again until an administrator restores it |
| `POST /logout` | | Ends the session (`503` if the revocation could not be stored) |

`expires_in_days` is 1–365 and `expires_at` must lie in the future, within
[`tokens.max_expiration_days`](configuration.md#tokens). Supplying both is an
error. Without either, new tokens get `tokens.default_expiration_days`.

## Administration

Administrator session plus `X-CSRF-Token`, as above. Lists are paged with
`page` (from 1) and `page_size` (1–100, default 20).

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /api/admin/tokens` | | All tokens with owner name and email |
| `DELETE /api/admin/tokens/{id}` | | Revokes a token |
| `DELETE /api/admin/tokens/{id}/permanent` | | Deletes a token |
| `DELETE /api/admin/tokens/revoked` | | Deletes all revoked tokens |
| `GET /api/admin/users` | | Accounts: `id`, `email`, `name`, `is_admin`, `created_at`, `unity_id` (OAuth subject), `has_password` |
| `POST /api/admin/users` | `{"email", "name", "password", "is_admin"}` | Creates a **local** password account |
| `PATCH /api/admin/users/{id}` | any of `name`, `password` (local accounts only), `is_admin` | Updates the account; a password or role change ends its sessions |
| `DELETE /api/admin/users/{id}` | | Deletes the account and its tokens and blocks it from signing in again |
| `POST /api/admin/users/{id}/revoke-credentials` | | Revokes all of the account's tokens and ends its sessions |
| `POST /api/admin/users/restore-oauth` | `{"subject": "<exact OAuth subject>"}` | Lets a deleted OAuth account sign in again (as a new, empty account) |

The last remaining administrator cannot be demoted or deleted. New and reset
passwords need at least 15 characters, at most 72 bytes, and must not be on
the configured block list.

## Health

| Path | Purpose | Response |
| --- | --- | --- |
| `GET /healthz` | Liveness: the process answers | Always `200 {"status": "ok"}` |
| `GET /readyz` | Readiness: the database answers | `200 {"status": "ready", "rate_limit_storage": "ok"}`; `"degraded"` when Redis is unreachable or full (limits then apply per process); `503 {"status": "unavailable"}` when the database is unreachable |

## Rate limits

Limits are counted in Redis, so they hold across workers and replicas. Every
request first passes a per-address admission budget (`rate_limits.preauth`,
240 per minute; token validation has its own, `rate_limits.token_validation`);
routes then apply their own limits. Exceeding a limit answers `429` with
`Retry-After`. IPv6 clients are counted per /64 network, since one host
usually controls a whole /64. All values are
[configurable](configuration.md#rate_limits).

| Budget | Default | Counted per |
| --- | --- | --- |
| Any request except token validation (admission) | 240/minute | client address |
| Pages, sign-in redirect | 120/minute | client address |
| OAuth callback | 60/minute | client address |
| Local password sign-in | 10/minute, and 5/minute per account | client address / account |
| Token reads | 60/minute | user |
| Token changes | 30/minute | user |
| Logout | 30/minute | user |
| Account deletion | 5/minute | user |
| Administration | 120/minute | user |
| Token validation | 600/minute | client address (exempt addresses unlimited) |

Many people can share one address (campus NAT, VPN, a course). If they hit the
per-address limits, raise `preauth` and `pages` rather than disabling limits.
