# Monitoring and logging

## Health endpoints

| Endpoint | Use for | Notes |
| --- | --- | --- |
| `GET /healthz` | Liveness | Constant `200`; does not touch dependencies. |
| `GET /readyz` | Readiness and external probes | `503` when the database does not answer within `app.readiness_timeout_seconds`. Returns `"rate_limit_storage": "degraded"` while Redis is unreachable; the service keeps serving with per-process limits, so this does **not** fail readiness. |

Kubernetes probes are set up by the chart; probe `/readyz` from outside too,
through the ingress.

## Logs

The application writes to standard error, one line per event:

```text
2026-10-16 21:36:00,192 INFO token_generator.audit user=0b9a… action=create_token token_id=5c1e… expires_at=2026-10-23T21:36:00+00:00
2026-10-16 21:36:00,207 INFO token_generator.access method=POST route=/api/v1/auth/validate status=200 duration_ms=5.8 client=10.42.0.17
```

Messages are `key=value` pairs, easy to parse in Loki, Elasticsearch or
similar.

| Logger | Content |
| --- | --- |
| `token_generator.audit` | Security events: sign-ins, token and account changes, administration, failures. Always kept at `INFO`. |
| `token_generator.account` | Account deletions. Always kept at `INFO`. |
| `token_generator.access` | One line per request (except `/healthz`, `/readyz`): method, route template, status, duration, client address. Disable with `app.access_log: false`. |
| `uvicorn.error` | Server start and stop. |

What is never logged: token values, passwords, session cookies, query strings
(they carry OAuth authorization codes), raw request paths of unmatched routes,
SQL parameters and exception messages. Some administration events contain
email addresses; client addresses appear in the access log. Choose retention
and access rights accordingly.

The application cannot control what your ingress, proxies or APM agents log:
configure them not to record `/oauth/openid/callback` query strings or
`Authorization` and `Cookie` headers.

## Events

| Event (`action=`) | Level | Meaning |
| --- | --- | --- |
| `startup` | INFO | Process started; includes `version`. |
| `schema_migrated`, `schema_adopted` | WARNING | Database schema changed or pre-1.0 database adopted. |
| `login` | INFO | Successful sign-in (`method=oauth` or `local`). |
| `login_failed` | WARNING | Wrong local email or password; includes the client address. |
| `oauth_authorization_failed` | WARNING | Sign-in cancelled or refused at the identity provider (`error=` code). |
| `oauth_authentication_failed`, `oauth_provider_failed` | WARNING/ERROR | Code exchange rejected, or the identity provider failed or timed out. |
| `oauth_account_created` | INFO | First sign-in of a new account; `is_admin` shows bootstrap grants. |
| `oauth_disabled_account_observed` | WARNING | A deleted account signed in during its deletion; clean up the row. |
| `logout`, `session_revoked` | INFO | Session ended. |
| `session_revocation_failed` | ERROR | A logout could not be stored; the session may still be valid. |
| `create_token`, `renew_token`, `rotate_token`, `revoke_token`, `delete_token`, `revoke_all_credentials` | INFO | Token lifecycle (`user=` is the actor). |
| `create_user`, `update_user`, `delete_user`, `revoke_user_credentials`, `restore_oauth_identity`, `delete_revoked_tokens` | INFO | Administrator actions (`admin=` is the actor). |
| `create_local_admin`, `grant_admin` | INFO | Command-line actions (`actor=cli`). |
| `account_deleted` | INFO | Self-service account deletion. |
| `revoked_token_used_by_deleted_account` | WARNING | A token of a deleted account was presented. |
| `admission_storage_failed`, `admission_storage_recovered` | ERROR/WARNING | Redis lost / back; limits were per process in between. |
| `readiness_degraded` | WARNING | `/readyz` found Redis unreachable. |
| `readiness_failed` | ERROR | `/readyz` found the database unreachable. |
| `login_storage_failed` | ERROR | Local password sign-in refused because Redis is unreachable. |
| `token_usage_update_failed` | WARNING | A token's *last used* time could not be written; validation still succeeded. |
| `request_failed` | ERROR | Unexpected error; the client got `500`. Includes route and exception type. |

## Alerts

A good starting set:

| Alert on | Why |
| --- | --- |
| `/readyz` failing, or `request_failed` / `5xx` in the access log | The service cannot serve. |
| `"rate_limit_storage": "degraded"` or `admission_storage_failed` | Redis is down; rate limits are weaker until it is back. |
| `session_revocation_failed` | A logout or containment did not take effect. |
| Spikes of `login_failed`, `oauth_authentication_failed`, `oauth_provider_failed` or `status=429` | Password guessing, identity provider problems, or a NAT exceeding limits. |
| Any `grant_admin`, `update_user … is_admin=True`, `oauth_account_created … is_admin=True`, `restore_oauth_identity` | Changes to who holds privileges. |
| `oauth_disabled_account_observed` | Needs manual cleanup. |
| The container risk assessments expiring (CI fails on 2026-11-10) | Images need a fresh review. |

There are no built-in metrics; request rates, error rates and latencies come
from the access log (`status`, `duration_ms`, `route`).
