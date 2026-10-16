# Token Generator Service

FastAPI/SQLAlchemy authentication infrastructure for Unity-IDM/JSC Login. Users create, list, renew, rotate and revoke opaque API tokens. Administrators provision local accounts, manage roles, restore disabled OAuth subjects and revoke all credentials during incidents.

Tokens appear once at creation/rotation and persist only as HMAC-SHA256 digests. Sessions use HttpOnly host cookies, CSRF, durable revocation and account epochs. OAuth identity binds to a fixed provider subject, never email. Configured admins bootstrap new accounts; existing roles change through explicit administrative operations.

Release documentation includes the [security audit](security_audit/REPORT.md), [complete control inventory](security_audit/CONTROLS.md) and [operations guide](security_audit/OPERATIONS.md).

## Setup and configuration

Use a current security patch release of Python 3.11+ and the frozen lockfile. The production container uses Python 3.12.15:

```bash
uv sync --frozen --all-extras
```

Copy `config.yaml.example` to protected `config.yaml` and supply required values; its secrets are deliberately empty. `CONFIG_PATH` selects a different file. Overrides: `JWT_SECRET_KEY`, `TOKEN_HASH_KEY`, `OAUTH_CLIENT_SECRET`, `DATABASE_URL`, `DATABASE_SSL_CA_FILE`, `RATE_LIMIT_STORAGE_URI`.

Production is default and requires distinct random signing/HMAC keys, secure cookies, HTTPS public/provider/redirect URLs, complete confidential OAuth or configured local authentication, verified PostgreSQL TLS and shared verified Redis TLS. Register the exact `/oauth/openid/callback` URI. Never replace the HMAC key without the documented token/tombstone migration plan.

Intentional development permits SQLite/memory storage and plain HTTP with secure cookies explicitly disabled. The launcher selects environment mode. Local authentication is optional and only for admin-provisioned accounts; there is no public registration. Newly set passwords need 15 characters, a common-password check and at most 72 UTF-8 bytes. Legacy hashes remain compatible.

```bash
./start.sh development
HOST=127.0.0.1 PORT=8080 WORKERS=2 ./start.sh production
```

The launcher defaults to loopback, preserves overrides and validates worker/port counts. A configured HTTPS proxy supplies public transport. Trust only its actual source addresses through `FORWARDED_ALLOW_IPS`; wildcard production trust is rejected. Supported launchers disable Uvicorn callback-query access logging; configure safe edge logging separately.

## API

```bash
curl -X POST https://tokens.example.com/api/v1/auth/validate \
  -H 'Authorization: Bearer YOUR_API_TOKEN'
```

Successful response:

```json
{"valid":true,"user_id":"internal-user-id","expires_at":"2026-12-01T00:00:00+00:00","error":null}
```

Invalid/revoked/expired credentials return 401. Management requires session+CSRF, not an API bearer token. Unauthenticated API/unsafe requests return 401; browser navigation can redirect to login.

| Operation | Endpoint |
| --- | --- |
| Create/list tokens | `POST /tokens`, `GET /tokens` |
| Revoke/delete | `DELETE /tokens/{id}`, `DELETE /tokens/{id}/permanent` |
| Extend lifetime with same secret | `POST /tokens/{id}/renew` |
| Replace secret; display once | `POST /tokens/{id}/rotate` |
| Revoke own tokens and sessions | `POST /tokens/revoke-all` |
| Contain another account | Admin `POST /api/admin/users/{id}/revoke-credentials` |
| Restore disabled OAuth subject | Admin `POST /api/admin/users/restore-oauth`, JSON `{"subject":"exact-subject"}` |
| Liveness/readiness | `GET /healthz`, `GET /readyz` |

The UI exposes rotation, containment and restoration. Use rotation/revocation for exposure response; renewal retains the secret. Password/role changes invalidate sessions; incident containment also revokes API tokens. IdP disable/logout does not automatically revoke independently issued tokens: connect organizational offboarding to containment/deletion.

## Production deployment

Follow [the chart guide](helm/blablador-token-generator/README.md) and [security operations](security_audit/OPERATIONS.md). Build app plus hardened PostgreSQL/Redis images, publish through the authorized workflow and deploy reviewed registry manifest digests. Project registry: `registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/blablador-token-generator`.

Helm requires explicit images, TLS/credential Secrets, trusted forwarding and ingress/egress peers. Defaults enforce hardened runtime and reject production transport/storage/network downgrades. Compose binds to loopback, uses constrained-role/ACL initialization and requires reviewed datastore images and certificates; it supplies neither a public HTTPS proxy nor Kubernetes isolation.

Existing PostgreSQL volumes need explicit role/password migration. Schema changes are Alembic migrations in `app/migrations/`; the service applies pending ones at startup under a PostgreSQL advisory lock (set `database.auto_migrate: false` to run them separately). Databases created before migrations existed are adopted automatically when their tables match the first revision:

```bash
uv run --no-sync python -m app.migrate check    # exit 1 unless the schema is current
uv run --no-sync python -m app.migrate          # apply pending migrations
```

Back up the database before upgrading. Runtime is a constrained schema owner; bundled stores are single replicas. Select external HA where required.

## Verification

```bash
env -u TEST_DATABASE_URL uv run --no-sync pytest -q
uv run --no-sync python helm/blablador-token-generator/tests/security_render.py
uv run --no-sync python helm/blablador-token-generator/tests/container_risk_gate.py --self-test
```

Tests force synthetic keys/config and use disposable SQLite. Set `TEST_DATABASE_URL` only to a disposable PostgreSQL database: tests create/drop tables. CI tests both engines, audits frozen production dependencies, builds/scans all three images, preserves all-severity scans/SBOMs and gates unreviewed HIGH/CRITICAL findings. Exact expiring workload assessments do not hide the full inventory.
