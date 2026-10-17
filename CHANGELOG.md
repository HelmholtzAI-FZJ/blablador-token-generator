# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] - 2026-10-16

First production release. It contains the remediation of the October 2026
security audit ([report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT.md)) and the production
hardening listed below.

### Upgrade notes

- **Schema migrations.** The schema is now managed with Alembic. The service
  migrates at startup (set `database.auto_migrate: false` to run
  `python -m app.migrate` yourself). Databases created by `create_all` since
  October 2026 are adopted automatically; older schemas are refused with an
  explanation. Back up the database first.
- **PostgreSQL and Redis are required in production**, both over verified TLS.
  The chart no longer accepts `latest` images, wildcard proxy trust, missing
  NetworkPolicy peers or missing TLS/credential Secrets.
- **Redis outages no longer fail readiness.** `/readyz` only requires the
  database and reports `"rate_limit_storage": "degraded"` when Redis is
  unreachable; alert on that and on `action=admission_storage_failed`.
- API responses now carry timestamps with an explicit `+00:00` offset.
- The chart's startup probe now allows 180 seconds (`startupProbe`), enough for
  a pod to wait for another pod's migration; migration connections wait up
  to 30 seconds for locks.

### Added

- Alembic migrations (`app/migrations`) with automatic, lock-protected
  startup migration and a `python -m app.migrate [upgrade|check|current]`
  command.
- Operator commands: `python -m app.manage create-local-admin` and
  `grant-admin`, for deployments without OAuth and for regaining
  administrator access.
- Access log: one line per request with route template, status, duration and
  client address; never query strings (`app.access_log`).
- Admin UI: grant or remove administrator rights, OAuth subjects shown for
  each account, paging through all tokens.
- Credential containment: rotate a token, revoke all of one's own tokens and
  sessions, administrator revocation of another account's credentials,
  restoration of a disabled OAuth subject.
- Helm: optional nightly PostgreSQL backups (`postgresql.backup`), graceful
  rollouts (`shutdownDelaySeconds`, `terminationGracePeriodSeconds`), a
  disruption budget, a values schema and CI values.
- Container images carry OCI labels (source, version, revision).
- Documentation website (`docs/`, published with GitHub Pages).

### Changed

- The service keeps serving when Redis is unavailable: admission falls back to
  per-process limits and retries Redis every 5 seconds. The per-account local
  password limiter still fails closed. This deliberately reverses the audit's
  fail-closed choice; see [Security](https://helmholtzai-fzj.github.io/blablador-token-generator/security/#deliberate-changes-since-the-audit).
- The validation API (`/api/v1/`) never needs a CSRF token; a call without a
  bearer token gets `401` with `WWW-Authenticate: Bearer`, and the scheme is
  matched case-insensitively.
- Failed sign-ins (cancelled at the identity provider, expired state, disabled
  account, provider outage) and unknown pages show an HTML page with the right
  status instead of JSON.
- Dependencies updated (FastAPI 0.143, Starlette 1.8, Pydantic 2.14,
  SQLAlchemy 2.1, Uvicorn 0.54).

### Fixed

- Dashboard and admin pages showed times shifted by the viewer's UTC offset.
- `/login` redirected to a broken URL when no OAuth client was configured.
- `uv sync` failed because setuptools found several top-level packages.
- The image build pinned an exact Debian package version, which breaks as
  soon as Debian publishes the next security update.

### Security

- All findings of the October 2026 audit (F01-F34) are fixed in code,
  deployment templates and tests; see the [report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT.md)
  for what still needs evidence from the real environment.

[1.0.0]: https://github.com/HelmholtzAI-FZJ/blablador-token-generator/releases/tag/v1.0.0
