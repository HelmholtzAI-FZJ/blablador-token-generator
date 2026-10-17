# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] - 2026-10-16

First production release. It contains the remediation of the October 2026
security audit ([report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT.md)), the production
hardening listed below, and the fixes of a follow-up security audit
([report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT-2026-10-17.md)).

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
- **Redis 8.** The hardened Redis image is based on Redis 8.10 (Alpine 3.23)
  instead of 7.4 (Alpine 3.21, end of support 2026-11-01). Redis holds only
  rate-limit counters, which reset on the switch.
- **Stricter production checks.** `FORWARDED_ALLOW_IPS` and
  `token_validation_exempt` must be addresses or networks written without
  host bits and at most `/8` wide; database and Redis URLs must not repeat a
  query parameter; the database role must not be able to read all data,
  call server-file functions or change server parameters. Fix such settings
  before upgrading, or startup refuses them.
- **Chart.** The chart `version` now equals the release version. Unknown
  top-level values are refused, and `shutdownDelaySeconds` must be at least
  5 seconds shorter than `terminationGracePeriodSeconds`.
- **PostgreSQL administrator.** New volumes accept the administrator only
  inside the database pod; the restore procedure runs that step with
  `kubectl exec`. For existing volumes, see the
  [upgrade guide](https://helmholtzai-fzj.github.io/blablador-token-generator/operations/upgrades/#postgresql-volumes-from-older-charts).
- **Docker Compose.** The application sits on a fixed `edge` network whose
  gateway is the trusted proxy (`FORWARDED_ALLOW_IPS` default
  `172.30.240.1`), and PostgreSQL and Redis on an internal network. If you
  set `FORWARDED_ALLOW_IPS` yourself, check that the access log shows
  clients' addresses.
- **Local accounts** are refused while `local.enabled` is false.
- **Releases** are made from tags on commits of `main` whose CI passed; the
  publishing jobs use the `release` environment (add reviewers there).

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
- Follow-up audit (F35-F69, none critical or high); see its
  [report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT-2026-10-17.md).
  Among the fixes:
  - Releases publish exactly the scanned images: built once without caches
    by a job without credentials, scanned per architecture, pushed by a
    separate job; tags only from `main` after CI; no overwriting.
  - A hung Redis no longer causes bursts of 503 for users, the gateway and
    readiness; a full Redis shows as degraded.
  - Docker Compose behind a host proxy no longer puts every client into one
    rate-limit budget.
  - The Redis TLS check could be bypassed with repeated URL parameters; the
    database role check missed whole-cluster and server-file privileges;
    proxy trust accepted entries that Uvicorn ignores or that trust everyone.
  - NUL characters no longer cause errors on PostgreSQL; names refuse
    invisible formatting characters.
  - WebSocket handshakes (unlimited, logged with query strings) are refused;
    FastAPI's own tracing, which records OAuth codes, is off.
  - The last-administrator rule counts only administrators who can sign in.
  - Migrations start without the schema lock when nothing is pending, and
    adopt old databases only when their schema matches.
  - The backup job retries until the database is reachable and deletes only
    its own dumps; long release names no longer break the database pod.
  - Fuller audit trail, safer restore and upgrade procedures.

[1.0.0]: https://github.com/HelmholtzAI-FZJ/blablador-token-generator/releases/tag/v1.0.0
