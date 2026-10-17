# Blablador Token Generator

[![CI](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/actions/workflows/ci.yml)
[![Documentation](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/actions/workflows/docs.yml/badge.svg)](https://helmholtzai-fzj.github.io/blablador-token-generator/)

The Token Generator issues the API tokens people use to call
[Blablador](https://helmholtz-blablador.fz-juelich.de), the LLM service of
Helmholtz AI at Forschungszentrum Jülich. People sign in with JSC Login
(Unity-IDM, OAuth 2.0), create personal tokens on a dashboard, and the Blablador
API gateway checks each presented token with this service.

**Documentation: <https://helmholtzai-fzj.github.io/blablador-token-generator/>**

## Quick start

```bash
uv sync --frozen --all-extras
cp config.yaml.example config.yaml     # then follow the getting-started guide
./start.sh development                 # http://127.0.0.1:8080
```

[Getting started](https://helmholtzai-fzj.github.io/blablador-token-generator/getting-started/)
explains the development configuration and how to create the first
administrator (`python -m app.manage create-local-admin`).

## Validating a token

```bash
curl -X POST https://tokens.example.org/api/v1/auth/validate \
     -H "Authorization: Bearer blablador-…"
# 200 {"valid": true, "user_id": "…", "expires_at": "…+00:00", "error": null}
# 401 for unknown, revoked or expired tokens
```

See the [API reference](https://helmholtzai-fzj.github.io/blablador-token-generator/api/).

## Deployment

Production runs on Kubernetes with the Helm chart in
[`helm/blablador-token-generator`](helm/blablador-token-generator): the
application, a hardened PostgreSQL and Redis, all over verified TLS, with
network policies and optional nightly backups. Docker Compose is supported for
single hosts. Start with the
[production checklist](https://helmholtzai-fzj.github.io/blablador-token-generator/deployment/checklist/).

Images for the production cluster live in the JSC registry
(`registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/`). Tagged releases
are built, scanned and published by CI to `ghcr.io/helmholtzai-fzj/`, and to
the JSC registry when its credentials are configured.

## Development

```bash
uv run pytest                     # tests (SQLite; set TEST_DATABASE_URL for PostgreSQL)
uv run --only-group lint ruff check .  # lint
uv run --only-group docs mkdocs serve
```

Schema changes are Alembic migrations in `app/migrations/`; see
[Development](https://helmholtzai-fzj.github.io/blablador-token-generator/development/).
Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
The October 2026 security audit, with its threat model, control inventory and
evidence, is in [`security_audit/`](security_audit/REPORT.md).
