# Development

## Layout

```text
app/
  main.py            routes for pages, sign-in, logout; middleware setup
  auth.py            OAuth, sessions, passwords, token hashing
  api/               token management, validation and administration APIs
  config.py          configuration model and production checks
  database.py        engine, locking helpers, startup
  migrate.py         schema migration runner and CLI
  migrations/        Alembic environment and revisions
  manage.py          operator commands
  admission.py, body_limit.py, error_safety.py,
  security_headers.py, access_log.py   ASGI middleware
  templates/, static/  pages and their scripts (no inline JavaScript)
tests/               pytest suite
helm/                Helm chart, hardened datastore images, chart tests
docs/                this documentation (MkDocs)
security_audit/      October 2026 audit record
```

## Tests and checks

```bash
uv sync --frozen --all-extras
uv run pytest                                   # SQLite
uvx ruff@0.17.1 check .                         # lint
uv run python helm/blablador-token-generator/tests/security_render.py
uv run python helm/blablador-token-generator/tests/container_risk_gate.py --self-test
```

The tests use their own configuration (`tests/config.test.yaml`), synthetic
keys and a throwaway SQLite database. To run them against PostgreSQL, point
`TEST_DATABASE_URL` at a **disposable** database (tests create and drop
tables):

```bash
docker run -d --rm --name tg-test-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=tokens \
    -p 127.0.0.1:55432:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql+asyncpg://postgres:postgres@127.0.0.1:55432/tokens uv run pytest
```

HTTP tests use `with TestClient(app) as client:` so that one event loop
serves the whole test; asyncpg connections cannot move between loops.

## Changing the database schema

1. Change the models in `app/models.py`.
2. Generate a revision with the next number and review it:

    ```bash
    APP_ENVIRONMENT=development uv run alembic revision --autogenerate --rev-id 0003 -m "describe the change"
    ```

3. Make it safe for a rolling upgrade: the previous release must keep working
   while the migration runs and until all pods are replaced. Add columns as
   nullable or with a server default, build indexes `CONCURRENTLY` inside
   `op.get_context().autocommit_block()` on PostgreSQL, and remove columns
   only in a later release.
4. `tests/test_migrations.py` fails until the migrations produce exactly the
   models' schema; run it on both SQLite and PostgreSQL.

## Continuous integration

Every push and pull request runs:

- lint (ruff), a JavaScript syntax check and a lockfile check;
- the test suite on SQLite and on PostgreSQL 16;
- `pip-audit` on the locked production dependencies;
- the Helm render tests, `helm lint`, and Kubernetes schema validation of the
  rendered chart;
- builds of the application, PostgreSQL and Redis images with a full
  vulnerability scan and SBOM each, failing on high or critical findings that
  have no current [risk assessment](security.md#security-audit);
- a strict documentation build.

Dependabot proposes updates for Python packages, base images and actions every
week.

## Releases

1. Update `CHANGELOG.md` and the version in `pyproject.toml`,
   `app/__init__.py` and the chart's `appVersion` (a test checks they agree);
   bump the chart `version` when the chart changed.
2. Merge to `main`, then tag: `git tag -s v1.0.0 -m "v1.0.0" && git push origin v1.0.0`.

The release workflow then builds the three images for `linux/amd64` and
`linux/arm64`, scans them, pushes them to
`ghcr.io/helmholtzai-fzj/blablador-token-generator{,-postgresql,-redis}` with
SBOM and provenance attestations, publishes the chart to
`oci://ghcr.io/helmholtzai-fzj/charts`, and creates a GitHub release with the
changelog section and the image digests. If the repository secrets
`JSC_REGISTRY_USER` and `JSC_REGISTRY_TOKEN` are set, the images are also
pushed to `registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/`.

## Documentation

```bash
uv run --only-group docs mkdocs serve      # http://127.0.0.1:8000
```

Pushes to `main` that touch `docs/`, `mkdocs.yml` or `CHANGELOG.md` publish
the site to GitHub Pages.
