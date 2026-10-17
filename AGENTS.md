# Agent Guidelines for Token Generator

This document provides guidelines for agentic coding agents working on this codebase.

## Project Overview

Token authentication service built with FastAPI and SQLAlchemy. Users authenticate via OAuth2 (Unity-IDM/JSC Login), then create/manage API tokens for their applications.

## Build, Test, and Development Commands

### Setup

```bash
# Install the locked dependencies (uv)
uv sync --frozen --all-extras
source .venv/bin/activate
```

### Running the Application

```bash
# Development (with auto-reload)
./start.sh development

# Production (multiple workers)
./start.sh production
```

### Testing

```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_api.py

# Run a single test
pytest tests/test_api.py::TestValidateEndpoint::test_validate_valid_token

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=app --cov-report=html
```

Run the suite against PostgreSQL too when touching queries, locking or
migrations (tests create and drop tables, so use a disposable database):

```bash
TEST_DATABASE_URL=postgresql+asyncpg://postgres:postgres@127.0.0.1:55432/tokens pytest
```

HTTP tests must use `with TestClient(app) as client:` (asyncpg connections are
bound to one event loop).

### Linting and other checks

```bash
uv run --only-group lint ruff check .
python helm/blablador-token-generator/tests/security_render.py
uv run --only-group docs mkdocs build --strict
```

## Code Style Guidelines

### General Principles

- Write clean, readable code over clever code
- Keep functions small and focused (single responsibility)
- Use descriptive variable and function names
- Comment complex logic, not obvious code
- No comments unless absolutely necessary (per project convention)

### Python Conventions

- Use Python 3.11+ type hints
- Use async/await for all I/O operations (database, HTTP calls)
- Use f-strings for string formatting
- Use dataclasses/Pydantic models for data structures
- Follow PEP 8 for formatting

### Imports

Organize imports in this order (per PEP 8):

```python
# Standard library
import uuid
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager

# Third-party
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# Local application
from app.config import get_config
from app.database import get_db
from app.models import User, Token
from app.auth import get_current_user
```

### Naming Conventions

- **Files**: `snake_case.py` (e.g., `auth.py`, `token_utils.py`)
- **Classes**: `PascalCase` (e.g., `User`, `Token`, `OAuthConfig`)
- **Functions/variables**: `snake_case` (e.g., `get_current_user`, `token_hash`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_TOKEN_LENGTH`)
- **Database tables**: `snake_case` plural (e.g., `users`, `tokens`)

### Type Hints

Use type hints for all function signatures:

```python
# Good
async def create_token(name: str, user_id: str, db: AsyncSession) -> Token:
    ...

# Avoid
async def create_token(name, user_id, db):
    ...
```

Use Pydantic models for configuration:

```python
class AppConfig(BaseModel):
    name: str = "Token Generator"
    port: int = 8080
```

### Database (SQLAlchemy)

Use the new SQLAlchemy 2.0 style with Declarative Base:

```python
class User(Base):
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    tokens: Mapped[list["Token"]] = relationship(back_populates="user")
```

Always use async sessions:

```python
async def get_db():
    async with async_session_maker() as session:
        yield session
```

Schema changes need an Alembic migration (`app/migrations/versions/`); the
service applies them at startup. Generate one with
`APP_ENVIRONMENT=development alembic revision --autogenerate --rev-id 000N -m "..."`,
keep it compatible with the previous release during a rolling upgrade, and let
`tests/test_migrations.py` confirm that migrations and models agree.

Query with async/await:

```python
result = await db.execute(select(User).where(User.id == user_id))
user = result.scalar_one_or_none()
```

### Error Handling

- Use HTTPException for HTTP errors (FastAPI)
- Return appropriate HTTP status codes (401 for auth failures, 404 for not found, etc.)
- Never expose internal errors to clients - log internally, return user-friendly messages
- Validate input data with Pydantic models

```python
# Good
if not user:
    raise HTTPException(status_code=404, detail="User not found")

# Authentication failure
raise HTTPException(
    status_code=401,
    detail="Invalid token",
    headers={"WWW-Authenticate": "Bearer"},
)
```

### FastAPI Routes

Define routes with clear separation of concerns:

```python
# Use separate routers for different domains
# app/api/tokens.py - token management
# app/api/validate.py - token validation
# app/api/admin.py - admin operations
```

Use dependency injection for authentication and database:

```python
@router.get("/tokens")
async def list_tokens(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    ...
```

### Templates (Jinja2)

Templates are in `app/templates/`. Use consistent HTML structure and CSS classes matching the existing style (see `dashboard.html` and `admin.html`).

- Use semantic HTML
- Follow existing CSS class patterns (`.btn`, `.card`, `.form-group`)
- Keep JavaScript inline for simple interactions, extract to separate file for complex logic

### Configuration

All configuration is in `config.yaml` - never hardcode values.

```python
from app.config import get_config

config = get_config()
app_name = config.app.name
```

### Security

- Never log secrets or tokens
- Hash tokens before storing (use `hash_token()`)
- Use HTTP-only cookies for authentication
- Validate all user input
- Use parameterized queries (SQLAlchemy does this automatically)

## Container Registry

The container registry for this project is:

```
registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/blablador-token-generator
```

Build and push with:

```bash
docker build -t registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/blablador-token-generator:latest .
docker push registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/blablador-token-generator:latest
```

## Project Structure

```
token_generator/
├── app/
│   ├── main.py          # FastAPI app, pages, OAuth flow, middleware setup
│   ├── auth.py          # OAuth, sessions (JWT), passwords, token hashing
│   ├── config.py        # Configuration model and production checks
│   ├── database.py      # Engine, locking helpers, startup
│   ├── migrate.py       # Migration runner: python -m app.migrate
│   ├── migrations/      # Alembic environment and revisions
│   ├── manage.py        # Operator commands: python -m app.manage
│   ├── models.py        # User, Token, RevokedJWT, DeletedUser
│   ├── tombstones.py    # Deletion records (keyed hashes)
│   ├── admission.py, body_limit.py, error_safety.py,
│   │   security_headers.py, access_log.py   # ASGI middleware
│   ├── api/
│   │   ├── tokens.py    # /tokens: create, list, renew, rotate, revoke
│   │   ├── validate.py  # POST /api/v1/auth/validate
│   │   └── admin.py     # /api/admin: tokens and users
│   ├── templates/       # Jinja2 HTML templates
│   └── static/          # Page scripts (no inline JavaScript: CSP)
├── tests/               # pytest suite
├── docs/, mkdocs.yml    # Documentation website (GitHub Pages)
├── helm/                # Helm chart, hardened datastore images, chart tests
├── security_audit/      # October 2026 audit record
├── config.yaml          # Local configuration (NOT in git)
├── config.yaml.example  # Configuration template
├── CHANGELOG.md
├── Dockerfile
└── docker-compose.yaml
```

## Key Files to Know

- `app/main.py`: Main application, pages, OAuth flow, middleware order
- `app/auth.py`: Authentication, JWT sessions, token hashing
- `app/models.py`: SQLAlchemy models; change only together with a migration
- `app/api/tokens.py`: User token endpoints
- `app/api/validate.py`: Token validation API used by the Blablador gateway
- `app/templates/dashboard.html`, `app/static/dashboard.js`: User dashboard
- `app/templates/admin.html`, `app/static/admin.js`: Admin panel
- `docs/`: User, deployment and operations documentation

## Testing Patterns

Tests use pytest with async support:

```python
@pytest.mark.asyncio
async def test_something(test_db, test_user):
    # test_db is an in-memory SQLite database
    # test_user is a pre-created test user fixture
    result = await some_function(user_id=test_user.id, db=test_db)
    assert result is expected
```

See `tests/conftest.py` for available fixtures.

## Common Tasks

### Adding a new API endpoint

1. Add route in appropriate file (`app/api/*.py`)
2. Use dependency injection for auth/db
3. Return Pydantic response models
4. Add tests in `tests/`

### Adding a new template

1. Create HTML in `app/templates/`
2. Use Jinja2 syntax
3. Follow existing CSS patterns
4. Add JavaScript inline or in existing script blocks

### Modifying configuration

1. Add the field to the Pydantic model in `app/config.py`
2. Add it to `config.yaml.example`, the Helm `values.yaml` and `values.schema.json`
3. Document it in `docs/configuration.md` (a test checks every field is listed)

### Changing the database schema

1. Change `app/models.py`
2. Generate and review a migration (see Database above)
3. Run the tests on SQLite and PostgreSQL

### Releasing

Update `CHANGELOG.md` and the version (`pyproject.toml`, `app/__init__.py`,
chart `appVersion`), merge, then push a `vX.Y.Z` tag; the release workflow
builds, scans and publishes the images and the chart.