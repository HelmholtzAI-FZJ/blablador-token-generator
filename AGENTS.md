# Agent Guidelines for Token Generator

This document provides guidelines for agentic coding agents working on this codebase.

## Project Overview

Token authentication service built with FastAPI and SQLAlchemy. Users authenticate via OAuth2 (Unity-IDM/JSC Login), then create/manage API tokens for their applications.

## Build, Test, and Development Commands

### Setup

```bash
# Install dependencies (use uv - already configured in project)
cd /Users/surak/Devel/blablador/token_generator
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

### Linting/Type Checking

```bash
# If ruff is available
ruff check app/

# If mypy is available
mypy app/
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
│   ├── main.py          # FastAPI app, routes, templates
│   ├── auth.py          # OAuth2, JWT, authentication
│   ├── config.py        # Configuration loader
│   ├── database.py      # SQLAlchemy setup
│   ├── models.py        # User, Token models
│   ├── api/
│   │   ├── tokens.py    # POST/GET/DELETE /tokens
│   │   ├── validate.py  # POST /api/v1/auth/validate
│   │   └── admin.py     # Admin endpoints
│   └── templates/       # Jinja2 HTML templates
├── tests/               # pytest test suite
├── config.yaml          # Configuration (NOT in git)
├── config.yaml.example  # Configuration template
├── Dockerfile
├── docker-compose.yaml
└── helm/                # Helm chart
```

## Key Files to Know

- `app/main.py`: Main application, routes, OAuth flow
- `app/auth.py`: Authentication, JWT, token hashing
- `app/models.py`: SQLAlchemy models (User, Token)
- `app/api/tokens.py`: User token CRUD endpoints
- `app/api/validate.py`: Token validation API
- `app/templates/dashboard.html`: User dashboard UI
- `app/templates/admin.html`: Admin panel UI

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

1. Edit `config.yaml.example` with new values
2. Add to `app/config.py` as Pydantic model
3. Document in README if user-facing