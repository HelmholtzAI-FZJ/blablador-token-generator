# Getting started

This page runs the service on your machine in **development mode**: SQLite
instead of PostgreSQL, in-process rate-limit counters instead of Redis, plain
HTTP on `localhost`. For anything shared with other people, follow the
[production checklist](deployment/checklist.md) instead.

## Requirements

- Python 3.11 or newer (the container image uses 3.12)
- [uv](https://docs.astral.sh/uv/)
- git

## Install

```bash
git clone https://github.com/HelmholtzAI-FZJ/blablador-token-generator.git
cd blablador-token-generator
uv sync --frozen --all-extras
```

`--frozen` installs exactly the versions in `uv.lock`.

## Configure

Create `config.yaml` in the repository root (it is git-ignored). Generate the
two keys once and keep them: the token key hashes stored API tokens, so
changing it invalidates every token.

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'   # run twice
```

```yaml
app:
  environment: development
  secret_key: "<first random value>"      # signs browser sessions
  token_hash_key: "<second random value>" # hashes stored API tokens
  api_url: "http://localhost:8080"
  secure_cookies: false                   # browsers drop Secure cookies on plain http
database:
  url: "sqlite+aiosqlite:///./tokens.db"
local:
  enabled: true                           # password accounts; no identity provider needed
```

Every setting is described in the [configuration reference](configuration.md).

## Create an administrator

There is no public registration. Create the first administrator from the
command line; it asks for the password twice (at least 15 characters):

```bash
APP_ENVIRONMENT=development uv run python -m app.manage \
    create-local-admin --email you@example.org --name "Your Name"
```

## Start

```bash
./start.sh development
```

Open <http://127.0.0.1:8080>, choose **Local Login** and sign in. The
dashboard creates tokens; **Admin Panel** lists all tokens and accounts.

Try a token against the validation API:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/validate \
     -H "Authorization: Bearer blablador-…"
```

The database schema is created and migrated automatically at startup.

## Sign in with JSC Login (optional)

To test the real OAuth flow, register a client with the identity provider
whose redirect URI is `http://localhost:8080/oauth/openid/callback`, then add:

```yaml
oauth:
  client_id: "<client id>"
  client_secret: "<client secret>"
  authorize_url: "https://login.jsc.fz-juelich.de/oauth2-as/oauth2-authz"
  token_url: "https://login.jsc.fz-juelich.de/oauth2/token"
  userinfo_url: "https://login.jsc.fz-juelich.de/oauth2/userinfo"
  redirect_uri: "http://localhost:8080/oauth/openid/callback"
  scopes: ["openid", "profile", "email"]
admin:
  admin_subjects: ["<your subject>"]   # administrator on first sign-in
```

Your subject is shown next to your account in the admin panel's **Users** tab
once you have signed in; [Administration](operations/administration.md)
explains how administrator rights are granted.

## Next steps

- [Development](development.md): tests, linting, writing migrations.
- [User guide](user-guide.md): what the dashboard does.
- [Production checklist](deployment/checklist.md): everything a real
  deployment needs.
