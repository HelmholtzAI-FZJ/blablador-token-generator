# Token Generator Service

A token-based authentication infrastructure that works on top of Unity-IDM. Users authenticate via Unity-IDM OAuth2, then create and manage API tokens for their applications.

## Features

- **Unity-IDM OAuth2 Authentication** - Users log in through your institution's Unity-IDM
- **Token Management** - Create, list, and revoke API tokens
- **Token Display Once** - Tokens are shown only once at creation time for security
- **Secure Storage** - Tokens are stored as SHA-256 hashes, never in plain text
- **Token Validation API** - Validate tokens from client applications
- **Admin Panel** - Administrators can view all tokens with user information

## Requirements

- Python 3.11+
- Unity-IDM OAuth2 endpoint (e.g., `https://unity-jsc.fz-juelich.de`)

## Installation

```bash
# Create virtual environment
uv venv

# Install dependencies
uv pip install -e .
```

## Configuration

Edit `config.yaml` with your Unity-IDM OAuth2 settings:

```yaml
app:
  host: "0.0.0.0"
  port: 8080
  secret_key: "your-secure-secret-key"
  token_hash_key: "a-different-secure-key"  # hashes stored API tokens

database:
  url: "sqlite+aiosqlite:///./tokens.db"

oauth:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  authorize_url: "https://unity-jsc.fz-juelich.de/oauth/authorize"
  token_url: "https://unity-jsc.fz-juelich.de/oauth/token"
  userinfo_url: "https://unity-jsc.fz-juelich.de/oauth/userinfo"
  redirect_uri: "http://localhost:8080/callback"
  scopes:
    - "openid"
    - "profile"
    - "email"

tokens:
  default_expiration_days: 365
  token_length_bytes: 32

admin:
  admin_emails:
    - "admin@example.com"
```

## Usage

### Development
```bash
# Start the server (single worker)
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### Production
```bash
# Start with multiple workers (recommended for high traffic)
uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4

# Or use all available CPU cores
uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers $(nproc)

# With systemd (see start.sh for more options)
./start.sh production
```

Then open http://localhost:8080 in your browser.

## Configuration

Edit `config.yaml`:

```yaml
app:
  name: "Token Generator"          # App display name
  api_url: "http://your-domain.com"  # Public URL for API examples
  host: "0.0.0.0"
  port: 8080
  secret_key: "your-secure-secret-key"
  token_hash_key: "a-different-secure-key"  # hashes stored API tokens

login:
  name: "JSC Login"                          # Login button text
  description: "Authenticate to create..."   # Home page description

oauth:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  authorize_url: "https://login.example.com/oauth2-as/oauth2-authz"
  token_url: "https://login.example.com/oauth2/token"
  userinfo_url: "https://login.example.com/oauth2/userinfo"
  redirect_uri: "http://your-domain.com/oauth/openid/callback"
  scopes:
    - "openid"
    - "profile"
    - "email"

admin:
  admin_emails:
    - "admin@example.com"
```

## API Endpoints

### Validate Token (Bearer token)

```bash
curl -X POST https://your-domain.com/api/v1/auth/validate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Response (valid):
```json
{
  "valid": true,
  "user_id": "user-123",
  "username": "jdoe",
  "email": "jdoe@example.com",
  "name": "John Doe",
  "expires_at": "2026-03-05T00:00:00+00:00"
}
```

Response (invalid):
```json
{
  "valid": false,
  "error": "Token not found or revoked"
}
```

## Deployment

### Docker

```bash
# Build the image
docker build -t blablador-token-generator:latest .

# Run with config mount
docker run -v /path/to/config.yaml:/app/config/config.yaml -p 8080:8080 blablador-token-generator:latest
```

Or using docker-compose:

```bash
# Edit config.yaml first, then
docker-compose up -d
```

docker-compose runs the app with PostgreSQL (volume `postgres-data`) and Redis; secrets come from a `.env` file next to `docker-compose.yaml`.

### Kubernetes (Helm Chart)

Deploy to Kubernetes with the Helm chart; there are no separate raw manifests.

```bash
# Install with custom values
cd helm/blablador-token-generator

# Option 1: Set values via command line
helm install token-generator . \
  --set config.app.secret_key=$(openssl rand -hex 32) \
  --set config.app.token_hash_key=$(openssl rand -hex 32) \
  --set postgresql.password=$(openssl rand -hex 32) \
  --set redis.password=$(openssl rand -hex 32) \
  --set forwardedAllowIps=<ingress-controller-pod-cidr> \
  --set config.oauth.client_id=your-client-id \
  --set config.oauth.client_secret=your-secret \
  --set config.oauth.redirect_uri=https://your-domain/oauth/openid/callback \
  --set config.admin.admin_emails[0]=admin@example.com \
  --set config.admin.admin_emails[1]=another-admin@example.com

# Option 2: Create values file
cp values.yaml values-production.yaml
# Edit values-production.yaml with your config
helm install token-generator -f values-production.yaml .
```

The Helm chart generates a Kubernetes Secret from the `config.*` values in `values.yaml`.

By default the chart deploys PostgreSQL (StatefulSet with its own volume) and Redis for shared rate-limit counters, with NetworkPolicies that only let the app reach them. Setting `postgresql.enabled: false` falls back to SQLite on a PersistentVolumeClaim, which only supports `replicaCount: 1`.

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## License

MIT