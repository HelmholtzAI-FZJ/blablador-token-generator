# Docker Compose

[`docker-compose.yaml`](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/docker-compose.yaml)
runs the application with the hardened PostgreSQL and Redis images on a single
host. It uses the same hardening as the Helm chart (non-root, read-only file
systems, no capabilities, resource limits, TLS between all components) but
does **not** provide public HTTPS or network isolation: put a TLS reverse proxy
in front of it and firewall the host.

The application listens on `127.0.0.1:8080` only.

## Prepare

1. Check out a release tag of this repository; Compose builds the application
   image from it. Build (or pull) the hardened PostgreSQL and Redis images
   (see [Kubernetes](kubernetes.md#1-images)) and note their digests.
2. Create certificates for the services `postgres` and `redis`, signed by a
   CA you control. On Linux, the PostgreSQL key must be readable by UID 70 and
   the Redis key by UID 999 (Compose keeps host file ownership).
3. Write `config.yaml` (production settings, as in the
   [Kubernetes example](kubernetes.md#2-secrets)) with
   `database.ssl_ca_file: /app/tls/postgresql/ca.crt`.
4. Put the secrets into an environment file readable only by you
   (`chmod 600`):

```bash
JWT_SECRET_KEY=<64 hex characters>
TOKEN_HASH_KEY=<64 different hex characters>
POSTGRES_ADMIN_PASSWORD=<hex>
POSTGRES_PASSWORD=<hex, runtime role>
REDIS_PASSWORD=<hex>
DATABASE_URL=postgresql+asyncpg://tokens:<POSTGRES_PASSWORD>@postgres:5432/tokens
RATE_LIMIT_STORAGE_URI=rediss://:<REDIS_PASSWORD>@redis:6379/0?ssl_ca_certs=/app/tls/redis/ca.crt&ssl_cert_reqs=required&ssl_check_hostname=true
POSTGRES_IMAGE=<registry>/blablador-token-generator-postgresql@sha256:<digest>
REDIS_IMAGE=<registry>/blablador-token-generator-redis@sha256:<digest>
POSTGRES_TLS_CERT_FILE=/etc/tokens/tls/postgres.crt
POSTGRES_TLS_KEY_FILE=/etc/tokens/tls/postgres.key
POSTGRES_TLS_CA_FILE=/etc/tokens/tls/ca.crt
REDIS_TLS_CERT_FILE=/etc/tokens/tls/redis.crt
REDIS_TLS_KEY_FILE=/etc/tokens/tls/redis.key
REDIS_TLS_CA_FILE=/etc/tokens/tls/ca.crt
# The reverse proxy's address, if it is not on this host:
# FORWARDED_ALLOW_IPS=192.0.2.10
```

## Run

```bash
docker compose --env-file /etc/tokens/tokens.env up -d
docker compose ps          # all three services become "healthy"
curl -s http://127.0.0.1:8080/readyz
```

On first start, PostgreSQL creates the separate runtime role and refuses
plaintext connections; the application then creates its schema.

## Upgrade

```bash
git fetch --tags && git checkout v1.1.0      # the release to run
docker compose --env-file /etc/tokens/tokens.env up -d --build
```

`--build` rebuilds the application image from the new source; without it the
old build keeps running. Change `POSTGRES_IMAGE`/`REDIS_IMAGE` when their
images change. Database migrations run when the new application starts; read
[Upgrades](../operations/upgrades.md) first.

## Create the first administrator

With OAuth, list your subject in `admin.admin_subjects` and sign in. Without
OAuth (local accounts only):

```bash
docker compose exec app python -m app.manage create-local-admin \
    --email admin@example.org --name "Administrator"
```

## Backups

Compose has no scheduler. Run the same dump the Helm chart uses from cron on
the host, as the runtime role over verified TLS:

```bash
set -a; . /etc/tokens/tokens.env; set +a
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" -e PGSSLMODE=verify-full \
    -e PGSSLROOTCERT=/run/secrets/postgres_ca postgres \
    pg_dump -h postgres -U tokens -d tokens --format=custom > tokens-$(date -u +%Y%m%dT%H%M%SZ).dump
```

Restoring is described in [Backups](../operations/backups.md#restore).
