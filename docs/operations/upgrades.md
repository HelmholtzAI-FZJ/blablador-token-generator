# Upgrades and migrations

## Before every upgrade

1. Read the [changelog](../changelog.md), especially *Upgrade notes*.
2. Take a database backup and make sure `token_hash_key` is backed up
   ([Backups](backups.md)).
3. Check the new images' scan results.

## Rolling out

With Helm, change the image digests and run `helm upgrade`
([details](../deployment/kubernetes.md#upgrading)). With Compose, change the
image references and run `docker compose up -d`.

The schema is managed with [Alembic](https://alembic.sqlalchemy.org)
migrations in `app/migrations/`. With `database.auto_migrate: true` (the
default) the first new process applies pending migrations at startup while
holding a PostgreSQL advisory lock; other processes wait and then start
normally. The log shows:

```text
WARNING token_generator.audit action=schema_migrated from=0001 to=0002
```

Migrations are written so the previous release keeps working while they run
(new indexes are built `CONCURRENTLY`). Check the state at any time:

```bash
kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate check
kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate current
```

### Migrating separately

If schema changes must not run from application pods (for example to apply
them in a maintenance window), set `database.auto_migrate: false`. Startup then
refuses an outdated schema, and you run `python -m app.migrate` with the new
image and the same configuration before the rollout, for example as a one-off
Kubernetes Job that uses the chart's Secrets and volumes.

### Rolling back

Migrations only move forward in operation. To return to an older release
after a migration ran, restore the backup taken before the upgrade.

## Databases from before version 1.0

- **Created by `create_all` since October 2026** (no `alembic_version`
  table): adopted automatically at revision `0001` when all expected tables and
  columns exist, then migrated. The log shows `action=schema_adopted`.
- **Older schemas** (August 2026 releases and earlier) are refused with a list
  of the differences rather than failing at request time. The project history
  records no production data from those releases; if you have such a database,
  start with a new one and ask users to create new tokens.

### PostgreSQL volumes from older charts

Volumes initialised before the hardened chart may have a runtime role with
superuser rights and accept plaintext connections. Production startup refuses
such a role. Initialisation scripts never run on an existing volume, so fix it
once, as a separate administrator:

```sql
ALTER ROLE tokens NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER SCHEMA public OWNER TO tokens;
REVOKE ALL ON DATABASE tokens FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

and put these lines at the top of `pg_hba.conf`, then reload PostgreSQL and
confirm that a plaintext connection is refused:

```text
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::/0 reject
```

### Tokens without an expiry

Tokens created before expiry became mandatory have none and stay valid until
revoked. Find them and ask their owners to rotate them:

```sql
SELECT t.id, t.name, u.email, t.created_at FROM tokens t JOIN users u ON u.id = t.user_id
 WHERE t.expires_at IS NULL AND t.revoked_at IS NULL;
```
