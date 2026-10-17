# Upgrades and migrations

## Before every upgrade

1. Read the [changelog](../changelog.md), especially *Upgrade notes*.
2. Take a database backup and make sure `token_hash_key` is backed up
   ([Backups](backups.md)).
3. Check the new images' scan results.

## Rolling out

With Helm, change the image digests and run `helm upgrade`
([details](../deployment/kubernetes.md#upgrading)). With Compose, check out the
new release and run `docker compose up -d --build`
([details](../deployment/docker-compose.md#upgrade)).

The schema is managed with [Alembic](https://alembic.sqlalchemy.org)
migrations in `app/migrations/`. With `database.auto_migrate: true` (the
default) the first new process applies pending migrations at startup while
holding a PostgreSQL advisory lock; other processes wait and then start
normally. Processes whose schema is already current start without the lock.
The log shows:

```text
WARNING token_generator.audit action=schema_migrated from=0001 to=0002
```

Migrations are written so the previous release keeps working while they run
(new indexes are built `CONCURRENTLY`). A starting pod waits up to 120 seconds
for another pod's migration and the chart's startup probe allows 180 seconds;
migration statements may run for 120 seconds and wait 30 seconds for locks. If
the wait times out, the error names the server process holding the lock
(`pg_stat_activity` shows it; migration sessions are called
`token-generator-migrate` and send keepalives, so the lock of a migrator on a
lost node is released within about a minute). Allow only the application's
roles to connect to its database, since any session could take the lock.
If a release notes a long migration, run it separately (below). Check the
state at any time:

```bash
kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate check
kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate current
```

### Migrating separately

If schema changes must not run from application pods (for example to apply
them in a maintenance window), set `database.auto_migrate: false`. Startup then
refuses an outdated schema, and you run `python -m app.migrate` with the new
image and the same configuration before the rollout, for example as a one-off
Kubernetes Job that uses the chart's Secrets and volumes. Give its pod the
labels of the backup job's pods (`app.kubernetes.io/name:
<release>-blablador-token-generator-postgresql-backup`,
`app.kubernetes.io/instance: <release>`), which the network policies let reach
PostgreSQL. Do not copy the application's labels: such a pod would also
receive the application's traffic from its Service.

### Rolling back

Migrations only move forward in operation. A release refuses to start on a
schema migrated by a newer release (the error says so). After a migration
ran, roll forward with a fixed release, or restore the backup taken before
the upgrade, which undoes every security action since
([Backups](backups.md#restore)).

## Databases from before version 1.0

- **Created by `create_all` since October 2026** (no `alembic_version`
  table): adopted automatically at revision `0001` when the schema matches
  this release (tables, columns, types, indexes, unique and foreign-key
  constraints; only the indexes revision `0002` adds may be missing), then
  migrated. The log shows `action=schema_adopted`.
- **Older schemas** (August 2026 releases and earlier, including ones whose
  missing columns were added by hand) are refused with a list of the
  differences rather than failing at request time. The project history
  records no production data from those releases; if you have such a
  database, start with a new one and ask users to create new tokens.

### PostgreSQL volumes from older charts

Volumes initialised before the hardened chart use `tokens` as both the
runtime role and the bootstrap superuser, and accept plaintext connections.
Production startup refuses such a role, and PostgreSQL cannot take superuser
rights from its bootstrap role. Initialisation scripts never run on an
existing volume, so move the application to a new runtime role once, inside
the database pod (`kubectl exec -it <release>-blablador-token-generator-postgresql-0
-- psql -U tokens -d tokens`):

```sql
CREATE ROLE tokens_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password tokens_app
ALTER SCHEMA public OWNER TO tokens_app;
DO $$
DECLARE item record;
BEGIN
  FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO tokens_app', item.tablename);
  END LOOP;
END $$;
REVOKE ALL ON DATABASE tokens FROM PUBLIC;
GRANT CONNECT ON DATABASE tokens TO tokens_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
```

Then set `postgresql.username: tokens_app` and `postgresql.adminUsername:
tokens` (the existing superuser, with its current password as the
administrator password), put the new password and a matching `database-url`
in the credentials Secret, and upgrade.

Finally put these lines at the top of `pg_hba.conf` (the first rejects
network logins of the administrator, the others plaintext connections), run
`SELECT pg_reload_conf();`, and confirm that both are refused:

```text
host all tokens all reject
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::/0 reject
```

The same three lines, with the administrator's name, apply to volumes created
by the October 2026 chart, whose administrator could still sign in over the
network.

### Tokens without an expiry

Tokens created before expiry became mandatory have none and stay valid until
revoked. Find them and ask their owners to rotate them:

```sql
SELECT t.id, t.name, u.email, t.created_at FROM tokens t JOIN users u ON u.id = t.user_id
 WHERE t.expires_at IS NULL AND t.revoked_at IS NULL;
```
