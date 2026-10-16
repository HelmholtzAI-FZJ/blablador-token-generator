# Security operations and production release

> Audit-time record. Day-to-day procedures, updated for the 1.0.0 release (automatic schema migrations instead of `app.migrate_token_owner_index`, backups, operator commands), are in the [operations documentation](https://helmholtzai-fzj.github.io/blablador-token-generator/operations/administration/).

Reviewed 2026-10-12. These procedures accompany [REPORT.md](REPORT.md). The audit executed only isolated verification; real deployment and migration require the authorized release process.

## Configuration and release

Use `config.yaml.example` as a schema reference. Its empty credentials intentionally cannot start production. Prefer externally managed Secrets; required Secret keys, TLS certificate contents and a Helm example are in [the chart guide](../helm/blablador-token-generator/README.md). Protect secret files/directories with restricted ownership, `umask 077` and mode 0600. Do not put credentials in Helm `--set`, shell history, support messages or committed values. Generated-secret Helm values and rendered manifests contain credentials and need the same protection as the Secret.

Supply independently generated JWT and token-HMAC keys of at least 32 characters. Length checks do not establish entropy. Back up the HMAC key securely: deletion records use it too. URL-encode datastore credentials correctly. Production requires secure host cookies, debug disabled, HTTPS public/provider/redirect URLs, complete confidential-client OAuth or configured local authentication, verified PostgreSQL TLS and shared verified Redis TLS. Validate configuration without printing it:

```bash
uv run --no-sync python -c 'from app.config import get_config; get_config(); print("Configuration valid")'
```

This does not prove live certificates, IdP assurance or database grants. Production is default; `APP_ENVIRONMENT=development` intentionally relaxes transport/storage checks. Keep that override out of production.

Build all three reviewed images:

```bash
docker build -t token-generator:reviewed .
docker build -f helm/blablador-token-generator/files/Dockerfile.postgresql -t token-generator-postgresql:reviewed .
docker build -f helm/blablador-token-generator/files/Dockerfile.redis -t token-generator-redis:reviewed .
```

Publish through the authorized registry workflow, then use target-architecture **registry manifest digests**. Local Docker image IDs are not interchangeable manifest digests. The chart expects hardened derived datastore images; choosing their upstream bases loses the package/binary fixes. Immutable release tags are supported, with digests preferred. Record matching scan, SBOM/provenance and runtime evidence.

Render with protected inputs, validate against the target API schema and Restricted Pod Security admission, then perform the authorized rollout. Defaults deliberately require credentials, reviewed images, certificates, exact forwarding sources and explicit ingress/egress peers. The container contract is isolated HTTP port 8080; public TLS comes from ingress. The non-container launcher supports HOST/PORT overrides. Verify CNI enforcement, untrusted-pod denial, forwarded-header integrity, public HTTPS/redirect, datastore CA/SAN checks and plaintext rejection on the real cluster. Edge header/connection/TLS limits and representative load remain deployment checks.

## Existing database upgrade

Back up and test restore before a real change. Preserve keys, roles, epochs, revocations and tombstones with the database. Compare existing schema with `app/models.py`. Inventory legacy NULL-expiry API credentials and older local-password policy; reissue/reset under the approved upgrade plan. NULL-expiry legacy tokens remain valid until revoked, while new/renewed/rotated credentials receive bounded expiry. Startup `create_all` creates missing tables, but does not alter existing columns/constraints/indexes. Review and apply the explicit index migration using the intended verified database and authorized schema-owner identity:

```bash
uv run --no-sync python -m app.migrate_token_owner_index
uv run --no-sync python -m app.migrate_token_owner_index --apply
```

It preserves rows/credentials, is idempotent, adds `ix_tokens_user_id ON tokens(user_id)` and uses PostgreSQL `CONCURRENTLY`. Wrong/invalid index definitions fail. If interrupted, inspect validity and repair the partial index under an approved procedure before retrying. This is one migration, not a general future schema-migration framework. Migration deadlines are deliberately longer than runtime query deadlines; review execution/lock timing for a large production table.

An old official PostgreSQL volume initialized with `POSTGRES_USER=tokens` may retain a superuser runtime role. Changing environment values does not repair it. Connect as a separately controlled administrator and explicitly migrate to the constrained role. Production startup rejects privileged current/login/member roles before schema initialization; fresh initialization also rejects missing/shared user names or passwords. Verify `rolsuper`, `rolcreatedb`, `rolcreaterole`, `rolreplication` and `rolbypassrls` are false, privileged server-file/program memberships are absent, SCRAM is used, and ownership covers only the intended application objects. Retain an independent recovery administrator outside the app Secret. The fresh initialization script applies only to fresh volumes. Its TLS-only `pg_hba.conf` rules also require explicit review/migration on reused volumes: enabling `ssl` alone does not reject plaintext clients. Test rejection of plaintext TCP before accepting the upgrade.

Current runtime credentials are a constrained schema owner because startup creates missing tables. They still permit DDL over their schema, rather than being a DML-only minimum-permission identity. Do not grant privileged extensions, `pg_execute_server_program` or unrelated database access to resolve a startup failure. Switch consumers to verified runtime-role TLS, roll out, and test create/validate/revoke plus role changes. Separate runtime-role tests establish privilege; the behavioral regression suite's powerful synthetic role does not.

Runtime connect, statement, lock and idle-transaction deadlines are configurable and bounded. Tune them for legitimate production latency without removing them. Monitor deadline errors and long transactions; maintenance may temporarily reject requests rather than retain locks indefinitely.

## Administrator lifecycle and restoration

Configured subjects (preferred), or trusted verified emails, grant admin **only when creating a new OAuth account**. Configuration changes do not promote existing accounts. An existing admin must use `PATCH /api/admin/users/{id}` to change the persisted role. Demotion survives login and invalidates prior sessions. Maintain at least two independently recoverable administrators and avoid unnecessarily broad bootstrap rules.

Last-admin protection counts usable, non-tombstoned admins. A deletion/login race can leave a disabled row for investigation; the application emits `oauth_disabled_account_observed cleanup_required=True` and refuses its sessions. If 100 disabled alternatives prevent a bounded availability proof, mutation returns 503. A live admin can investigate/delete disabled rows. Do not blindly restore them or bypass the lock with direct database edits.

Deletion removes the application account/credentials and records a pseudonymous tombstone; it does not delete upstream identity or external logs/backups. Admin local provisioning lifts only local-email records. OAuth restoration requires an admin session, CSRF header and `POST /api/admin/users/restore-oauth` with `{"subject":"exact-provider-subject"}`. This permits future login without recovering old tokens/sessions. Verify the subject, original deletion reason and current eligibility. A newly recreated account may match retained bootstrap-admin rules again. The admin UI exposes restoration and credential containment.

## Incident containment

Use trusted authenticated administration and the internal user ID; OAuth email is not unique. Management operations require a session and `X-CSRF-Token`; an API bearer credential cannot administer accounts.

| Trigger | Operation | Completion evidence |
| --- | --- | --- |
| Exposed single API token | Owner `POST /tokens/{id}/rotate` or `DELETE /tokens/{id}` | Old bearer fails fresh validation; rotated value succeeds within expiry. |
| Account compromise/offboarding | Admin `POST /api/admin/users/{id}/revoke-credentials` | All prior bearer values and sessions fail, including pending writes waiting for locks. |
| Self containment | `POST /tokens/revoke-all` | Own tokens/sessions fail; account can authenticate again if eligible. |
| Permanent offboarding | Admin deletion plus upstream eligibility change | Old credentials fail and OAuth login is blocked by the subject tombstone. |
| Browser logout | `POST /logout` |200 only after durable revocation; replay fails.503 means failure requiring investigation/retry. |
| Local password reset | Admin PATCH with valid new password | Prior browser sessions fail; separately contain API tokens if potentially compromised. |

Rotation displays the new credential once and preserves expiry unless an explicit permitted expiry is supplied. Expired rotation requires a future expiry; revoked credentials cannot be revived. Renewal extends lifetime using the existing secret, so can revive an expired stolen value. Use rotation/revocation for exposure response. Do not put plaintext tokens in URLs/logs/messages.

Containment is effective after commit for subsequent checks. Already authorized reads/validation may finish; downstream caches can extend exposure. Purge those caches or wait their explicitly documented maximum lifetime. Gateway clients must fail closed on authoritative authentication failure. Optional usage telemetry failure is deliberately different. IdP logout/disable/reset does not automatically revoke issued API credentials: wire organizational offboarding to these APIs and test propagation delay.

## Keys, passwords and certificates

JWT signing-key rotation invalidates browser sessions without invalidating API tokens. Coordinate all workers/replicas; mixed signing keys cause intermittent failure. Complete containment and monitor rejection before closing an incident.

**Do not casually replace `token_hash_key`.** Existing API tokens cannot be rehashed without plaintext, and tombstones cannot be rebuilt from hashes without original identifiers. A key change invalidates tokens and prevents old deletion matches, potentially allowing deleted identities to return. No versioned keyring/automatic migration exists. Protect/back up the key. If lost/compromised, restrict ingress and provider eligibility while executing a reviewed identity/tombstone migration and credential reissuance. Preserving the old table alone is insufficient; restarting with a new random key is not recovery.

PostgreSQL password rotation needs authorized server `ALTER ROLE`, then consumer Secret changes and coordinated rollout. Initialization environment variables do not rotate live roles. Redis server ACL and consumer password changes must agree; its restart resets budgets, not persisted authorization. Generated Secret changes trigger checksum rollout. For external app/store/TLS Secrets increment `secretRevision`, because Helm cannot observe their contents. For a compromise, terminate existing database sessions under the authorized maintenance procedure as well: changing a password does not close already authenticated connections. Verify readiness, new-credential acceptance, old-credential rejection, CA/SAN trust and TLS-only listeners. Plan certificate trust overlap and correct service names. Compose bind-backed keys need real server UID ownership/mode; secret mounts do not repair host permissions.

## Monitoring, privacy and recovery

Supported entrypoints disable Uvicorn query-bearing access logs. Unexpected errors log route templates/types, not raw paths/messages. Configure every ingress/proxy/IdP/APM logger to omit callback code/state queries, authorization/cookie headers and token/password bodies. Audit/account INFO remains enabled independently of general thresholds. Some administration events include email; choose retention/access deliberately.

Alert on containment/revocation failure, repeated login/provider failure, admin/bootstrap/restoration changes, disabled-row cleanup, readiness/dependency failures and expiring image assessments. Local events do not establish a tamper-resistant collector, delivered alert, full cross-service correlation or on-call response; those external systems require evidence.

Backups must include matching keys/configuration and be encrypted/tested. An old backup can resurrect deleted/revoked identities; reconcile recent containment/tombstones and upstream eligibility before reopening ingress. Tombstones are pseudonymous/linkable personal data, not irreversible anonymization. Do not age-purge them without a resurrection prevention policy. Bundled stores are single replicas: app replicas/spreading/disruption budgets are not database HA. Set recovery/availability objectives and provide managed/replicated stores when necessary.

## Repeatable checks

```bash
env -u TEST_DATABASE_URL uv run --no-sync pytest -q
uv run --no-sync python helm/blablador-token-generator/tests/security_render.py
uv run --no-sync python helm/blablador-token-generator/tests/container_risk_gate.py --self-test
```

Only point `TEST_DATABASE_URL` at an explicitly disposable PostgreSQL database: tests create/drop tables. Audit the frozen production export. Build/scan all selected images at every severity and preserve scans/SBOM. Risk assessments expire 2026-11-10; renew only after reviewing vendor status, exact versions, reachability and unchanged runtime protections. Do not add blanket suppression or `ignore-unfixed` to force success.
