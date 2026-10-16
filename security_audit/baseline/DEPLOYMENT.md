> Historical audit notes for baseline commit `3341bc087ffbf4f76b469cd7f272dfbeafdcebe3`, recorded 2026-10-11 before remediation. Findings and proposed fixes below are superseded by [the implemented remediation report](../REPORT.md). These notes preserve detailed original evidence; do not treat their old source line numbers, old deployment defaults, or suggestions as current behavior. Some temporary probe paths have equivalent saved probes in `../probes/`.

# Token Generator deployment and supply chain audit notes

Date: 2026-10-11 (Europe/Berlin). Scope: read-only examination of Dockerfile, Docker Compose, start.sh, Helm chart and helpers, config example/schema relevant to deployment, `.gitignore`, `.dockerignore`, README, SECURITY.md, CI and Dependabot. No production connection, deployment or production database modification was performed. The initial review was read-only; additional authorized local testing used only disposable PostgreSQL containers bound to loopback with synthetic data and tmpfs, described below. Dependency advisory audit and Git-secret/history examination belong to the root reviewer and are not duplicated here.

## Results and evidence strength

- Source evidence and synthetic local reproductions confirm the issues below. A chart is deployment intent, not evidence of the running cluster configuration.
- Helm 4.2.1 is available. Synthetic `helm template` outputs parse as YAML; this is not Kubernetes admission validation or an actual startup check.
- Docker Compose's configuration parses with synthetic credentials. Docker client29.8.2 is installed. Initial sandbox socket access failed; later approved sandbox escalation allowed the isolated PostgreSQL tests below. No application image build or runtime image scan was completed by this sub-review; the root reviewer handles those.
- `bash -n start.sh` passes.
- All probe inputs contain synthetic test credentials only. No real credentials are in notes or captured outputs.

## Confirmed actionable findings

### D01 — HIGH: Published example JWT signing and token-hash placeholders pass startup validation

Evidence: `config.yaml.example:10`, `config.yaml.example:14`; `app/config.py:127-160`.

The example uses two literal `REPLACE_WITH_...` strings longer than 32 characters. `validate_security()` rejects five default values and secrets shorter than 32 characters, but does not reject the actual example placeholders or otherwise require secure generation. Reproduction: instantiate `Config` with the unchanged example and call `validate_security()`; it succeeds. These signing/hash values are public source content. A user following the example without replacing both can start the service with a publicly known JWT signing key. JWT forgery still requires a valid existing user subject and other supported claims; parent authentication audit establishes the specific impact.

Remediation: ship blank or rejected placeholders, reject the actual template placeholder pattern, document secure independent generation, and test every distributed example/default against fail-closed startup validation. Validate production secrets without printing them. Real deployed key entropy/rotation must be verified separately.

### D02 — HIGH: Bundled app PostgreSQL credentials are database superuser credentials

Evidence: `docker-compose.yaml:15,27-29`; `helm/blablador-token-generator/values.yaml:95-98`; `templates/postgresql.yaml:12-13,43-50`; `templates/deployment.yaml:65-69`.

Both packaged deployment paths set `POSTGRES_USER` to the same username used by the application connection URL. The official PostgreSQL image creates that user with superuser privileges. A compromised application or stolen app database credential can control the entire database cluster, create privileged roles, tamper with every account/token/revocation row, and use privileged server facilities. No SQL injection is asserted here; this is privilege blast radius.

Remediation: separate initialization/migration and runtime identities. Pre-create tables/migrations with an administrative role, grant the runtime role only required schema/table/sequence permissions, deny superuser/createdb/createrole/replication, and verify `rolsuper=false` using the actual app connection. Current `create_all` on startup needs to be moved to an explicit migration/init job or narrowly scoped schema-owner role before using a true DML-only role.

Primary source: [Official PostgreSQL image environment variables](https://hub.docker.com/_/postgres) explicitly states POSTGRES_USER creates a superuser and POSTGRES_PASSWORD sets its password.

### D03 — HIGH conditional: Broad forwarded-header trust with app ingress unrestricted enables IP spoofing

Evidence: `Dockerfile:31-35`; `values.yaml:55-70,163-164`; `templates/deployment.yaml:62-63`; `templates/networkpolicy.yaml:29-50`; `app/rate_limit.py:48-53`.

The Helm chart requires a forwarded-allow IP/CIDR string and describes the ingress controller pod CIDR. App NetworkPolicy is disabled by default. If that trust range includes other attacker-reachable pods/nodes, an attacker whose TCP source is within the trusted range can submit X-Forwarded-For values accepted by Uvicorn. This changes per-IP limiter keys and can claim an address in `token_validation_exempt`, removing validation throttling. Broad whole-cluster pod CIDRs or `*` are especially unsafe. Actual controller hostNetwork behavior and source rewriting may require node ranges rather than pod ranges; comments acknowledge this, but do not enforce isolated peers.

Remediation: restrict actual network peers to ingress/gateway; trust only their narrow effective source addresses; sanitize forwarded headers at the ingress; verify spoofed headers from public clients and an unauthorized pod cannot change rate-limit identities or claim an exempt gateway IP. CNI NetworkPolicy enforcement, controller source-IP behavior and production allowlist are operational unknowns.

### D04 — MEDIUM: Mutable application latest tag with IfNotPresent can silently run stale or mixed security fixes

Evidence: `values.yaml:3-6`; `templates/deployment.yaml:57-58`; `values.yaml:81-82,100-101`; `templates/postgresql.yaml:41`; `templates/redis.yaml:39`; `docker-compose.yaml:25,39`.

Dockerfile base and uv build-tool images are pinned by digest, but the deployed application defaults to `:latest` with explicit `IfNotPresent`. Nodes can reuse an older locally cached image while other nodes resolve a newer latest tag. Bundled PostgreSQL and Redis use mutable major-version Alpine tags and do not offer a dedicated digest field. This weakens reproduction, emergency patch rollout, rollback and proof that the reviewed code equals running code. AppVersion is also `1.0` while package/chart versions are `0.1.0`; neither identifies a source commit.

Remediation: deploy all three immutable registry digests, record source commit/SBOM and scan result for each digest, and verify runtime `imageID`. Add supported digest fields and an approved release pipeline/registry. The instruction registry is the JSC registry, while Helm defaults and chart README use GHCR; operator values must align this explicitly.

Primary source: [Kubernetes image tags, digests and pull policy](https://kubernetes.io/docs/concepts/containers/images/) documents mutable tags, fixed digests and IfNotPresent cache behavior.

### D05 — MEDIUM: Helm silently omits requested security settings

Evidence: `templates/config-secret.yaml:10-53` versus `app/config.py:9-32,48-66,109-123`.

A local synthetic render passing `config.app.jwt_expiration_hours: 1`, `config.app.log_level: WARNING`, `config.app.max_body_bytes: 1024`, `config.database.echo: true`, and `config.local.enabled: true` omits all five settings from the generated config. The local section is wholly absent, also dropping `allow_registration`; `tokens.token_prefix` and the complete `blablador` section are omitted too. App defaults therefore apply silently: 24-hour JWT lifetime, INFO audit logging, 65536-byte body cap, echo false, local auth disabled. The shorter intended session lifetime/body limit are actual examples of policy not reaching runtime; omitted echo/local settings currently fail toward the safer default.

Remediation: support the full intended schema or reject unsupported values via values.schema.json; template all documented security properties and regression-check rendered config. Explicitly document unsupported application sections. Add schema constraints to chart values. `rate_limits` is dynamically ranged and DOES preserve an external `storage_uri`; do not report it as omitted.

### D06 — MEDIUM: PostgreSQL/Redis password changes do not rotate running credentials or trigger rollout

Evidence: `templates/deployment.yaml:36-37,65-76`; `templates/postgresql.yaml:11-13,47-51`; `templates/redis.yaml:10-12,42-57`.

Rendered password-rotation reproduction: change only postgresql.password and redis.password. Both data-store Secret objects change, but all three workload PodTemplates remain byte-for-byte equal; the config Secret/checksum does not change. Secret-key environment values remain in existing processes until restart. PostgreSQL's POSTGRES_PASSWORD is an initialization setting; changing it or restarting on an existing data directory does not change the actual database password. Rescheduling app/Redis at different times can create credential disagreement. Redis disagreement can move the limiter into local fallback, while PostgreSQL disagreement causes availability failure. An old compromised database credential remains valid until explicitly changed at the database.

Remediation: external secret references, documented coordinated rotation with DB ALTER ROLE and overlap where supported, all relevant checksum/rollout triggers, rollback protection and validation of old-credential rejection/new-credential acceptance. Do not promise Helm password-value changes alone rotate the database. Hash-key rotation also needs a versioned application design; it must not be improvised because existing tokens and identity tombstones depend on it.

Primary source: [Official PostgreSQL image initialization behavior](https://hub.docker.com/_/postgres) states Docker environment variables only initialize empty data directories.

### D07 — MEDIUM: start.sh ignores advertised environment bind, port and worker overrides

Evidence: `start.sh:7-13,21-24,31-35`.

HOST, PORT, WORKERS are assigned unconditionally. A mock-only invocation with environment HOST=127.0.0.1, PORT=9999, WORKERS=1 and mocked nproc=3 produces `--host 0.0.0.0 --port 8080 --workers 3`. An operator trying to keep the service bound to loopback can accidentally expose it on all interfaces, and trying to cap workers cannot do so. This can also amplify per-process in-memory limiter ceilings and memory pressure.

Remediation: preserve `${VAR:-default}` values, validate them, add a trivial command-construction verification, resolve the script's own directory and fail if virtualenv activation fails. `source .venv/bin/activate` is relative to the caller directory and has no fail-fast behavior; a missing virtualenv can select a global uvicorn instead of the locked environment. The cloudflared command at line45 is unreachable after exec in both startup branches and is confusing dead code, not a live public tunnel finding.

### D08 — MEDIUM: Missing internal transport encryption

Evidence: `docker-compose.yaml:15-16`; `templates/postgresql.yaml:13`; `templates/redis.yaml:12,41-57`; SECURITY.md:124-125.

Bundled deployment config uses plain PostgreSQL and redis:// TCP connections and configures no server TLS. Redis AUTH password and rate-limit traffic are unencrypted; database records/query data have no transport encryption. Password authentication and ingress-only NetworkPolicies reduce reachability but do not encrypt bytes or establish server identity. Risk depends on cluster/node/CNI trust and any externally imposed transparent encryption, neither verified.

Remediation: authenticated TLS with server identity verification for both data stores, or explicitly document/approve verified node-to-node encrypted transport and its boundaries. Use rediss:// and supported asyncpg SSL settings when integrating an external managed service. Confirm certificates and actual connection security at runtime.

### D09 — MEDIUM: Deployment secret handling relies on plaintext Helm values and sensitive command lines

Evidence: `README.md:178-194`; chart README:48-56; `templates/config-secret.yaml:8-29`; `templates/postgresql.yaml:11-13`; `templates/redis.yaml:10-12`; `.gitignore:1-14`.

The recommended --set OAuth client secret command can expose credentials through shell history/process observation; generated values contain signing, token-hash, OAuth and DB/Redis secrets and are stored with Helm release history. The values-production.yaml file suggested by README is not ignored by .gitignore; .env variants/backups/keys are also not generally excluded. Helm does not support existingSecret/externalSecret values for these three generated Secrets, so operators must put secret material into Helm inputs unless they customize the chart. Synthetic tests did not place real secrets in files.

Remediation: external secret store or existingSecret references, least-privilege namespace/Helm-release RBAC, Kubernetes at-rest encryption, encrypted backups, mode0600 local secret inputs, avoid secret literals in command-line flags, ignore intended local secret artifacts and run secret detection on commits/build contexts. .gitignore is not a security boundary and does not repair tracked/history secrets.

Primary sources: [Helm advanced storage notes](https://helm.sh/docs/topics/advanced/) says release information contains chart/value contents and may contain passwords or private keys; [Kubernetes Secret practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/) calls for encryption at rest and restricted access.

### D10 — MEDIUM: Security limits relax silently when Redis is disabled, down or evicts live counters

Evidence: `values.yaml:1,76-89`; `templates/deployment.yaml:71-77`; `Dockerfile:35`; `app/config.py:68-71`; `app/rate_limit.py:18-30`; `templates/redis.yaml:40-51`.

The app image always uses two workers. Helm defaults to two replicas. Setting redis.enabled=false without external rate_limits.storage_uri still renders successfully and leaves storage_uri absent, so application default memory:// creates independent worker counters; steady per-client ceilings can rise with worker/replica count. During Redis failure, in_memory_fallback_enabled and swallow_errors similarly favor availability. Redis itself has a 64mb limit and volatile-ttl eviction; eviction or restart resets valid counters. More concurrency and repeated outage/recovery can therefore loosen advertised limits. This is deliberate code behavior rather than a claim the limiter ceases checking every request; parent limiter audit should characterize error behavior and blocking I/O precisely.

Remediation: require a supported shared backend for multi-worker/replica production, define and surface degraded state, enforce sensitive local-login throttling at an independent edge or fail closed for selected actions, alert on backend errors/evictions, size counter capacity and load-test failover. External config.rate_limits.storage_uri is supported by the template range.

### D11 — LOW/MEDIUM hardening gap: Compose lacks the hardened Helm runtime boundaries

Evidence: entire `docker-compose.yaml`, particularly 7-16,25-41; Dockerfile:27.

Compose publishes app port8080 on all host interfaces, with no bundled TLS reverse proxy, source restriction, read_only, cap_drop, no-new-privileges, per-service resource/pids limits or app healthcheck. Redis has no healthcheck or maxmemory cap and starts without readiness dependency. PostgreSQL/Redis are not published to the host, and the app image is non-root, which are existing strengths. Plain direct HTTP makes production Secure cookies unusable and exposes bearer credentials to transport interception if clients nevertheless use validation. Service-level TLS/firewall/resource controls can be imposed externally but are not evidenced.

Remediation: bind loopback behind HTTPS proxy or tightly restrict host firewall, mirror Helm's runtime hardening, add resource/pid limits and writable tmpfs/volumes, cap Redis memory, add functional readiness. Pass narrow FORWARDED_ALLOW_IPS explicitly when proxying; Compose currently never supplies that environment variable and Docker defaults to127.0.0.1.

### D12 — LOW/MEDIUM operational gap: Health checks prove process response, not authentication readiness

Evidence: `app/main.py:180-182`; `values.yaml:41-53`; `templates/postgresql.yaml:57-60`; `templates/redis.yaml:61-64`.

App liveness and readiness are identical `/healthz` endpoints that always report ok. PostgreSQL probe only checks accepting connections, and Redis readiness is a TCP connection. Credentials, database/schema/query health and shared limiter operation are not checked. A database outage or credential mismatch can leave app pods Ready and accepting users while requests fail; Redis degradation can go unobserved. No app startupProbe, datastore liveness probes, PodDisruptionBudget, topology spreading/affinity, DB HA or Redis HA appears in the chart. Single DB and Redis replicas are explicit default failure domains.

Remediation: separate lightweight liveness from bounded DB-backed readiness, expose limiter degradation rather than blindly removing all auth capacity when Redis fails, add metrics/alerts and externally verified availability/backup objectives. Add PDB/topology or managed/replicated stores according to required service availability. Avoid liveness checks that unnecessarily kill healthy processes for dependency outages.

### D13 — LOW hardening gap: seccomp unspecified, unrestricted egress, Secret-file permissions implicit

Evidence: `templates/deployment.yaml:45-56,98-103`; `templates/postgresql.yaml:33-38,61-65`; `templates/redis.yaml:31-36,65-69`; `templates/networkpolicy.yaml:17,44`.

Helm pods use non-root IDs, read-only roots, dropped capabilities and no service account tokens, but no seccompProfile is explicit. All policies are Ingress-only; app/DB/Redis egress can reach other network locations. Config Secret volume does not set restrictive defaultMode and uses the Kubernetes default. Pod Security Admission enforcement, seccomp runtime default, external egress policies, cloud metadata isolation and Secret RBAC are unknown. Lack of explicit seccomp can prevent admission under a Restricted Pod Security namespace unless a cluster default/mutator supplies it.

Remediation: explicit RuntimeDefault seccomp, enforce Restricted policy for the namespace and verify admission, narrow app egress to DNS/IdP/database/Redis and allow justified store egress, set owner/group-readable Secret mode appropriate to UID/fsGroup, and test expected controller/gateway network paths.

Primary source: [Kubernetes Restricted Pod Security standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/) describes the required seccomp and container isolation settings.

### D14 — LOW operational/documentation gap: direct Docker and some setup examples do not reproduce intended runtime

Evidence: `README.md:23-26,37-49,93-109,153-159`; `Dockerfile:19-21`; `app/config.py:166-173`; chart README:29-30,50-56; `start.sh:5`.

README docker run mounts /app/config/config.yaml but does not set CONFIG_PATH; the image does not set it either, so the app looks for /app/config.yaml and fails strong-key validation. The shown README placeholder keys are too short, HTTP public API/redirect examples are unsuitable for production, first callback example is /callback rather than the real route, and `uv pip install -e .` ignores frozen lock semantics. Chart README's simple helm install omits newly required secrets/forwarded IP and fails. README states raw SHA256 tokens while current implementation is keyed HMAC-SHA256. These defects do not independently permit auth bypass, but can push operators toward ad hoc config/weakening instead of the reviewed secure path.

Remediation: one current production guide with tested locked installation, exact mounted config path, HTTPS, generated keys, Redis, trusted proxy setup, approved immutable registry digests and sanitized deployment validation. Keep development examples explicitly separated.

## CI / supply chain coverage and controls

Evidence: `.github/workflows/ci.yml:3-60`; `.github/dependabot.yml:2-14`; `Dockerfile:1-27`; `.dockerignore:1-8`; `pyproject.toml:5-34`; `uv.lock`.

Existing positive controls:

- Python base and uv build-tool images pinned by sha256; multi-stage build leaves uv/cache out of final image.
- Frozen uv export, locked versions and require-hashes installation; production excludes project/dev extras. Registry sources in lock inventory are PyPI; root reviewer checks advisories/version drift.
- Only app/ is copied; Docker context allowlist excludes root config.yaml, .env, cookie jars, Git metadata, tests and deployment files. App code/templates remain root-owned; UID10001 is the runtime user and only data directory made writable in Dockerfile.
- CI checkout/setup-uv/Trivy action dependencies use commit SHAs; repository permissions contents:read; checkout persist-credentials:false.
- CI executes pytest on SQLite and a PostgreSQL16 service, pip-audit pinned tool2.10.1 against hashed frozen export, Trivy image scan and weekly Dependabot for uv/Docker/actions.
- Helm Secrets separate from app code, read-only config mount, config checksum automatic rollout for config.* changes, PostgreSQL/Redis password required at render, weak JWT/hash keys fail runtime startup, forced single SQLite replica.
- App/storage pod identities are non-root, privilege escalation prohibited, all capabilities dropped, roots read-only, short-lived directories mounted, no SA tokens. Postgres data uses PVC; network policies select only app peers for DB/Redis ingress.

Coverage gaps/limitations:

- Trivy gates only HIGH/CRITICAL and `ignore-unfixed:true`; unresolved CVEs and medium exposures are excluded from gate. No artifact preserving the full unfiltered vulnerabilities/SBOM scan or explicit accepted-risk review is defined.
- Trivy scans built application image only; bundled PostgreSQL/Redis mutable runtime digests are not scanned by these steps. Current CI build cannot prove deployed images match scan.
- No Helm render/schema/Pod Security checks, Compose lint, image startup smoke test, Redis-backed multi-worker integration test, mTLS/internal TLS check, production cookie/forwarded-header deployment test or real IdP integration is visible in CI (app tests may cover subsets; root audit maps tests).
- No signing/provenance/SBOM publishing, deployment image-verification policy or release publish workflow is visible.
- Dependency setup docs bypass lock; build-system setuptools has a broad minimum but not locked for editable local installs.
- Dependabot is maintenance intent; not proof alerts/PRs were reviewed/merged. Branch protections/status requirements, CODEOWNERS/reviews, secret scanning/push protection, registry access restrictions and CI latest success are external unknowns.
- Application image OS advisory state/build/start are handled by the root reviewer. This sub-review validated the official PostgreSQL runtime hardening with isolated containers, not the final application image.

## Sanitized local working-directory configuration (not live production evidence)

Read only config.yaml keys/booleans and file mode; no secret, hostname, database path or email printed:

- config.yaml exists and mode0644 (world-readable).
- app.debug=true, app.secure_cookies=false.
- OAuth authorize/token/userinfo URLs HTTPS; redirect URI HTTP.
- Database scheme sqlite+aiosqlite, echo defaultfalse.
- rate_limit storage_uri absent -> default memory://.
- No CONFIG_PATH/JWT_SECRET_KEY/TOKEN_HASH_KEY/DATABASE_URL/RATE_LIMIT_STORAGE_URI/OAUTH_CLIENT_SECRET/FORWARDED_ALLOW_IPS environment override present in tool process.
- jwt_expiration_hours, log_level, max_body_bytes use defaults.

These are development settings and must not be used as production configuration. Config secrecy on shared machines needs mode0600 or an external store; production manifests/runtime configuration were not supplied/queried. Whether actual secret values have sufficient random entropy is deliberately not inferred from length.

## Additional operational requirements / unknowns to verify before go-live

- Cluster/ingress TLS certificate validity, forced HTTP-to-HTTPS redirect, proxy header sanitization, request/header/body/read timeouts and request concurrency limits; HSTS alone does not redirect HTTP or protect first use.
- Validate a public client sees its real IP, cannot spoof client/gateway identity, cannot directly reach pods, and isolated other pods cannot reach DB/Redis. NetworkPolicy requires actual CNI support and network rules are additive.
- Verify resource sizes under bcrypt, OAuth HTTP latency, token validation throughput and 2workersx2replicas; DB connection count/pool and Redis counter memory/eviction, ephemeral volume limits and disk exhaustion.
- DB encrypted-at-rest storage, backup encryption/access/retention, tested restore, schema migrations, recovery point/time objectives. app/database.py creates missing tables only, not migrations; SECURITY.md acknowledges no schema migrations.
- Recovery restores signing/hash/tombstone identity keys consistently; database rollback can resurrect revoked tokens/sessions/deleted identities unless incident procedures explicitly account for it.
- PG/Redis and OAuth/JWT/hash-key rotation runbooks; email/subject admin allowlists and role persistence procedures belong to authentication audit.
- Central audit-log retention/tamper controls, ingress query-string redaction for OAuth callback code/state, PII handling and absence of Authorization/cookie capture in proxy/APM/exception logs.
- Patching ownership and lifecycle for OS base image, Redis, PostgreSQL, ingress controller and cluster; Trivy no-fix advisory risk acceptance.
- Secrets mounted/defaultMode, etcd encryption, RBAC least privilege, ability to create pods in namespace, node access and registry credentials permissions.
- Existing Git secret incident rotation/provider revocation and historical purge claims in SECURITY.md require root's investigation; this review did not read old secret contents.
- Standing 256K model-serving requirement is not applicable to this authentication-service deployment; this review deploys/accepts no serving model.

## Reproduction artifacts

All are under `/private/tmp`; synthetic credentials only; generated values/rendered manifests mode0600.

- `/private/tmp/token-generator-helm-audit/normal.yaml`, `normal-rendered.yaml`: safe synthetic normal chart input/output.
- `custom-security-knobs.yaml`, `custom-security-knobs-rendered.yaml`: confirms omitted JWT lifetime/log/body/local/db settings.
- `redis-off.yaml`, `redis-off-rendered.yaml`: proves external rediss storage URI preserved when bundled Redis disabled.
- `redis-disabled-no-external.yaml`, `redis-disabled-no-external-rendered.yaml`: proves memory default with Redis off and no external backend.
- `sqlite-two-replicas.yaml`, `sqlite-two-replicas-render-error.txt`: fail-closed SQLite guard.
- `password-rotation.yaml`, `password-rotation-rendered.yaml`, `password-rotation-result.json`: both data-store Secrets change, all workload PodTemplates unchanged.
- `compose-synthetic.json`: normalized Docker Compose configuration with synthetic secrets; no live daemon used.
- `/private/tmp/token-generator-start-audit/`: fake activate/uvicorn/nproc files used for non-listening start.sh argument reproduction. Observed HOST/PORT/WORKERS overrides ignored; FORWARDED_ALLOW_IPS respected.
- Default helm template fails on required redis.password. Default helm lint --quiet exits0 while WARNing about required values, so lint-only success must not be considered real deployment validity.

## Additional authorized disposable PostgreSQL runtime validation

Two uniquely named postgres:16-alpine containers were created only for this audit and removed successfully in finally blocks. Each bound5432 to an ephemeral127.0.0.1 host port, used synthetic credentials, had no persistent host/production volumes, and used tmpfs for database/tmp/run directories. Runtime restrictions: user70:70, read-only root, capabilitiesALL dropped, no-new-privileges,128 PID limit,768MiB memory limit and1CPU. This successfully validated the intended PostgreSQL UID/non-root/read-only/capability startup combination on the actual image. Role query confirmed `tokens:true` (rolsuper) on both runs, strengthening D02 beyond source inference. Metadata files record imageID and cleanup exit0.

1. Complete existing suite against PostgreSQL: **92 passed,119 warnings in5.17s**, output `/private/tmp/token-generator-postgres-test-result.txt`; metadata `/private/tmp/token-generator-postgres-test-metadata.json`; runner `/private/tmp/token-generator-run-postgres-baseline.py`.
2. Parent API agent's safe probes adapted to PostgreSQL, resetting synthetic schema per case:
   - quota configured1; two real concurrent route creations both succeed; stored_count2.
   - sole-admin self-delete response200; remaining_admins0.
   - two concurrent real self-demotions both succeed; remaining_admins0.
   - extreme expiry returns OverflowError.
   - simulated validation commit failure returns MissingGreenlet.

Concurrency barriers only waited after two actual database count queries returned; no mocked count result. These independently reproduce the API agent's findings on the production database family. Results `/private/tmp/token-generator-postgres-probe-result.txt`; metadata `/private/tmp/token-generator-postgres-probe-metadata.json`; adapted probe `/private/tmp/token-generator-api-probes-postgres.py`; isolated runner `/private/tmp/token-generator-run-postgres-probes.py`. No application source was changed.
