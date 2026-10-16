# Token Generator production chart

Build and review all three images before installation. The chart requires an explicit release tag or registry digest for each image and refuses `latest`. Defaults point to the JSC registry, with no image identifier selected. The PostgreSQL and Redis images must be built from the hardened Dockerfiles below; the upstream official images retain vulnerabilities removed by these builds.

```sh
docker build -t token-generator:reviewed .
docker build -f helm/blablador-token-generator/files/Dockerfile.postgresql -t token-generator-postgresql:reviewed .
docker build -f helm/blablador-token-generator/files/Dockerfile.redis -t token-generator-redis:reviewed .
```

Publishing these reviewed images is a separate operator step. Set each `image.repository` to its published location and `image.digest` to the registry manifest digest. A local Docker image ID is not a registry digest. Prefer digests; release tags must be immutable in the registry. CI records full vulnerability reports and SBOMs, including unfixed findings, and rejects HIGH/CRITICAL findings unless a matching, unexpired, explicitly assessed risk exception exists.

## Required deployment inputs

Prepare a private values file outside Git, or use the ignored `values-production.yaml`. It must identify:

- App, PostgreSQL and Redis reviewed image identifiers.
- The public HTTPS URL, registered OAuth client, exact callback URI and administrator subjects.
- `configExistingSecret`: an existing Secret containing the complete `config.yaml`. Start from `config.yaml.example`, supply independent random signing/token-hash keys and the OAuth credential, and use `app.environment: production`.
- `postgresql.existingSecret`: keys `admin-password`, `password`, and `database-url`. The administrator username defaults to `token_admin`, runtime username to `tokens`, database to `tokens`. Keep the two passwords independent. The URL must use the runtime role and percent-encode reserved credential characters.
- `redis.existingSecret`: keys `password` and `storage-uri`. Use `rediss://` with CA verification and hostname verification, for example query parameters `ssl_ca_certs=/app/tls/redis/ca.crt&ssl_cert_reqs=required&ssl_check_hostname=true`.
- `postgresql.tls.existingSecret` and `redis.tls.existingSecret`: each contains `tls.crt`, `tls.key`, and `ca.crt`. Certificates must be valid for the generated datastore service DNS name, including its namespace/FQDN when used in connection URLs. The app receives only each CA certificate; private keys are mounted only in the relevant datastore pod.
- `forwardedAllowIps`: the actual ingress/gateway source IPs. Wildcard trust is forbidden. Prefer exact addresses. A CIDR additionally requires `allowForwardedCidrs: true` and network isolation proving every address in that range is a trusted proxy.
- `networkPolicy.app.from`: explicit allowed ingress/gateway peers. For hostNetwork ingress controllers, use their actual node source addresses. Public clients and unrelated pods must never be trusted forwarded-header sources.
- `networkPolicy.app.egress.extraRules`: the identity provider's HTTPS destination addresses and any external database/Redis destinations. DNS and bundled datastore peers are already allowed. Kubernetes NetworkPolicy cannot select a DNS hostname; keep provider address changes coordinated with these rules. NodeLocal DNS or a different DNS namespace requires an explicit additional rule.

TLS is enabled by default. Production rendering rejects disabling bundled datastore TLS or the app network policies. Fresh initialization installs PostgreSQL rules that reject plaintext TCP; existing volumes require the access-rule migration below. Redis listens only on TLS. The cluster CNI must actually enforce NetworkPolicy. Ingress defaults to forced HTTPS; provide a real certificate Secret for the public hostname.

Prefer external Secrets rather than placing passwords in Helm values. Generated Secrets remain supported for controlled bootstrap, but Helm release history retains supplied values and rendered secrets. Restrict release/Secret RBAC and encrypt etcd and backups. Never supply secret literals with `--set`, commit secret values, or log rendered manifests. Keep local inputs mode0600. Rotate keys and credentials through the procedure below.

A sanitized structure, with operator-owned names and addresses, is:

```yaml
image:
  digest: sha256:REPLACE_WITH_REVIEWED_APP_REGISTRY_DIGEST
configExistingSecret: token-generator-config
postgresql:
  image:
    digest: sha256:REPLACE_WITH_REVIEWED_POSTGRES_REGISTRY_DIGEST
  existingSecret: token-generator-postgres-credentials
  tls:
    existingSecret: token-generator-postgres-tls
redis:
  image:
    digest: sha256:REPLACE_WITH_REVIEWED_REDIS_REGISTRY_DIGEST
  existingSecret: token-generator-redis-credentials
  tls:
    existingSecret: token-generator-redis-tls
forwardedAllowIps: REPLACE_WITH_ACTUAL_PROXY_SOURCE_IP
networkPolicy:
  app:
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
        podSelector:
          matchLabels:
            app.kubernetes.io/name: ingress-nginx
    egress:
      extraRules:
        - to:
            - ipBlock:
                cidr: REPLACE_WITH_IDENTITY_PROVIDER_ADDRESS_AND_PREFIX
          ports:
            - port: 443
              protocol: TCP
```

The displayed replacement values are deliberately invalid and must be replaced before rendering. Existing config secrets must use `database.ssl_ca_file: /app/tls/postgresql/ca.crt` for bundled PostgreSQL. Existing data-store URLs must use the exact rendered Service names: `<release>-blablador-token-generator-postgresql` and `<release>-blablador-token-generator-redis`, unless the release already includes the chart name or `fullnameOverride` is set. Confirm actual rendered names rather than assuming them.

Validate privately before installation:

```sh
helm lint helm/blablador-token-generator -f values-production.yaml --strict
helm template token-generator helm/blablador-token-generator -f values-production.yaml > /private/operator/path/rendered.yaml
```

Protect rendered files because generated-secret mode contains credentials. Validate the rendered resources against the target cluster's API schema and Restricted Pod Security admission. Verify image IDs, actual TLS, effective app configuration, trusted proxy behavior, readiness, network isolation, storage encryption, backups and restore procedures after an authorized deployment. This repository does not publish images or supply production certificates/cluster identities automatically.

## PostgreSQL privilege and lifecycle

On a fresh data directory the initialization script creates a separate `tokens` login with NOSUPERUSER, NOCREATEDB, NOCREATEROLE and NOREPLICATION. It owns only the application `public` schema, so the current schema initialization and explicit index migration can operate without cluster-wide privilege. Ordinary application traffic and token validation use this role; administrator credentials are never injected into the app.

Initialization scripts run only on an empty database. They do not demote an existing legacy role, rotate an existing password or migrate its existing `pg_hba.conf`. Before reusing an old volume, create/verify an independent administrative role, demote the old runtime role, establish its schema ownership, and verify the app identity is not privileged. Review/migrate server access rules to reject plaintext TCP while allowing the intended authenticated TLS clients; `ssl=on` alone still permits plaintext. Verify plaintext rejection on reused volumes and external servers. Never delete a database to apply these changes. The root documentation describes the explicit token-index migration; future schema changes still require planned migrations.

PostgreSQL and Redis remain single datastore replicas. App pods spread across nodes and have a disruption budget when replicated, but this does not create database HA. Supply managed/replicated external stores when required by availability objectives. With an external PostgreSQL, set `postgresql.enabled: false` and keep `databaseBackend: postgresql`; put its verified URL/CA configuration into the config Secret. With external Redis set `redis.enabled: false` and provide a verified `config.rate_limits.storage_uri` in that Secret. Set the matching TLS CA Secret references if the chart mounts private CA certificates. SQLite is development only and requires `databaseBackend: sqlite` and a single replica.

## Credential and certificate rotation

For existing database roles, first change the runtime password through the authenticated administrative database connection and coordinate the app's credential Secret update. Updating `POSTGRES_PASSWORD` or a Helm value never changes an initialized database's password. Rotate the administrative role separately and verify both old credentials are refused.

After rotating externally managed app/data-store/TLS Secrets, increment `secretRevision` and perform a coordinated authorized rollout. Helm cannot see external Secret content changes while rendering. Generated credential changes affect pod checksums automatically; this only restarts consumers and does not rotate PostgreSQL's stored credentials. Wait for `/readyz`, verified database/Redis TLS, valid-token behavior, old-credential rejection and stable counters. Coordinate certificate trust overlap and hostname validity before rollout.

JWT-key rotation invalidates all old sessions. `token_hash_key` also keys existing API tokens and identity tombstones; changing it without a designed migration breaks token validation and deletion protections. Preserve it in recovery backups and use the application's incident-containment controls when appropriate.

## Docker Compose

Compose binds the app only to 127.0.0.1:8080 behind a separately configured HTTPS proxy. It requires reviewed `POSTGRES_IMAGE` and `REDIS_IMAGE` identifiers for these hardened builds, independent PostgreSQL administrator/runtime passwords, complete verified `DATABASE_URL`/`RATE_LIMIT_STORAGE_URI`, signing/hash keys, and each server certificate/private-key/CA file path. Passwords embedded in URLs must be percent-encoded. The app's PostgreSQL CA path is injected explicitly.

On Linux, PostgreSQL's private key must be owned by UID70 (or root with an appropriate UID70-readable group) and meet PostgreSQL's private-key permission rules; Redis's key must be readable by UID999. Compose file-backed secrets retain host ownership/permissions; setting Secret uid/gid in Compose would not fix bind-mounted files. Prepare these files deliberately and verify the servers start under their non-root identities. Existing volumes follow the database lifecycle/rotation procedure above.

Compose uses the same runtime-role initialization and Redis ACL wrapper as Helm, read-only roots, dropped capabilities, no privilege escalation, PID/memory/CPU limits and readiness probes. Redis limits memory without evicting live counters and denies dangerous administrative commands. Configure the HTTPS proxy's exact forwarded source IPs and host firewall. Compose does not provide Kubernetes network isolation or a public TLS proxy.

## Local verification

```sh
.venv/bin/python helm/blablador-token-generator/tests/security_render.py
.venv/bin/python helm/blablador-token-generator/tests/container_risk_gate.py --self-test
```

The render tests exercise complete security setting serialization, existing Secrets, digest identifiers, credential-triggered rollouts, TLS/network rejection cases, and startup host/port/worker overrides. They use synthetic credentials and do not contact a cluster. The container risk gate requires complete Trivy JSON, exact package/version/CVE exception matches with expiry and reasoning, and rejects new unreviewed HIGH/CRITICAL findings. Full lower-severity findings remain in the evidence artifacts.
