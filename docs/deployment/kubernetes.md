# Kubernetes (Helm)

The chart in
[`helm/blablador-token-generator`](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/tree/main/helm/blablador-token-generator)
deploys the service with hardened defaults. It refuses to render until the
production inputs below are supplied, so a forgotten value fails the install
instead of producing an insecure deployment.

## What gets deployed

| Resource | Notes |
| --- | --- |
| Application `Deployment` + `Service` | 2 replicas spread over nodes, a disruption budget, non-root, read-only root file system, no capabilities, `RuntimeDefault` seccomp, no service-account token. |
| `Ingress` | Defaults for ingress-nginx: forced HTTPS, 64 KiB body limit. |
| PostgreSQL `StatefulSet` | Single replica of the hardened image; TLS only (plaintext TCP rejected); a separate non-superuser runtime role. |
| Redis `Deployment` | TLS only, password ACL without dangerous commands, no persistence, `noeviction`. |
| `NetworkPolicy` | The application accepts traffic only from the peers you list; PostgreSQL and Redis only from the application. |
| Backup `CronJob` | Optional nightly `pg_dump`; see [Backups](../operations/backups.md). |

Requirements: Kubernetes 1.25 or newer, an ingress controller, a CNI that
enforces NetworkPolicy, and a storage class that honours `fsGroup` (the
PostgreSQL and backup volumes are written by UID 70).

## 1. Images

Every image must be pinned to a release tag or, preferably, a digest; `latest`
is refused. Tagging a release (`vX.Y.Z`) runs the
[release workflow](../development.md#releases), which builds all three images
for amd64 and arm64, scans them, attaches SBOM and provenance and publishes
them to `ghcr.io/helmholtzai-fzj/`. To build them yourself:

```bash
VERSION=1.0.0
REGISTRY=registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador
docker build --build-arg VERSION=$VERSION --build-arg REVISION=$(git rev-parse HEAD) \
    -t $REGISTRY/blablador-token-generator:$VERSION .
docker build -f helm/blablador-token-generator/files/Dockerfile.postgresql \
    -t $REGISTRY/blablador-token-generator-postgresql:$VERSION .
docker build -f helm/blablador-token-generator/files/Dockerfile.redis \
    -t $REGISTRY/blablador-token-generator-redis:$VERSION .
```

Use the hardened PostgreSQL and Redis images: the upstream images contain
vulnerable components these builds remove or update. After pushing, use the
registry's manifest digests (`docker buildx imagetools inspect <image>`), not
local image IDs.

## 2. Secrets

Create these in the target namespace. The examples use release name `tokens`,
which makes the service names `tokens-blablador-token-generator-postgresql`
and `tokens-blablador-token-generator-redis`. Read passwords into variables
with `read -rs` so they stay out of your shell history.

**Datastore certificates.** One Secret each for PostgreSQL and Redis with
`tls.crt`, `tls.key` and `ca.crt`, valid for the service name (and its
`.<namespace>.svc` form). With [cert-manager](https://cert-manager.io) and a
private CA issuer:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tokens-postgresql-tls
spec:
  secretName: tokens-postgresql-tls
  issuerRef: {name: internal-ca, kind: Issuer}
  privateKey: {algorithm: ECDSA, rotationPolicy: Always}
  dnsNames:
    - tokens-blablador-token-generator-postgresql
    - tokens-blablador-token-generator-postgresql.blablador.svc
```

(Repeat for `tokens-redis-tls` with the Redis service name.)

**PostgreSQL credentials** (`postgresql.existingSecret`): `admin-password`,
`password` (runtime role) and `database-url`. Hexadecimal passwords need no
URL encoding:

```bash
PG_ADMIN=$(openssl rand -hex 32); PG_RUNTIME=$(openssl rand -hex 32)
kubectl create secret generic tokens-postgresql-credentials \
  --from-literal=admin-password="$PG_ADMIN" \
  --from-literal=password="$PG_RUNTIME" \
  --from-literal=database-url="postgresql+asyncpg://tokens:$PG_RUNTIME@tokens-blablador-token-generator-postgresql:5432/tokens"
```

**Redis credentials** (`redis.existingSecret`): `password` and
`storage-uri`:

```bash
REDIS_PASSWORD=$(openssl rand -hex 32)
kubectl create secret generic tokens-redis-credentials \
  --from-literal=password="$REDIS_PASSWORD" \
  --from-literal=storage-uri="rediss://:$REDIS_PASSWORD@tokens-blablador-token-generator-redis:6379/0?ssl_ca_certs=/app/tls/redis/ca.crt&ssl_cert_reqs=required&ssl_check_hostname=true"
```

**Application configuration** (`configExistingSecret`), key `config.yaml`.
The database URL and Redis URI come from the Secrets above; the file holds
everything else:

```yaml
app:
  environment: production
  name: "Blablador Tokens"
  api_url: "https://tokens.example.org"
  secret_key: "<64 random hex characters>"
  token_hash_key: "<64 different random hex characters>"
database:
  ssl_ca_file: /app/tls/postgresql/ca.crt
oauth:
  client_id: "<client id>"
  client_secret: "<client secret>"
  authorize_url: "https://login.jsc.fz-juelich.de/oauth2-as/oauth2-authz"
  token_url: "https://login.jsc.fz-juelich.de/oauth2/token"
  userinfo_url: "https://login.jsc.fz-juelich.de/oauth2/userinfo"
  redirect_uri: "https://tokens.example.org/oauth/openid/callback"
  scopes: ["openid", "profile", "email"]
login:
  name: "JSC Login"
admin:
  admin_subjects: ["<subject of the first administrator>"]
rate_limits:
  token_validation_exempt: ["<gateway address>/32"]
```

```bash
kubectl create secret generic tokens-config --from-file=config.yaml=./config.production.yaml
```

Plus the ingress certificate Secret (for example from cert-manager's ingress
integration).

## 3. Values

Keep this file out of Git; `values-production*.yaml` is ignored.

```yaml
image:
  repository: registry.jsc.fz-juelich.de/kaas/rke2-clusters/blablador/blablador-token-generator
  digest: sha256:<app digest>
configExistingSecret: tokens-config

postgresql:
  image:
    digest: sha256:<postgresql digest>
  existingSecret: tokens-postgresql-credentials
  tls:
    existingSecret: tokens-postgresql-tls
  backup:
    enabled: true

redis:
  image:
    digest: sha256:<redis digest>
  existingSecret: tokens-redis-credentials
  tls:
    existingSecret: tokens-redis-tls

ingress:
  hosts:
    - host: tokens.example.org
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: tokens-public-tls
      hosts: [tokens.example.org]

# Addresses the ingress controller connects from (trusted X-Forwarded-For).
forwardedAllowIps: "10.42.0.17,10.42.1.23"

networkPolicy:
  app:
    from:
      - namespaceSelector:
          matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
        podSelector:
          matchLabels: {app.kubernetes.io/name: ingress-nginx}
      # plus the Blablador gateway's namespace/pods
    egress:
      extraRules:
        - to:
            - ipBlock: {cidr: <identity provider address>/32}
          ports: [{port: 443, protocol: TCP}]
```

`forwardedAllowIps` takes exact addresses; a CIDR additionally needs
`allowForwardedCidrs: true` and must contain only trusted proxies. With a
`hostNetwork` ingress controller, list the nodes' addresses.

All other values (resources, probes, replicas, `workers`, the full `config`
block for generated config Secrets) are documented in
[`values.yaml`](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/helm/blablador-token-generator/values.yaml)
and checked by `values.schema.json`.

## 4. Install

```bash
helm lint helm/blablador-token-generator -f values-production.yaml --strict
helm upgrade --install tokens helm/blablador-token-generator \
    --namespace blablador -f values-production.yaml
kubectl -n blablador rollout status deploy/tokens-blablador-token-generator
```

The first pod to start creates the database schema; the others wait for it.
Then work through the go-live items of the
[production checklist](checklist.md#7-go-live-verification).

## Upgrading

Change the image digests and run the same `helm upgrade`. Pending database
migrations are applied by the first new pod, under a lock; old pods keep
serving until the new ones are ready. Read the
[changelog](../changelog.md) and [Upgrades](../operations/upgrades.md) first.

## Rotating secrets

Helm cannot see changes inside existing Secrets. After changing one, bump
`secretRevision` (any new string) and upgrade, so the pods restart with the
new values. A changed PostgreSQL password must first be set in the database
(`ALTER ROLE`); see [Incident response](../operations/incidents.md#rotate-keys-and-passwords).

## External PostgreSQL or Redis

Set `postgresql.enabled: false` (keep `databaseBackend: postgresql`) and put
the database URL and `database.ssl_ca_file` in the configuration Secret; mount
its CA with `postgresql.tls.existingSecret`. The same applies to Redis with
`redis.enabled: false` and `rate_limits.storage_uri`. Allow their addresses in
`networkPolicy.app.egress.extraRules`.

## Uninstalling

`helm uninstall` keeps the PostgreSQL data volume and the backup volume.
Delete them explicitly once you no longer need the data.
