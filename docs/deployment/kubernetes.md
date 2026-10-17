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
| PostgreSQL `StatefulSet` | Single replica of the hardened image; TLS only (plaintext TCP rejected); a separate non-superuser runtime role; the administrator can sign in only inside the pod. |
| Redis `Deployment` | Redis 8, TLS only, an ACL that allows the counter commands and the rate limiter's Lua scripts only, no modules, no persistence, `noeviction`. |
| `NetworkPolicy` | The application accepts traffic only from the peers you list; PostgreSQL only from the application and the backup job, Redis only from the application. |
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
and `tokens-blablador-token-generator-redis`. They write secret values to
private files and create the Secrets from those, so no value appears on a
command line (visible to other users in `ps`) or in your shell history.

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
umask 077; secrets=$(mktemp -d)
openssl rand -hex 32 > "$secrets/admin-password"
openssl rand -hex 32 > "$secrets/password"
printf 'postgresql+asyncpg://tokens:%s@tokens-blablador-token-generator-postgresql:5432/tokens' \
  "$(cat "$secrets/password")" > "$secrets/database-url"
kubectl create secret generic tokens-postgresql-credentials --from-file="$secrets/admin-password" \
  --from-file="$secrets/password" --from-file="$secrets/database-url"
```

**Redis credentials** (`redis.existingSecret`): `password` and
`storage-uri`:

```bash
mkdir "$secrets/redis"
openssl rand -hex 32 > "$secrets/redis/password"
printf 'rediss://:%s@tokens-blablador-token-generator-redis:6379/0?ssl_ca_certs=/app/tls/redis/ca.crt&ssl_cert_reqs=required&ssl_check_hostname=true' \
  "$(cat "$secrets/redis/password")" > "$secrets/redis/storage-uri"
kubectl create secret generic tokens-redis-credentials --from-file="$secrets/redis/password" \
  --from-file="$secrets/redis/storage-uri"
rm -r "$secrets"
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
  # The gateway validates tokens for many users from few addresses; without
  # this, each of its addresses is limited to 600 validations a minute.
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

# Where the ingress controller connects from (trusted X-Forwarded-For).
forwardedAllowIps: "10.42.0.0/16"
allowForwardedCidrs: true

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

`forwardedAllowIps` lists addresses or networks (written without host bits:
`10.42.0.0/16`, not `10.42.0.7/16`, which Uvicorn ignores); networks need
`allowForwardedCidrs: true`. Choose addresses that do not change: ingress
controller pods get new IP addresses when they restart, and a stale list makes
every client share the ingress pod's rate-limit budget. Use the pod network
(as above) while `networkPolicy.app.from` admits only the ingress controller
(and the gateway), or the nodes' addresses with a `hostNetwork` ingress
controller. The ingress controller itself must replace, not trust, the
`X-Forwarded-For` header clients send (ingress-nginx does by default).

After installing, check that the access log shows clients' real addresses,
not the ingress controller's:

```bash
kubectl logs deploy/tokens-blablador-token-generator | grep token_generator.access | tail -3
```

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
(with psql's `\password`); see [Incident response](../operations/incidents.md#rotate-keys-and-passwords).

## External PostgreSQL or Redis

Set `postgresql.enabled: false` (keep `databaseBackend: postgresql`) and put
the database URL and `database.ssl_ca_file` in the configuration Secret; mount
its CA with `postgresql.tls.existingSecret`. The same applies to Redis with
`redis.enabled: false` and `rate_limits.storage_uri`. Allow their addresses in
`networkPolicy.app.egress.extraRules`.

## Uninstalling

`helm uninstall` keeps the PostgreSQL data volume and the backup volume.
Delete them explicitly once you no longer need the data.
