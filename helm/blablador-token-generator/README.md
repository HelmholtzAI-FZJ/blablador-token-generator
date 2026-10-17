# blablador-token-generator Helm chart

Deploys the Blablador Token Generator with a hardened PostgreSQL and Redis,
verified TLS between all components, NetworkPolicies, a disruption budget and
optional nightly database backups.

**Full guide:** <https://helmholtzai-fzj.github.io/blablador-token-generator/deployment/kubernetes/>
(and the [production checklist](https://helmholtzai-fzj.github.io/blablador-token-generator/deployment/checklist/)).

## Required values

The chart refuses to render without them:

| Value | Content |
| --- | --- |
| `image.digest` (or `image.tag`), `postgresql.image.*`, `redis.image.*` | Reviewed images built from this repository's Dockerfiles; `latest` is refused. |
| `configExistingSecret` | Secret with key `config.yaml` (or set `config.app.secret_key` and `config.app.token_hash_key` to have the chart generate it). |
| `postgresql.existingSecret` | Keys `admin-password`, `password`, `database-url` (or the `postgresql.*Password` values). |
| `redis.existingSecret` | Keys `password`, `storage-uri` (or `redis.password`). |
| `postgresql.tls.existingSecret`, `redis.tls.existingSecret` | `tls.crt`, `tls.key`, `ca.crt`, valid for the datastore service names. |
| `forwardedAllowIps` | Where the ingress controller connects from (trusted `X-Forwarded-For`): addresses, or networks without host bits with `allowForwardedCidrs: true`. Prefer addresses that survive ingress restarts; see the guide. |
| `networkPolicy.app.from` | Peers allowed to reach the application (ingress controller, API gateway). |
| `networkPolicy.app.egress.extraRules` | The identity provider's addresses on port 443. |

Useful optional values: `postgresql.backup.enabled` (nightly `pg_dump`),
`replicaCount`, `workers`, `resources`, `shutdownDelaySeconds`,
`terminationGracePeriodSeconds`, `secretRevision` (bump after changing an
existing Secret). See `values.yaml`; `values.schema.json` validates them.

## Checks

```sh
helm lint helm/blablador-token-generator --strict -f helm/blablador-token-generator/ci/test-values.yaml
python helm/blablador-token-generator/tests/security_render.py
python helm/blablador-token-generator/tests/container_risk_gate.py --self-test
```

`ci/test-values.yaml` contains synthetic values for these checks only. The
render tests cover the security settings, Secret handling, rollouts on
credential changes, graceful shutdown, backups and the rejection of unsafe
values, and keep names within Kubernetes limits for long release names; the
risk gate fails on high or critical image findings without a current
assessment, on secrets in images and on unsupported operating systems.
