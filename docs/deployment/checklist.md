# Production checklist

The code and the Helm chart are safe by default: production mode refuses weak
keys, plaintext database or Redis connections, wildcard proxy trust and missing
network policies. What remains are decisions and evidence that only your
environment can provide. Work through this list before going live; each item
links to the details.

## 1. Identity provider

- [ ] Register a **confidential OAuth client** with JSC Login. The redirect URI
      must be exactly `https://<your host>/oauth/openid/callback`; request the
      scopes `openid profile email`.
- [ ] Choose the first administrators **by OAuth subject**
      ([`admin.admin_subjects`](../configuration.md#admin)) and plan for at least
      two of them, so one can always restore the other.
- [ ] Require **multi-factor authentication** for administrators at the
      identity provider. The service cannot enforce it.
- [ ] Connect your **leaver process** to the service: disabling someone at the
      identity provider does not revoke the API tokens they already hold. See
      [Incident response](../operations/incidents.md#someone-leaves-the-organisation).

## 2. Secrets

- [ ] Generate `secret_key` and `token_hash_key` independently
      (`python3 -c 'import secrets; print(secrets.token_hex(32))'`).
- [ ] Keep them in your secret store and **back up `token_hash_key` together
      with the database backups**: without it, no stored token can be checked
      and deleted accounts could sign in again.
- [ ] Use separate PostgreSQL administrator and runtime passwords and a Redis
      password, each at least 32 characters.
- [ ] Provide everything as existing Kubernetes Secrets
      (`configExistingSecret`, `postgresql.existingSecret`,
      `redis.existingSecret`) rather than in a values file. See
      [Kubernetes](kubernetes.md#2-secrets).

## 3. Images

- [ ] Build the application, PostgreSQL and Redis images in CI (the release
      workflow does this for version tags) and deploy them **by digest**.
- [ ] Verify each digest's provenance before deploying it, with the command
      in the GitHub release notes (`gh attestation verify … --repo …
      --signer-workflow …`).
- [ ] Check the image scan of the exact digest you deploy, for every
      architecture you run (attached to the GitHub release).
- [ ] Protect the release path in the repository settings: reviewers for the
      `release` environment (and the registry secrets moved there), a
      protected `main` that requires pull requests with passing CI, and a tag
      ruleset that lets only release managers create `v*` tags. Require
      two-factor authentication in the organisation.
- [ ] Review the container risk assessments in
      [`security_audit/container-risk-exceptions.json`](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/container-risk-exceptions.json)
      before they expire (2026-11-10); CI fails afterwards by design.

## 4. Network and TLS

- [ ] A trusted public certificate on the ingress; plain HTTP redirects to
      HTTPS (the chart's default ingress annotations do this for ingress-nginx).
- [ ] Certificates for PostgreSQL and Redis that are valid for their service
      names, and a Secret with their CA for the application.
- [ ] `forwardedAllowIps`: where your ingress controller connects from, in a
      form that survives its restarts (see
      [Kubernetes](kubernetes.md#3-values)), so clients cannot forge
      `X-Forwarded-For` and do not share one rate-limit budget.
- [ ] `networkPolicy.app.from`: the ingress controller and the Blablador
      gateway. `networkPolicy.app.egress.extraRules`: the identity provider's
      addresses on port 443. Confirm your CNI enforces NetworkPolicy.
- [ ] The gateway's source addresses in
      [`rate_limits.token_validation_exempt`](../configuration.md#rate_limits).
- [ ] Ingress and proxy logs must not record the query string of
      `/oauth/openid/callback` (it carries authorization codes) or
      `Authorization`/`Cookie` headers.

## 5. Data

- [ ] Decide where the database lives: the chart's bundled PostgreSQL is a
      single replica. Either enable
      [`postgresql.backup`](../operations/backups.md) **and** copy the backups
      off the cluster, or use a managed PostgreSQL with backups and failover.
- [ ] Encrypt the database and backup volumes at rest.
- [ ] Agree on recovery objectives and **restore a backup once** before go-live
      ([procedure](../operations/backups.md#restore)).

## 6. Monitoring

- [ ] Collect the application logs centrally and alert on the events listed in
      [Monitoring](../operations/monitoring.md#alerts), including failed
      backup Jobs and the age of the newest dump.
- [ ] Probe `https://<host>/readyz` from outside and alert on failures and on
      `"rate_limit_storage": "degraded"`.

## 7. Go-live verification

- [ ] Sign in with JSC Login; create, validate, rotate and revoke a token.
- [ ] Validate a token from the gateway; check it is not rate limited.
- [ ] The access log shows your own address for your requests, not the
      ingress controller's.
- [ ] From an unrelated pod, confirm the application, PostgreSQL and Redis are
      unreachable, and that plaintext connections to PostgreSQL and Redis are
      refused.
- [ ] `kubectl exec deploy/<release>-blablador-token-generator -- python -m app.migrate check`
      reports the current schema.
- [ ] Load-test the validation path at your expected peak, through the ingress.

## 8. Organisation

- [ ] Data protection: the service stores names, email addresses, identity
      provider subjects, token metadata, pseudonymous records of deleted
      accounts, and logs with client addresses. Document the purpose and
      retention, for example in a privacy notice linked from the start page.
- [ ] Decide on the repository's licence; none is declared yet.
