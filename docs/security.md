# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[**Report a vulnerability**](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/security/advisories/new).
Do not open a public issue.

## Security model

**Sign-in.** OAuth 2.0 authorization code flow with a confidential client,
PKCE (S256) and a `state` value, both bound to short-lived host-only cookies.
The provider endpoints are fixed HTTPS URLs; redirects are not followed and
responses are size- and time-limited and strictly typed. An account is
identified by the provider's subject only; email addresses never link
accounts or grant rights unless the provider marks them verified. The service
uses the provider's UserInfo endpoint over TLS and does not validate OpenID
Connect ID tokens.

**Sessions.** A signed JWT in a `__Host-` cookie (`Secure`, `HttpOnly`,
`SameSite=Lax`), valid for at most 24 hours (1 hour for administrators).
Logout stores the session's ID server-side, and a per-account epoch ends all
sessions at once on password reset, role change or credential revocation.
Every state-changing request needs a CSRF token (double-submit cookie).

**API tokens.** 256 random bits with a recognisable prefix, shown once and
stored only as HMAC-SHA256 under a key that is not in the database. Every new,
renewed or rotated token expires (at most 365 days by default), and each
account holds a bounded number of tokens.

**Authorization.** Owners act only on their own tokens; administration needs
the administrator role. Changes to an account's tokens or role are serialized
with row and advisory locks and re-check the caller's session after locking,
so containment cannot be outrun by a request already in flight. The last
administrator cannot be removed.

**Abuse resistance.** A per-address admission budget runs before any body is
read; bodies are limited in size and time; concurrent requests and bcrypt work
are capped per worker; routes have per-user or per-address limits, and
password sign-in also per account. Database statements and locks have
deadlines.

**Browser.** A Content Security Policy without inline scripts,
`frame-ancestors 'none'`, `nosniff`, HSTS, `no-store` caching and a strict
referrer policy on every response, including errors.

**Data and logs.** Deleted accounts leave only keyed hashes of their
identifiers. Logs never contain token values, passwords, cookies, query
strings or exception messages.

**Deployment.** Non-root, read-only, capability-free containers with
`RuntimeDefault` seccomp; NetworkPolicies for every component; verified TLS to
PostgreSQL and Redis; a PostgreSQL runtime role without superuser rights,
checked at startup; production mode refuses unsafe settings. CI scans every
image at all severities and fails on unreviewed high or critical findings.

## Security audit

A security review in October 2026 found and fixed 34 issues in the
application, the deployment templates and the supply chain. The full record is
in the repository:

- [Report](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/REPORT.md):
  findings and fixes, verification, production acceptance requirements.
- [Threat model](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/THREAT_MODEL.md)
  and [control inventory](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/CONTROLS.md).
- [Container vulnerabilities](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/CONTAINER_VULNERABILITIES.md)
  and the time-limited [risk assessments](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/security_audit/container-risk-exceptions.json) CI enforces.

The report describes the code as of the audit; the operational procedures in
this documentation supersede its `OPERATIONS.md`.

### Deliberate changes since the audit

| Change | Reason |
| --- | --- |
| When Redis is unavailable, admission limits fall back to per-process counters and `/readyz` stays ready (reporting `degraded`); the audit had both fail closed. | Redis is a single, non-replicated store. Failing closed turned any Redis restart, or Redis filling up, into an outage of sign-in and token validation for every replica. Limits remain enforced per process; password sign-in still fails closed. |
| `/api/v1/` requests skip the CSRF check even without a bearer token. | The validation API never reads cookies, so CSRF cannot apply; callers now get `401` instead of a misleading `403`. Cookie-authenticated endpoints are unchanged. |
| Schema migrations run at startup (Alembic) instead of `create_all`. | Existing databases can now be changed safely; the runtime role already owned the schema. |
| A request log (route template, status, duration, client address). | Operations had no request visibility; it never contains query strings or raw paths. |

## Known limitations

- Multi-factor authentication and account assurance are the identity
  provider's job; require them for administrators there.
- Disabling a person at the identity provider does not revoke their API
  tokens; connect your leaver process to the service
  ([Incident response](operations/incidents.md#someone-leaves-the-organisation)).
- `token_hash_key` cannot be rotated without invalidating every token; there
  is no key ring.
- The chart's PostgreSQL and Redis are single replicas; use managed, replicated
  stores where availability requires it.
- Per-address limits can affect many people behind one NAT; tune them for
  courses and events.
