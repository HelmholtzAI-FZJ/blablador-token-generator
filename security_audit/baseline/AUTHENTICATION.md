> Historical audit notes for baseline commit `3341bc087ffbf4f76b469cd7f272dfbeafdcebe3`, recorded 2026-10-11 before remediation. Findings and proposed fixes below are superseded by [the implemented remediation report](../REPORT.md). These notes preserve detailed original evidence; do not treat their old source line numbers, old deployment defaults, or suggestions as current behavior. Some temporary probe paths have equivalent saved probes in `../probes/`.

# Authentication, OAuth, session, and security configuration audit

Audit date: 2026-10-11. Source tree: `/Users/surak/Devel/blablador/token_generator`. Read-only application review; no application code, actual config, or actual DB was modified. Synthetic local probes used explicit fake JWT/HMAC/client secrets, `tests/config.test.yaml`, and temporary SQLite files. No provider or production services were contacted. Evidence line numbers refer to the current files inspected.

## Confirmed security findings

### AUTH-01 — Configured OAuth administrators regain explicitly revoked privilege, and config promotion preserves existing sessions (High)

Evidence: `app/auth.py:305-311`, `app/auth.py:331-334`, `app/auth.py:199-205`; explicit administrative demotion at `app/api/admin.py:300-307`.

`get_or_create_user()` recomputes whether the OAuth subject or trusted email is in configuration and sets `is_admin=True` whenever the configured user currently is not an administrator. `/api/admin/users/{id}` can demote that user and increment the session epoch, but the next OAuth login promotes them again. The adjacent comment says revocation is an explicit admin action that must not be silently undone; implementation does silently undo it. Removing an entry from config alone also does not demote an already promoted user, because there is intentionally no corresponding automatic demotion. Therefore neither control independently gives a stable privilege revocation policy: operators must change both config and DB with the correct sequencing.

A related privilege transition at the same point does not invoke `invalidate_sessions()`. A session created before config-based promotion remains valid and obtains the new administrator privileges through the DB-backed role lookup. Explicit role changes in the admin API do invalidate existing sessions, so this path bypasses that intended control.

Preconditions: an administrator is listed in `admin_subjects` or has a trusted email in `admin_emails`; an operator uses the admin demotion endpoint. Old-session promotion requires possession of a valid pre-promotion session and an ensuing config-driven promotion.

Impact: a demoted or compromised administrator can regain control over all users, credentials, token revocations, and administrative operations. A stolen older non-admin session immediately gains administrative power when the account is promoted through configuration.

Safe evidence: `/private/tmp/token-generator-auth-probes.py` demoted a configured subject via the real `update_user` function and observed `False`, then authenticated the same OAuth subject and observed `True`. `/private/tmp/token-generator-auth-http-probes.py` created a session while its owner was non-admin, added the subject to the synthetic config, logged that identity in, and got HTTP 200 from `/api/admin/users` using the old cookie.

Remediation: define one explicit authority and precedence policy for administrative grants. Either seed/configure administrators once and let persistent DB roles govern subsequent changes, or implement a persistent explicit denial override that config cannot supersede. Ensure every role transition invalidates existing sessions, including config-driven promotions. Expose the effective authority to operators. Consider requiring a fresh sign-in for newly privileged sessions.

Regression tests: configured admin stays demoted on later login; removal from configured grants has the documented effect; fresh config promotion rejects all pre-promotion sessions; verified-email and subject-based grants follow the same precedence.

### AUTH-02 — Self-service deletion bypasses last-administrator protection (Medium; significant administrative availability risk)

Evidence: `app/main.py:338-368` compared with `app/api/admin.py:300-304` and `app/api/admin.py:348-355`.

`/account/delete` accepts any authenticated user and deletes that user without checking whether they are the sole remaining administrator. The administrative demotion/deletion endpoints explicitly guard against losing the final admin. A lone admin can nevertheless destroy the final administrative account through self-service deletion, which also records an OAuth tombstone, preventing that identity from recreating itself at login.

Preconditions: the sole admin deliberately or accidentally uses self-service deletion, or an attacker obtains that admin's browser session. CSRF still applies, so an arbitrary cross-site form alone cannot trigger this action.

Impact: all in-app administration can become unavailable until an operator repairs persistent state outside the application. Configured email/subject bootstrap cannot resurrect a tombstoned subject through the usual login flow.

Safe evidence: real `delete_my_account.__wrapped__` in an isolated DB returned 200 for a sole admin; the remaining administrator count was zero. Script: `/private/tmp/token-generator-auth-probes.py`.

Remediation: apply a shared invariant check to every role removal/deletion path, including self-service deletion, and enforce it under transaction locking to cover simultaneous operations. Give administrators an actionable error requiring transfer of administrative authority first.

Regression tests: sole-admin self-deletion rejected; ordinary users and one of several admins can self-delete as intended; parallel admin removal cannot leave zero admins.

### AUTH-03 — Logout reports success when session revocation fails to persist (Medium; High when incident response depends on logout invalidating a stolen session)

Evidence: `app/auth.py:147-158`, `app/main.py:318-332`.

JWT revocation catches every exception during delete/insert/commit, rolls back, and returns normally. Logout then clears the local cookie and returns 200. When a write fails, the revoked-session row never exists; a copied JWT remains accepted until its natural expiration or a separate epoch/key change. No warning/audit event identifies the failed revocation. This failure applies to write/commit failures inside the try block; a failure during the preceding lookup is outside the try and normally propagates.

Preconditions: the browser session has been copied or will be replayed, and blacklist persistence encounters a write/commit failure. No client control of DB failure was claimed.

Impact: the user is told they logged out while an attacker can continue using the same session; for admins that preserves administrative access. A transient database write problem can silently break a security boundary.

Safe evidence: replacing only the temporary session's `commit()` with a synthetic failure made `revoke_jwt()` return without exception, created no `RevokedJWT` row, and left the original JWT accepted by `get_current_user()`. Script: `/private/tmp/token-generator-auth-probes.py`.

Remediation: return an explicit revocation result or propagate a security-specific error. Clear the browser cookie regardless, but distinguish local sign-out from successful server revocation; log and alert on persistence failure without logging the JWT. Use a durable revocation transaction and a safe idempotent insert. Define a fail-closed policy for incidents and database degradation.

Regression tests: successful logout rejects cookie replay; revocation commit failure is visible in response/telemetry and never falsely reports durable invalidation; concurrent logout requests remain idempotent; deleted or expired users do not cause incorrect success claims.

### AUTH-04 — Password hashing blocks the asynchronous server event loop (Medium; conditional on local login enabled)

Evidence: `app/auth.py:26-30`, `app/auth.py:35-36`, `app/auth.py:352-365`, `app/main.py:399-418`; admin password set/reset at `app/api/admin.py:245` and `app/api/admin.py:298`.

The async local-login path directly calls synchronous bcrypt. Unknown email attempts intentionally run the same hash cost as known accounts, which is good against enumeration but gives every anonymous requester the same expensive CPU operation. The normal utility function is called from async code and is not automatically moved to a thread. Each password check blocks that worker's event loop, delaying unrelated dashboards and token-validation requests. Per-IP throttling limits one address but does not bound aggregate work across many source addresses. Admin password creation/reset also blocks, though those operations require an administrator.

Preconditions: `local.enabled=true`; attackers can supply valid CSRF cookies obtained from the ordinary public login page and requests from enough addresses to stay below each IP's budget. The production local-auth setting was not inspected by this sub-audit.

Impact: service-wide latency and availability degradation even at modest aggregate login rates. This service participates in token validation, increasing the blast radius.

Safe evidence: one bcrypt check took 0.168 seconds in the local runtime and delayed an independently scheduled 10 ms event-loop timer to 0.168 seconds. This is a local measurement, not a production throughput benchmark. Script: `/private/tmp/token-generator-auth-probes.py`.

Remediation: offload hashing/checking to a bounded worker/thread executor and add an aggregate concurrency/work budget plus per-account and per-IP failed-login throttling. A thread alone removes event-loop blocking but does not eliminate CPU saturation, so bound the pool and reject excess work. Disable local authentication in production if it is unnecessary. Keep enumeration-resistant failure behavior.

Regression tests: parallel slow password checks do not delay an unrelated async health/token operation; aggregate password-work saturation returns controlled responses; unknown and known accounts retain equivalent work; distributed attempts are constrained by an aggregate policy.

Primary reference: [FastAPI async documentation, utility functions](https://fastapi.tiangolo.com/async/#other-utility-functions) confirms that directly invoked utility functions are not automatically offloaded.

### AUTH-05 — Authentication rejection occurs before route rate limits, allowing unbounded database-backed rejection work (Medium)

Evidence: `app/auth.py:170-194`; `app/main.py:236-241` and other dependency-authenticated decorated routes; `app/rate_limit.py:34-45`.

SlowAPI applies limits in the decorated endpoint wrapper. FastAPI resolves `Depends(get_current_user)` before calling that wrapper. A revoked or stale signed cookie causes authentication to query revocations and/or users and then raise before the rate limiter is consulted. Therefore configured per-user route limits do not cap this rejection work. The same limitation affects unauthorized access to administrative dependencies; non-admin authenticated users are rejected before the admin route limiter.

Preconditions: an attacker obtains a correctly signed but revoked/stale session. An ordinary registered attacker can create this condition by signing in and signing out. A non-admin can exercise the analogous admin rejection path with an otherwise valid session. Even fully anonymous requests without a cookie bypass the wrapper, although those fail before DB work and are cheaper.

Impact: bypass of documented route throttling on a repeatable database query path; potential DB/CPU denial of service. No access-control bypass was observed.

Safe evidence: 130 requests to `/dashboard` with the same revoked session all returned 307 during one second despite the configured 120/minute page budget; none returned 429. Script: `/private/tmp/token-generator-auth-http-probes.py`. This proves missing enforcement on authentication rejection, not high-volume exhaustion.

Remediation: add IP/global admission control before expensive authentication, via ASGI middleware or an explicit earlier dependency, while retaining authenticated user budgets after identity verification. Avoid moving trust to an unsigned header. Bound rejection paths and monitor them. A reverse-proxy limit can supplement the app but must cover every accessible path.

Regression tests: repeated revoked-session, invalid-epoch, deleted-user, and non-admin admin requests hit controlled budgets and eventually return 429; legitimate NAT users retain intended per-user budgets.

### AUTH-06 — Security configuration allows plaintext OAuth credential transmission and production cookie downgrade (Medium configuration hazard; no deployed plaintext transport established)

Evidence: `app/config.py:18-22`, `app/config.py:35-45`, `app/config.py:135-160`; Basic client credentials to token URL at `app/auth.py:218-234`, bearer credentials to UserInfo URL at `app/auth.py:250-253`; cookie prefix downgrade at `app/cookies.py:15` and cookie Secure attribute at `app/cookies.py:30`.

`validate_security()` checks only signing/HMAC key length and separation. Token/UserInfo endpoint strings can be plain HTTP, and `secure_cookies=false` is accepted without a production-mode guard. Using HTTP backend URLs sends the client secret or provider access token in plaintext. Disabling secure cookies also removes the `__Host-` cookie names that prevent sibling-domain cookie planting, potentially weakening the double-submit-CSRF boundary. HTTPS defaults and examples are positive, but startup does not enforce the transport requirement when configuration changes.

Preconditions: a deployment misconfiguration; attacker has a network vantage for HTTP endpoints or control of an applicable sibling host when insecure cookies are enabled. This is not a confirmed condition of the live service.

Safe evidence: a constructed Config with HTTP token/UserInfo URLs, `secure_cookies=false`, independent synthetic 64-character keys, and debug false passed `validate_security()`. No HTTP request was made.

Remediation: enforce a deployment profile with HTTPS token and UserInfo URLs, HTTPS production redirect/canonical URL, secure cookies, permitted provider hosts, and a deliberate local-only development exception. Keep secure cookies independent of TLS termination's internal HTTP connection. Reject zero/negative or unreasonably large session lifetimes/body limits and invalid expiration relationships. Consider rejecting unknown configuration keys to prevent silent typo-induced unsafe defaults.

Primary reference: [RFC 6749 §3.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2) requires TLS for the token endpoint.

## Additional policy and hardening observations (not all are standalone confirmed vulnerabilities)

1. **Local password policy is weak for a single-factor credential.** `app/auth.py:39-77` accepts the common password `Password1` and requires only 8 characters plus uppercase/lowercase/digit composition; no compromised/common-password blocklist or MFA is present in the local flow. The local probe confirmed `Password1` accepted. For deployments adopting NIST guidance, 15-character single-factor minimum and a common/compromised-password blocklist would improve resistance. Composition requirements give little assurance. [NIST SP 800-63B-4 password guidance](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver) documents those recommendations/requirements; this is a security baseline comparison, not a claim that this project is legally required to comply. The existing 72-byte bcrypt boundary must be addressed when improving long Unicode passphrase support.
2. **Per-IP login throttling lacks per-account and aggregate attack detection.** `app/main.py:400`, `app/config.py:76`: botnets can multiply the 10/minute budget against one local account. Generic auth responses and dummy bcrypt are positive, but not a complete credential-stuffing defense.
3. **No local MFA, recent-auth requirement, or step-up check.** A current admin session suffices to create admins, reset local passwords, delete users, and revoke tokens. The OAuth provider might enforce MFA; that is unverified, and `get_unity_userinfo()` does not inspect an assurance claim. Define required admin assurance and session timeout. Re-authenticate for credential/role changes and irreversible account deletion where appropriate.
4. **External IdP disable/logout is not connected to local sessions or generated API tokens.** `app/auth.py:178-196` checks local DB/session epoch only; no back-channel logout, provider status synchronization, introspection, or disabled flag appears. A user whose IdP account is disabled can continue to use an existing session until local expiry (default 24 h), and API tokens independently until their expiration/revocation. Define the desired deprovisioning SLA and implement/administer it explicitly. This is conditional on IdP policy expectations, not an OAuth protocol exploit.
5. **OAuth subject identity is not namespaced by issuer.** `app/auth.py:290`, `app/auth.py:313`, `app/models.py:27` key accounts only by `sub`. This is coherent for exactly one fixed provider. Reusing the DB after provider/tenant migration can bind a new provider's equal `sub` to an old account. Add issuer identity before multi-provider use or document/migrate on provider changes; this is a future/operational hazard, not a demonstrated current remote attack.
6. **UserInfo-only trust is explicit but provider guarantees remain unverified.** No ID token signature/issuer/audience/nonce validation occurs (`app/auth.py:242-274`), because identity is read from the configured UserInfo endpoint through the access token. Do not declare “missing nonce” a standalone vulnerability in this single-provider authorization-code/PKCE/state flow. If full OIDC behavior is intended, use a maintained OIDC client and verify ID token claims and UserInfo subject consistency. Confirm subject uniqueness/stability and `email_verified` semantics with the actual IdP. HTTPS certificate verification is enabled by httpx defaults.
7. **HTTP OAuth errors produce generic server failures rather than controlled auth failures.** Transport timeouts, malformed JSON, non-mapping responses, and malformed profile types are not handled in `app/auth.py:216-274`; they can lead to 500 responses. httpx default timeouts exist; it is inaccurate to claim no timeout at all. Add explicit configured connection/read limits, bounded response sizes, typed responses, and safe internal exception logging. Treat provider input as untrusted schema even though the endpoint is configured.
8. **Profile/subject validation is incomplete.** `get_unity_userinfo()` requires only truthy subject/email. `get_or_create_user()` converts arbitrary values to strings, truncates profile fields to 255, and leaves subject unbounded before persisting to `String(255)`. SQLite allows overly long subjects; PostgreSQL rejects them. Require bounded nonempty strings and validate actual email syntax/verified status when email influences privileged grants. Avoid truncating privilege-relevant identifiers before comparison.
9. **Admin allowlists are sticky.** Removing a subject/email from config does not remove a previously granted DB role (`app/auth.py:331-349`). This belongs in AUTH-01's precedence policy and operator documentation. Email-based admin grant additionally depends on address ownership/reassignment guarantees; subject-based grants are safer and correctly documented as preferred.
10. **JWT claim schema could be stricter.** Decoder pins HS256 and requires exp/sub, but does not require jti, session epoch, issuer, audience, issued-at, or token purpose. `get_current_user()` rejects missing epoch for current users, so missing epoch is not an auth bypass. `is_jwt_revoked()` treats missing jti as not revoked. Requiring current session claim schema would fail closed for future internal call sites; keep dedicated random signing keys unique per environment. No unsigned/algorithm-confusion acceptance was found.
11. **Session epoch increments are Python read-modify-write operations.** `app/auth.py:205` can lose increments under parallel role/password changes. Use an atomic DB increment or row lock if simultaneous security updates are possible; production concurrency behavior is unverified. In-flight requests authorized before a revocation may finish, a normal race requiring explicit operational expectations for high-risk operations.
12. **OAuth state/PKCE cookies persist on error paths.** They are deleted only on successful callback (`app/main.py:231-232`), not on provider error/missing code/failed state/exchange. They have 5-minute browser expiry. Clear on terminal outcomes and support independent login transactions if multi-tab convenience matters; no state bypass was established.
13. **Callback query parameters may appear in access logs/history.** Authorization codes and state arrive via GET (`app/main.py:209-224`). PKCE and one-time short-lived codes reduce replay risk, but proxy/application access-log redaction must be verified. Same-origin referrers can include the callback URL under strict-origin-when-cross-origin, though the callback immediately redirects on success. Consider a callback-specific no-referrer policy and query redaction.
14. **Authentication exception mapping drops WWW-Authenticate.** The global handler at `app/main.py:68-71` omits `exc.headers`, including the challenge set in `app/auth.py:129-132`. This is protocol correctness and client integration hardening, not privilege escalation.
15. **Protected API failures redirect with 307.** `app/main.py:64-67` converts special 302 auth failures to RedirectResponse's default 307. A request body/method can be resubmitted to `/` during client redirect following. The target is the same origin and `/` has no unsafe handler, so no external credential leak was demonstrated. APIs should use clear 401/403; browser navigation should use suitable 303 where method conversion is intended.
16. **Error responses outside normal middleware may lack security headers/cache control.** `security_headers_middleware` decorates successful/handled responses; outer body-limit 413 and uncaught ServerErrorMiddleware failures may lack it. Parent/infrastructure audit can verify. Add policy at the outermost response layer/proxy where required.
17. **No in-app session-management inventory/all-session logout.** The underlying session epoch supports invalidation, but users do not have a clear global logout/session list and admins cannot directly terminate OAuth sessions while leaving account/tokens otherwise managed. Add an incident-response control if required.
18. **No provider access/refresh token persistence.** This is positive for minimization; the OAuth access token is used for UserInfo and not stored. Local logout also does not sign out of the provider; make session semantics clear.
19. **Key validation does not prove entropy.** The application rejects named defaults/short/shared keys but accepts 64 identical characters. That is unavoidable from length alone; generate cryptographically random secrets, store them properly, rotate signing keys operationally, and verify policy in deployment. The HMAC/token/tombstone key has no versioned rotation path; parent audit should document the lifecycle risk.
20. **Configuration accepts unbounded and negative values in many fields.** A synthetic config with `jwt_expiration_hours=-1` and `max_body_bytes=-1` passed validation. This generally causes availability/configuration failures, not a remote privilege bypass. Cross-validate maximum generated token length against 256-character input validation and reject unsupported runtime values.
21. **No registration endpoint was found.** `allow_registration` exists but is unused. Local accounts are admin-provisioned. OAuth auto-provisions any successful IdP subject not tombstoned, so admission policy is the IdP/client application policy; document this explicitly and add domain/group/tenant restrictions only if the intended audience requires them.

## Positive controls verified in source/tests

- HS256 is explicitly pinned; JWT signature, expiry, and subject validation use PyJWT; randomized jti supports per-session revocation.
- DB-backed identity and admin roles are consulted on each authenticated request; deleted accounts cannot use local sessions.
- Password resets and explicit role transitions increment the session epoch (`app/api/admin.py:299,307`).
- OAuth authorization code grant uses random state and S256 PKCE; verifier/state are HttpOnly host-only short-lived cookies and are cleared on success.
- Session, CSRF, state, and verifier cookies default to Secure, HttpOnly, SameSite=Lax, Path=/ and `__Host-` names; cookie deletion preserves the same attributes.
- Constant-time byte comparisons avoid non-ASCII `compare_digest` crashes.
- CSRF covers unsafe cookie-authenticated requests; bare form posts are only allowed on explicit paths that validate their form token. A fake Bearer header does not bypass cookie routes outside `/api/v1/`.
- API token storage uses HMAC-SHA256 with a separate key; token entropy is at least 128 bits through config validation and defaults to 256 bits.
- Account matching is by OAuth subject, never email linking; OAuth/local accounts sharing an email remain independent. Verified email required for email-derived admin privileges unless explicit trusted-provider override is enabled.
- Local-password auth is restricted to local accounts (`unity_id IS NULL`); admins cannot give OAuth accounts a bypass password. Local login disabled by default.
- Dummy bcrypt prevents the obvious unknown-user/no-hash timing difference; generic failure responses avoid direct account enumeration. New password inputs reject >72 bytes and verification handles existing truncated bcrypt hashes consistently.
- Tombstones prevent ordinary deleted OAuth identity resurrection and store keyed identifiers instead of plaintext data.
- Strict CSP excludes inline/eval scripts, frame denial blocks clickjacking, nosniff and HSTS are set, sensitive responses are no-store.
- Admin token search uses a POST body and never echoes the full plaintext token into the result page/URL.
- Pydantic bounds multiple UI input fields; parameterized SQLAlchemy selects avoid injection in reviewed auth/profile/admin lookup flows.
- Built-in API docs are disabled unless debug is explicitly enabled.
- Logging reviewed login/auth paths includes internal IDs and safe client metadata rather than session/API/OAuth credential values.
- `yaml.safe_load()` avoids executable YAML tags; key env overrides are supported and validated on config load.

## Existing test coverage and gaps

Read: `tests/test_security.py`, `tests/test_secure_cookies.py`, `tests/conftest.py`, auth-related portions of token/API tests. Tests cover secure cookie prefixes/attributes, CSRF enforcement, state/PKCE challenge construction and callback verifier presence, verified-email admin grants, subject/email separation, session epochs, tombstones, password truncation boundaries, local/OAuth login separation, last-admin checks through admin functions, and some logging/limits/header checks.

Important gaps: configured-admin demotion followed by re-login; stale-session promotion; sole-admin self-deletion; durable logout failure and actual HTTP JWT replay; limiting auth rejection paths; event-loop responsiveness under password checks; distributed/per-account throttling; malformed/oversized provider responses; typed OAuth subjects; deployed IdP TLS/MFA/claim guarantees; provider changes/deprovisioning; simultaneous role/session changes; real production PostgreSQL concurrency; security headers on 413/500 paths.

Several tests assert source-code strings or invoke `__wrapped__`, so they do not by themselves prove full middleware/dependency order. The new safe probes deliberately exercised the real HTTP dependency path for stale-session admin access and revoked-session rate limits, and actual persistence functions for security transition failures. Existing suite execution is handled by the parent audit to avoid duplicate full runs.

## Probe output summary

- Configured admin after explicit demotion: False.
- Configured admin after next OAuth login: True.
- Failed revocation commit: no exception, no persisted blacklist row, original JWT accepted.
- Sole-admin self-service deletion: HTTP function response 200, zero admins remain.
- Synchronous bcrypt check: 0.168 s locally; 10 ms timer delivered after 0.168 s.
- Old pre-promotion cookie after config promotion: `/api/admin/users` HTTP 200.
- 130 revoked-cookie dashboard requests: 130 HTTP 307, no 429 despite 120/minute setting.
- Common password `Password1`: accepted.
- Plain HTTP OAuth back-channel URLs and insecure cookies: accepted by security validation.
- Negative JWT lifetime/body limit: accepted by configuration validation.

## Unverified assumptions and boundaries

Actual IdP behavior (PKCE enforcement, code reuse, redirect URI exact matching, subject persistence, MFA, email verification), TLS/front-proxy controls, production local-auth enablement, client IP trust, production secrets/entropy, external deprovisioning operations, DB/network ACLs, deployment logging, and incident-response procedures were not tested by this sub-audit. No active attacks or load tests were run against live services. No severity here assumes attacker control of configured endpoints or secrets unless explicitly stated in preconditions. No complete-production assurance can be inferred from these local results alone.

## Final OIDC, credential-lifecycle, and telemetry detail

### OIDC classification

The current code is best described as an OAuth authorization-code login using a fixed provider's bearer-protected identity endpoint, with state and PKCE. It requests OpenID scopes but ignores any `id_token` returned by the token endpoint. This is incomplete if the project claims strict OIDC Relying Party validation, but the code alone does not demonstrate a remote token-substitution attack against a fixed honest HTTPS provider: the access token is taken directly from that provider's response to the bound code exchange. The missing OIDC checks should be documented as a conditional protocol/assurance gap, not exaggerated into an unauthenticated account-takeover finding.

For full OIDC behavior, check token issuer, intended client audience, validity, approved algorithms/signature or permitted authenticated token-endpoint response validation rules, and any requested nonce/auth-time/assurance claims. Match UserInfo subject to the validated identity token before consuming profile data. Key stored accounts by a configured issuer plus subject, not naked subject, before provider changes. [OpenID Connect Core §5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse) requires UserInfo/ID-token subject consistency; [§5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability) defines the issuer/subject pair as stable identity. A nonce is optional in the authorization-code flow, and PKCE/state already supply important protections here; merely reporting “no nonce” as a standalone exploit would be misleading.

### Credential lifecycle matrix

| Event | Current browser session | Other browser sessions | API tokens | Operational implication |
|---|---|---|---|---|
| Successful logout with durable revocation | Cleared and jti blacklisted | Unaffected | Unaffected | Current-session sign-out only; no global logout control. |
| Logout blacklist commit fails | Cookie cleared, JWT remains valid elsewhere | Unaffected | Unaffected | AUTH-03 silent persistence failure. |
| Local password reset | Epoch invalidated | Epoch invalidated | Unaffected | A copied API credential survives password reset; incident procedure must explicitly revoke tokens. |
| Explicit admin role change | Epoch invalidated | Epoch invalidated | Unaffected | Good session control; API tokens are independent of web role state. |
| Config-based admin promotion | Old session remains valid | Old sessions remain valid | Unaffected | AUTH-01 stale sessions gain admin power. |
| Config admin entry removal | Existing DB privilege persists | Existing DB privilege persists | Unaffected | Role and config controls need coherent precedence. |
| Application account deletion | User lookup fails | User lookup fails | Removed through cascade | Durable app-side disable; tombstone blocks OAuth recreation. |
| Upstream IdP disabled/deleted/logout | No immediate app-side effect | No immediate app-side effect | No immediate app-side effect | Deprovisioning SLA and external integration must be defined. |
| JWT signing key rotation | Invalidated | Invalidated | Unaffected by design | Useful emergency session termination; coordinate across workers. |
| Token HMAC key replacement | Browser JWTs unaffected | Browser JWTs unaffected | Existing hashes no longer match | Also changes tombstone matching; no versioned migration/rotation path. |

Password reset intentionally preserving independently issued API credentials can be appropriate, but must be explicit. For a compromised account, the operator needs a supported “invalidate sessions and revoke all API tokens” action and evidence that it completed. The existing password/role endpoint does not perform that combined incident response.

### Missing audit events and correlation

Relevant evidence: `app/main.py:226`, `app/main.py:320-332`, `app/main.py:420-428`, `app/auth.py:157-158`, `app/auth.py:332-334`.

- Successful OAuth/local logins log internal user ID and method but no client source, session identifier hash, or event correlation ID. Source IP is logged only on local failures.
- Local failures have no bounded normalized account identifier/hash for per-account stuffing detection; OAuth failures and invalid-state attempts are not security-audited here.
- Logout success/revocation failure, CSRF failures, session epoch rejection, blacklist use, and config-driven admin grants have no dedicated audit event.
- Role/password changes are audited through the admin API; config-driven role transitions bypass that audit trail.
- Broadly swallowed profile/revocation persistence errors give no safe internal error signal. Profile-update failure is generally an availability-friendly choice, but revocation failure is security-sensitive.

Add structured security events with safe internal IDs, event type/outcome, source context determined through trusted proxy rules, bounded correlation identifiers, and revocation/grant result. Never log the plaintext JWT, API key, OAuth access token, authorization code, PKCE verifier, password, or client secret. Avoid retaining unnecessary plaintext personal identifiers; set access control, retention, and alerting for audit logs. The audit logger's existence is already tested, but semantic coverage and failure alerts need end-to-end tests.

### Probe safety confirmation

Both preserved probe scripts now explicitly remove inherited `CONFIG_PATH`, `DATABASE_URL`, `TEST_DATABASE_URL`, `RATE_LIMIT_STORAGE_URI`, `JWT_SECRET_KEY`, `TOKEN_HASH_KEY`, `OAUTH_CLIENT_SECRET`, and HTTP proxy endpoint variables before installing their synthetic test values. They only load `tests/config.test.yaml`, never the developer's config, and create new temporary SQLite databases. They make no external HTTP calls and never inspect the actual production secret values. Both scripts were rerun after this environment-clearing change and reproduced the results above (bcrypt timing 0.170 seconds on the second run).

## Additional confirmed race finding

### AUTH-07 — Concurrent security changes lose session-epoch increments and fail to invalidate an intermediate session (Medium)

Evidence: Python read-modify-write in `app/auth.py:203-205`; password reset call at `app/api/admin.py:297-299`; role transition call at `app/api/admin.py:305-307`; SQLAlchemy user load at `app/api/admin.py:284-285`; auth enforcement at `app/auth.py:193-194`.

`invalidate_sessions()` calculates the next epoch from the current in-memory User object. Two request sessions can each load epoch 0. The first reset persists epoch 1. A user then signs in and obtains a session with sep=1. The second request's identity-mapped User still has epoch 0; its update persists epoch 1 again, instead of advancing to 2. The newly issued session survives the second security change. An extra SELECT in the second update does not refresh already-loaded identity-map attributes automatically, so calling the actual update function after the first commit reproduces the stale value.

Preconditions: overlapping per-user password/role mutations that load the same earlier User state, plus a session issued between the first and second commits. The probe deterministically coordinated the overlap rather than asserting a high probability in production. No production concurrency policy or PostgreSQL load behavior was tested.

Impact: a password reset or administrative security change can claim to terminate every existing session while an intermediate session remains valid. In a compromise response, an attacker who signs in during the first change can retain a session beyond the second reset; concurrent role transitions can similarly fail the intended invalidation boundary. No unauthenticated attacker can directly invoke the administrative updates.

Safe evidence: `/private/tmp/token-generator-session-epoch-probe.py` loads the same local user in two real independent async SQLAlchemy sessions, invokes real `update_user.__wrapped__()` for two password resets, and uses `get_current_user()` in a new verification session. Output: both initially see 0; first reset persists 1; second still holds 0; second reset persists 1; a cookie created between the resets is accepted afterward.

Remediation: increment the epoch atomically in SQL (`session_epoch = session_epoch + 1`) in the same transaction as password/role mutation, obtaining the refreshed result before issuing any session; or serialize per-user security mutations with a DB row lock. An optimistic version column plus conflict retry can also prevent stale writes. Audit every caller, including config-driven changes, to maintain the invariant.

Regression tests: deterministic two-session interleavings for password reset/password reset, role change/role change, and password reset/role change; assert that the final epoch reflects all relevant committed changes and that a session issued between changes is rejected after the later change. Run a real PostgreSQL case because production locking and transaction behavior differ from SQLite.

This safe probe upgrades Additional Observation 11 above from a suspected concurrency weakness to a confirmed local lost-update reproduction. Production frequency/triggerability remains unverified. The script explicitly clears inherited config/secrets/URLs and uses a new temporary SQLite database; no live services are called.
