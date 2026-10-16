> Historical audit notes for baseline commit `3341bc087ffbf4f76b469cd7f272dfbeafdcebe3`, recorded 2026-10-11 before remediation. Findings and proposed fixes below are superseded by [the implemented remediation report](../REPORT.md). These notes preserve detailed original evidence; do not treat their old source line numbers, old deployment defaults, or suggestions as current behavior. Some temporary probe paths have equivalent saved probes in `../probes/`.

# API, persistence, middleware and browser security audit notes

Scope: `app/api/{tokens,validate,admin}.py`, `app/{models,database,tombstones,rate_limit,body_limit}.py`, `app/static/*.js`, all templates, corresponding route/dependency interactions in `app/main.py` and `app/auth.py`, and the test coverage for these paths. Audited source under `/Users/surak/Devel/blablador/token_generator` on 11 October 2026. No application source was changed. No real configuration, keys, tokens, database, identity provider, gateway, Redis, or live services were used in probes. Safe scripts force `CONFIG_PATH` to test configuration, synthetic keys and memory rate storage; every database is in-memory or a disposable `/private/tmp` directory. File locations and line numbers below refer to the audited source.

## Reproducible findings

### API-01 — Medium: the last-admin invariant is bypassable by self-deletion and races

Evidence: `app/main.py:338-368` implements account deletion for any authenticated user and never checks whether the user is the last administrator. The admin-only delete and demotion checks are at `app/api/admin.py:300-307,348-355`, relying on `is_last_admin` at `24-32`. Their count and mutation are separate operations without any serialized lock or database invariant.

Reproductions: `/private/tmp/token-generator-api-probes.py` created a sole admin in disposable SQLite, invoked the real unwrapped self-delete route, and received status 200 with zero remaining admins. In a separate disposable database with two admins, two concurrent demotion routes each queried the real admin count before either committed; both successfully demoted themselves and left zero admins. Synchronization wraps real AsyncSession.execute calls and waits only after each real COUNT query returns. It does not fabricate database results or change application logic.

Conditions/impact: requires an authenticated administrator or concurrent legitimate admin operations. A stolen admin session can deliberately remove the sole administrative account through self-deletion. Ordinary production workflows can accidentally eliminate the recovery/admin plane. Existing configured OAuth admin allowlists may permit some recovery via another configured identity, but the deleted identity has a tombstone and cannot simply sign in again. This is not privilege escalation by an ordinary user.

Fix: apply one shared last-admin rule to self-deletion, API deletion and demotion; serialize admin membership mutations using a stable advisory lock/invariant row or appropriate transaction strategy, not a count without locking. Provide and test a documented out-of-band bootstrap/recovery operation. Tests currently exercise the helper serially (`tests/test_security.py:215-236`), not the actual sole-admin self-delete or concurrent mutations.

### API-02 — Medium: token quota is a non-atomic check and can be exceeded

Evidence: `app/api/tokens.py:54-57` counts existing tokens, then generation/validation/insertion occurs before a separate commit at `93-95`. No per-user lock, quota counter or database constraint protects the limit.

Reproduction: configured max_tokens_per_user=1 and ran two real creates concurrently with a barrier after the real count queries. Both succeeded and two rows were stored. Script `/private/tmp/token-generator-api-probes.py`.

Conditions/impact: any authenticated user with concurrent requests. The rate limiter allows a burst and cannot serialize the quota decision. The maximum surplus from one burst is bounded by simultaneously admitted work unless combined with further scheduling; do not describe this as automatically unlimited storage from a single account. It defeats the advertised maximum and weakens resource protection. Existing serial quota test at `tests/test_security.py:1055-1067` does not cover concurrency.

Fix: transactionally lock a per-user row before count and insert for PostgreSQL, or use an atomic quota counter/reservation or equivalent database-specific serialized transaction. Ensure delete/create and quota enforcement share consistent semantics. Add actual concurrent tests against the production database engine.

### API-03 — Medium, conditional: local account creation restores unrelated OAuth tombstones by untrusted email

Evidence: `app/tombstones.py:60-62` removes every deletion record matching the normalized email hash, including OAuth subjects. `app/api/admin.py:239-240` calls it when creating a local user. The initial OAuth email can be unverified (`app/auth.py:291,317`); identity and deletion otherwise use subject specifically to avoid trusting email (`app/tombstones.py:1-5,42-51`).

Reproduction: created OAuth subject `unrelated-banned-subject` asserting `owner@example.invalid` with email_verified=false, recorded its deletion and removed it. The subject was blocked. Creating an unrelated local account for the same email through the real admin create route removed the OAuth subject tombstone. Its next get_or_create_user call succeeded. `/private/tmp/token-generator-tombstone-probe.py` reports blocked-before=true, blocked-after=false, resurrected=true.

Conditions/impact: an admin must create a local account matching an asserted email of a deleted OAuth identity. An attacker capable of claiming an unverified email can arrange the collision; this does not let them create local accounts themselves. Account-ban/reinstatement crosses the identity boundary without the admin specifically choosing the OAuth subject. Current comments/tests deliberately expect broad restoration by email, so this is a policy/trust issue in the intended behavior, not an overlooked API authorization dependency.

Fix: only clear local tombstones (`unity_id_hash IS NULL`) during local account creation. Provide a separate explicit OAuth subject reinstatement action keyed by stable subject and audit it. Do not use unverified email as an OAuth reinstatement identifier.

### API-04 — Medium availability: validation logging write failure causes an unexpected 500

Evidence: `app/api/validate.py:88-104` updates last_used_at, catches commit errors, rolls back, and then reads expired ORM attributes (`token.user_id`, `token.expires_at`) synchronously. AsyncSession.rollback expires loaded objects even with expire_on_commit=False.

Reproduction: real token query and isolated database, fault-injected AsyncSession.commit raising a synthetic write-outage exception; the existing rollback executed, then the real route raised `MissingGreenlet` instead of returning its intended response. `/private/tmp/token-generator-api-probes.py`.

Impact: database write outage, lock timeout or concurrent deletion causing an update failure can break token validation even when the read succeeded. It does not accept revoked credentials or bypass authentication. The swallowed initial failure also loses explicit operational diagnostics. Since token validation is the central service, graceful behavior must be intentional.

Fix: copy only the already-validated primitive response values before committing if last-used telemetry is explicitly best-effort, or explicitly fail with a service-unavailable response when a consistent write/transaction is required. Avoid implicitly refreshing after rollback; log sanitized failure category/metrics. Do not introduce a stale-token fallback cache without an explicit revocation policy.

### API-05 — Medium/production scale risk: every successful validation writes and commits to the same token row

Evidence: `app/api/validate.py:88-90` synchronously updates and commits every successful request, even if the token was used immediately beforehand. Token validation can be unthrottled for configured gateway CIDRs (`app/rate_limit.py:48-53`), and the route is externally useful (`app/api/validate.py:41-104`).

Impact: a popular API credential creates a hot write row, WAL/write amplification and connection occupancy; SQLite permits only limited write concurrency and PostgreSQL updates on one row serialize. Database stress becomes authentication service denial. Old delayed updates can overwrite newer last_used_at timestamps, making this telemetry regress. No load/capacity claim is proven here; this is source-confirmed amplification, with production throughput/latency requiring a representative staging test.

Fix: rate/coalesce last_used_at updates, use a bounded async telemetry mechanism or an atomic update only when older than a configured window, and preserve monotonic timestamps where useful. Set connection, statement, lock and limiter storage timeouts; measure validation p95/p99 and DB writes at expected gateway concurrency. Keep authoritative revocation reads strong; do not optimize them away accidentally.

### API-06 — Low robustness: valid ISO datetimes near the representable edge cause uncaught OverflowError

Evidence: `app/api/tokens.py:67-73,221-227` catches ValueError from parsing but not overflow from converting extreme offsets into UTC.

Reproduction: authenticated POST /tokens with expires_at=`9999-12-31T23:59:59-01:00` receives 500. The direct route raises OverflowError. The same normalization exists in renew. `/private/tmp/token-generator-api-probes.py` and `...-http-probes.py`.

Impact: authenticated, rate-limited malformed/edge inputs cause server errors; this alone does not compromise other users or persist an invalid token. Useful as an exception/error-path hardening finding, not a high severity denial claim.

Fix: a bounded typed datetime input validator that catches conversion failures, normalizes UTC and enforces now < expiration <= configured maximum; add boundary/offset tests. Current API also accepts a past expiration, producing an immediately unusable credential.

### API-07 — Low robustness: unbounded page number overflows database OFFSET

Evidence: `app/api/admin.py:74-85,195-205` and `app/main.py:281-291` bound page_size but only enforce page>=1; computed offset has no upper bound.

Reproduction: admin GET /api/admin/users?page=10**40 yields 500 on SQLite. `/private/tmp/token-generator-api-http-probes.py`.

Impact: admin-only request errors. Ordinary very high offsets also incur expensive scans at scale. No unauthenticated privilege boundary crossed.

Fix: a reasonable page upper bound/64-bit-safe offset check or keyset pagination and explicit next-page metadata.

### API-08 — Low secret hygiene: password validation errors echo supplied passwords

Evidence: password fields at `app/api/admin.py:57-67` use FastAPI/Pydantic default validation errors; an overlong password is included verbatim under error `input`.

Reproduction: POST /api/admin/users with a synthetic password longer than 128 characters receives 422 with that synthetic value in response JSON. HTTP probe prints only `echoes_input=true`, not the password. Response does correctly carry Cache-Control:no-store.

Impact: the authorized caller already supplied this value, so this is not independently an unauthorized disclosure. It adds an unnecessary credential copy in response bodies, which increases exposure if response/error collection is enabled in an observability system or client. The reset UI uses error message strings rather than input for normal Pydantic errors (`app/static/admin.js:146-152`), reducing direct UI exposure.

Fix: sanitize RequestValidationError output for password/token/secret fields or return structured messages without input. Verify request/response-body logging and APM redaction at deployment; never demonstrate the issue with production secrets.

### API-09 — Low header consistency: outer size limiter bypasses normal headers

Evidence: `app/main.py:162-164` adds BodySizeLimitMiddleware outside security_headers_middleware; rejection in `app/body_limit.py:51-53` returns directly.

Reproduction: oversized POST returns 413 without Cache-Control, CSP, HSTS or X-Content-Type-Options. `/private/tmp/token-generator-api-http-probes.py`.

Impact: this particular response is generic JSON and contains no token/PII, so no sensitive response leak was found. It makes the stated all-response security policy incomplete. Unhandled 500 paths likewise need verification through an outer response policy, rather than assuming the success middleware covers them.

Fix: apply security/cache headers at the outermost response layer or in rejection/error handlers as appropriate. Ensure security header checks cover 2xx, redirects, 401/403, 413, 422, 429 and unexpected 500 responses.

## Other production risks and intentional semantics to document

- **Route limits execute after dependencies.** SlowAPI decorators wrap the route body; FastAPI authentication/admin dependencies run first. A valid but revoked/old-epoch session, or a normal user hitting admin routes, can repeatedly cause auth database work and be rejected before the rate limiter executes. Cross-reference the auth audit's reproduction. Token-validation bearer extraction is cheap and its real token query executes in the limited route body, so this same specific bypass is not proven for validation. Edge/global limits are necessary, and sensitive denied-request paths should have pre-authentication budgets.
- **Slow request body occupancy.** `app/body_limit.py:28-38` awaits body chunks before authentication or per-route limits and has a byte cap but no read deadline. Very slow bodies can retain requests without exceeding the cap. This needs ingress/server header/body timeouts and connection/concurrency limits; do not infer their effective deployed values from source defaults. The middleware temporarily copies the body (bytearray -> bytes) but max_body_bytes bounds normal buffered size.
- **Limiter storage is synchronous.** SlowAPI/limits Redis operations are synchronous inside async routes. Long Redis timeouts/delays can block an event loop before memory fallback activates. In-memory fallback is intentionally per process (`app/rate_limit.py:18-30`), multiplying aggregate effective limits across workers/replicas during Redis failure. Swallow_errors also warrants monitoring to prove limits remain active. Test Redis blackholes/delay, not only immediate connection refusal.
- **Rate budgets are per endpoint by default.** Multiple routes using `RATE_LIMITS.tokens_write` need a shared limit group if the intended meaning is one total per-user write budget across create/revoke/delete/renew. User-specific limits do correctly avoid NAT contention (`user_or_ip`, `34-45`); the session is cryptographically decoded but its DB revocation/epoch is not checked by the key function.
- **Gateway exemptions and proxy trust.** Exempting a CIDR skips the validation limiter only; it does not authenticate the caller or bypass token validity. Restrict CIDRs to actual gateway identities and verify effective proxy IP trust/forwarded addresses. A broad exemption or common proxy address can remove useful protection or create shared-budget denial. Root deployment audit owns actual Helm/Compose settings.
- **Unbounded admin bulk purge.** `app/api/admin.py:112-121` loads every revoked token into Python, loops per-row deletes and commits all in one operation. The user quota bounds each account's current rows in the serial case but does not bound the total number of accounts/rows. Global history can exhaust memory, hold a long transaction or produce large WAL. Use bounded batches or efficient bulk delete with measured transactional policy; audit count/results without loading all rows.
- **No Token.user_id index.** `app/models.py:43` is a foreign key without an explicit index; token creation count/list/dashboard/user deletion filter by this column. Global tokens can grow with user count even with quotas. Add the relevant user_id/created_at index and verify production query plans/migration; this is a source schema performance risk, not a proven measured DoS at the current unknown row count.
- **Credential length configuration mismatch.** `TokenConfig.token_length_bytes` only has a lower bound (`app/config.py:52`), and `token_prefix` is unrestricted (`53`). `generate_token` creates prefix + dash + two hex characters per byte (`app/auth.py:105-107`), but validator/header and admin search cap at 256 (`app/api/validate.py:30-36`, `app/main.py:300`). A valid accepted config can generate credentials that can never validate. Startup should validate final encoded length <=256 and sane prefix characters/length.
- **Expired-token renewal reuses the plaintext credential.** `app/api/tokens.py:240` changes only expiration; it does not rotate token_hash and allows expired tokens. A previously stolen expired token becomes usable if the owner renews it. This is a design policy requiring clear UX/documentation; offer rotation/replacement as the preferred renewal/incident action. Revoked tokens remain revoked even if API renewal updates expiration (confirmed). Renewal without explicit duration uses expires_at-created_at (`216-231`), so repeated renewals can grow the inferred duration until max_expiration_days rejects it. Past expiration input is accepted. API and template datetimes omit UTC suffix, so browsers can render timestamps in local time inconsistently; backend comparisons normalize UTC and were not shown to bypass expiry.
- **Password reset/session revocation does not revoke API credentials.** Admin password change invalidates JWT sessions (`app/api/admin.py:291-299`), while existing API tokens remain valid. This may be intentional independence, but production incident containment must explicitly revoke API tokens and sessions as separate actions. Admin privilege changes likewise do not remove API tokens. There is no all-user-token revoke API beyond account deletion, so an incident workflow needs efficient safe bulk revocation.
- **Session-epoch concurrency.** `invalidate_sessions` increments a loaded integer in Python (`app/auth.py:203-205`), rather than an atomic increment/version-protected write. Concurrent resets can both write the same next epoch. A session issued after the first commit can survive the second reset. This was not dynamically probed by this sub-audit; the auth auditor should determine the relevant threat/workflow and use an atomic database increment/optimistic version if enforcing every reset boundary.
- **Validation orphan assumptions.** Validate accepts a token when token.user is absent because deletion checking is conditional (`app/api/validate.py:67`). Correctly enforced FK CASCADE should make such rows impossible; build_engine enables SQLite foreign keys (`app/database.py:17-22`), and SQLAlchemy relationships and FK deletion cascade are configured. For restored/legacy/corrupted databases, fail closed on missing owner and verify foreign keys exist/enforced. Do not present this as an ordinary IDOR or an exploitable current orphan state.
- **Readiness versus liveness.** `/healthz` only returns ok and does not test DB or limiter health (`app/main.py:180-182`). Deployment must distinguish liveness from authentication readiness and expose safe dependency metrics.
- **Error auditing and retention.** Create/revoke/delete/renew/admin mutations catch database errors and return generic 500s, but do not log sanitized error categories (`tokens.py:97-99,158-160,185-187,244-246`, `admin.py` commit handlers). Success audit records contain IDs and some admin-create emails. Revoked-token cleanup/permanent deletion removes DB records; external audit retention/access controls/PII deletion policy are therefore relevant. Do not log raw token, password, OAuth code or bound SQL parameters.
- **Input models.** Token/user names are bounded and parameters use SQLAlchemy queries. Admin email is a bounded string, not EmailStr; normalization can turn a whitespace-only supplied value into empty. OAuth profiles may be non-email strings. Validate semantics server-side where business rules need real addresses; local account creation is admin-only, so this is a low-risk data/operability issue.
- **Bearer scheme compatibility.** extract_bearer_token requires exact `Bearer ` capitalization. Authentication schemes normally permit case-insensitive matching; this is an interoperability/robustness issue, not a security bypass.
- **No scopes/audience in API token records.** Validation returns only valid/user_id/expires_at. Downstream service must map this to its own authorization/rate/quota rules. A token does not itself restrict endpoints, models, tenant, project, spend or privilege; do not infer those restrictions exist. Admin APIs use browser sessions, not these API tokens.

## Verified existing controls and non-findings

- Every ordinary user token query/mutation constrains both token ID and user ID (`tokens.py:119-123,147-149,174-176,207-209`). Actual HTTP probes: list returned only own tokens; cross-user revoke/delete/renew all 404. UUIDs reduce guessing but ownership filtering is the real control.
- All admin API operations depend on get_current_admin; normal signed-in user requests to admin listing and create both returned 403. get_current_admin reads current database admin state through current-user authentication, not a client admin flag.
- Token validation looks up the keyed token hash and revoked_at IS NULL, then checks tombstones and expiry. Expired and revoked HTTP validation both returned 401. Renewal of a revoked token returned revoked=true and continued to fail validation. SQLAlchemy only updates dirty columns, so last_used_at writes do not themselves clear revocation; ordinary in-flight validation started before a revocation commit is a boundary race, not evidence that a post-revocation request can succeed.
- Tokens are hashed with keyed HMAC; plaintext exists only during generation and is returned once. Standard read/admin response models exclude token_hash/plaintext/password_hash. Strong random generation and cryptographic details are covered by auth audit.
- SQLite FK enforcement and SQLAlchemy cascade configured; normal deletion cascades token/JWT rows. Parameterized expressions provide SQL injection resistance; hide_parameters=True suppresses bound sensitive values from SQL errors/logs (`database.py:29-35`).
- CSRF protects cookie-based state-changing routes through matching header or validated form; bearer bypass is confined to /api/v1/ and explicit Authorization. All UI mutation fetches attach csrfHeaders. Host-prefixed secure cookies in production prevent common subdomain cookie injection; root auth audit covers cookie deployment conditions.
- Jinja templates use default escaping and no `|safe` on user content. Browser `innerHTML` for admin users escapes name/email/id (`admin.js:47-64`) using textContent-based `escapeHtml` (`common.js:11-15`) that also encodes quotes. Dashboard inserted token names and IDs are escaped (`dashboard.js:297-305`); interpolated timestamps are parsed/generated server datetime strings. New plaintext tokens use textContent (`dashboard.js:260`). Calendar HTML is built from numeric dates and fixed strings. No dynamic code execution/eval or external script source was found. CSP restricts scripts to self and forbids inline code; form-action/base/object/frame protections exist.
- Clipboard output is an explicit user action. Clipboard API and fallback textarea contain only the newly minted token; fallback node is removed. The token remains in a hidden DOM element until reload/next token; this is deliberate convenience, but any same-origin script/XSS/browser extension can read it despite its visual mask. The current reviewed code did not reveal an XSS path that makes this exploitable. Consider explicit dismissal/clear and communicate that a hidden token is only visually hidden.
- Cache-Control:no-store covers ordinary token/PII responses and password validation errors, and static files are revalidated. Tokens in admin search use POST body, no URL/history/log query; the result doesn't echo plaintext. CSP and frame headers prevent basic framing; root auth audit covers top-level error header gaps.
- Request body cap bounds Content-Length and accumulated chunked bodies before parsing. Tested >64KB body ->413. Header cap/body timeouts are distinct server controls and require deployment verification.
- Admin list page sizes are <=100, name lengths <=255, token expiry days are constrained in request models and maximum future lifetime enforced. User list is not paginated but intended quota normally bounds its rows, with race caveat above.
- No open redirect, path traversal, user-controlled template file selection or file upload flow was found in this scoped code.

## Probe inventory and observed output

1. `/private/tmp/token-generator-api-probes.py`: quota max=1, creates=[created,created], stored_count=2; sole-admin self-delete status=200, remaining_admins=0; two concurrent demotions=[demoted,demoted], remaining_admins=0; extreme date raises OverflowError; injected validation write failure raises MissingGreenlet.
2. `/private/tmp/token-generator-api-http-probes.py`: list_own_only=true; other_user_{revoke,delete,renew}=404; nonadmin_{users,create_user}=403; expired_validate=401; revoked_renew=true; revoked_validate_after_renew=401; extreme_date=500; password422 status=422, echoes_input=true, Cache-Control=no-store; hugepage=500; largebody=413, normal security headers absent.
3. `/private/tmp/token-generator-tombstone-probe.py`: subject_blocked_before_local_creation=true; subject_blocked_after_local_creation=false; OAuth resurrection=true.

All direct route probes intentionally bypass rate decorators and dependencies only when testing a local invariant with explicit synthetic User/AsyncSession inputs; HTTP authorization/header probes exercise the assembled ASGI app with real synthetic session cookies and real dependency resolution. No production authorization or downstream acceptance conclusions are inferred from direct calls. SQLite reproductions establish application-level logic and SQLite behavior; PostgreSQL-specific isolation, locks and timeout behavior should be repeated in disposable staging. Baseline/full test execution and coverage were assigned to root and are not duplicated here. Existing tests include source-string assertions and manually simulated operations, which can pass without proving actual route semantics/concurrency; findings include targeted actual route probes to cover that gap.
