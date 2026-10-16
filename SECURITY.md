# Security — Token Generator

The comprehensive review and implemented fixes from **2026-10-11–12** are in [the security audit](security_audit/REPORT.md). See [CONTROLS.md](security_audit/CONTROLS.md) for every route/control, [THREAT_MODEL.md](security_audit/THREAT_MODEL.md) for trust boundaries, and [OPERATIONS.md](security_audit/OPERATIONS.md) for release/incident procedures. Raw evidence is preserved under `security_audit/evidence/`.

Production rejects default/placeholder keys, debug/insecure cookies, HTTP provider/redirect URLs, SQLite, per-process counters, unverified datastore TLS and universal proxy/gateway trust. Sessions use host-only Secure/HttpOnly cookies, state/PKCE, CSRF, durable revocation and atomic epochs. Existing admin roles survive OAuth login. Owner/quota/membership mutations are serialized and reauthenticated after locking; disabled rows do not count as usable admins.

API credentials are random and stored as separate-key HMAC-SHA256 digests. New/reset local passwords require 15 characters, a blocklist and bcrypt's 72-byte limit. Admission/body/password/counter/query/lock work is bounded. Failure responses/logs omit sensitive inputs; supported entrypoints disable query-bearing access logs. Edge log redaction remains a deployment requirement.

Helm/Compose require reviewed images, verified datastore TLS, constrained identities and hardened runtime settings. The chart requires explicit ingress/egress peers and Secrets. Existing databases need documented role/index upgrade: initialization environment changes do not rotate an existing password or remove superuser status.

This audit does **not certify an unseen deployment**. Real IdP MFA/lifecycle, ingress/CNI/TLS, release digests/architecture, Secrets, backups and monitoring require recorded acceptance evidence. Unpatched Debian findings remain visible with exact expiring workload non-affected assessments. Full OIDC ID-token verification and an automatic HMAC keyring/migration are not implemented.

The October 9 report is superseded. Its remote GitHub credential-rotation/deletion claim cannot be verified from the rewritten local object graph; historical incident follow-up is documented as unverified.
