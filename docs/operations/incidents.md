# Incident response

Security actions take effect for every request that starts after they are
stored. Gateways that cache validation results keep accepting a revoked token
until their cache entry expires: purge those caches as part of each step.

## A token leaked

1. **Find the owner.** Admin panel, **Tokens** tab, **Search** with the token
   value (it is compared by hash and not logged).
2. **Note its last use first.** *Last used* shows the latest validation of
   the token's current value. Rotating resets it and deleting removes it; the
   audit log keeps the time (`rotate_token … previous_last_used_at=`,
   `delete_token … last_used_at=`). The gateway's logs show what was done
   with the token.
3. **Stop it.** The owner rotates or revokes it on their dashboard, or an
   administrator revokes it in the Tokens tab. Keep revoked tokens (no
   **Delete Revoked**) until the investigation is over.

Renewing does not help: it keeps the leaked value.

## An account is compromised

1. Admin panel, **Users** tab, **Revoke All Credentials** for the account. All
   its tokens are revoked and all its sessions end, including requests waiting
   to change data.
2. Have the person secure their identity provider account (password, second
   factor). For a **local** account, also **Reset Password**: revoking
   credentials leaves the password, which the attacker may know or have set.
   Until then, consider **Delete** instead: a deleted account cannot sign in
   again until an administrator restores it.
3. If the account is an administrator, review the audit log for
   administrator actions (`admin=<user id>`) since the compromise.

## Someone leaves the organisation

Disabling a person at the identity provider stops new sign-ins but **not** the
API tokens they already hold. Make your leaver process do one of:

- **Revoke All Credentials** (the account remains and could sign in again
  if the identity provider allowed it), or
- **Delete** (tokens are removed and the subject is blocked from signing in
  again until restored).

Both are available in the API (`POST /api/admin/users/{id}/revoke-credentials`,
`DELETE /api/admin/users/{id}`) for automation; they need an administrator
session.

## Rotate keys and passwords

| Secret | Effect of changing it | How |
| --- | --- | --- |
| `app.secret_key` | Every session ends; API tokens keep working. | Change the Secret, bump `secretRevision`, `helm upgrade`. All replicas must switch together (mixed keys cause random sign-outs during the rollout). |
| `app.token_hash_key` | **Every API token stops working** and deletion records no longer match. | Only after a confirmed key compromise, as a planned operation: revoke all tokens, change the key, ask everyone to create new tokens, and re-delete accounts that must stay deleted. |
| PostgreSQL runtime password | Application reconnects with the new password. | As the administrator inside the database pod, `kubectl exec -it <release>-blablador-token-generator-postgresql-0 -- psql -U token_admin -d tokens -c '\password tokens'` (psql hashes the new password before sending it; an `ALTER ROLE … PASSWORD '…'` statement can end up in the server log). Then update `password` and `database-url` in the credentials Secret, bump `secretRevision`, upgrade. Existing connections stay open until they end; restart PostgreSQL to drop them after a compromise. |
| Redis password | Rate-limit counters reset. | Update `password` and `storage-uri` in the Secret, bump `secretRevision`, upgrade (Redis and the application restart together). |
| Datastore certificates | None if the CA stays the same. | Renew the TLS Secrets (cert-manager does this automatically), bump `secretRevision`, upgrade. When changing the CA, publish the new CA alongside the old one first. |

## The database or a backup leaked

Token values cannot be recovered from the stored HMAC digests without
`token_hash_key`, and passwords are bcrypt hashes. The data still contains
names, email addresses and token metadata, which is a personal data breach to
report under your organisation's procedure. If `token_hash_key` may have
leaked as well, treat it as above. Reset the passwords of local accounts.

## The identity provider is unavailable

Existing sessions and API tokens keep working; new sign-ins fail with a
"temporarily unavailable" page (`oauth_provider_failed` in the log). Local
accounts, if enabled, can still sign in.
