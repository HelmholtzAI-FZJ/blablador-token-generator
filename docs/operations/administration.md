# Administration

Administrators open **Admin Panel** from the dashboard. Their sessions last
one hour (`app.admin_jwt_expiration_hours`).

## Who is an administrator

Administrator rights are stored per account in the database.

- **Bootstrap.** When an OAuth account is created at its first sign-in, it
  becomes an administrator if its subject is listed in
  [`admin.admin_subjects`](../configuration.md#admin) (preferred), or its
  provider-verified email in `admin.admin_emails`.
- **Afterwards**, these lists have no effect: removing someone from them does
  not demote them, and adding someone does not promote an existing account.
  Use **Make Admin** / **Remove Admin** in the **Users** tab. A role change
  signs the account out everywhere.
- The **last administrator who can sign in** cannot be demoted or deleted.
  Only accounts with a sign-in method the deployment offers count: OAuth
  accounts while OAuth is configured, local accounts with a password while
  `local.enabled` is true.
- **Locked out?** If no administrator can sign in, an operator with access to
  the deployment can grant the role from the command line (the account must
  have signed in once):

```bash
kubectl exec deploy/tokens-blablador-token-generator -- \
    python -m app.manage grant-admin --subject <OAuth subject>
```

Keep at least two administrators who sign in through the identity provider
with multi-factor authentication.

## Local accounts

When `local.enabled` is true, administrators can create password accounts in
the **Users** tab, for service operators or people without an identity
provider account. Otherwise the panel offers no form, and the API and the
command line refuse local accounts (they could not sign in). There is no
self-registration. Passwords need at least 15 characters, at most 72 bytes,
and must not be on the block list.

- **Reset password** sets a new password and ends the account's sessions. It
  does not revoke API tokens; use **Revoke All Credentials** for that.
- The first local administrator of a deployment without OAuth is created with
  `kubectl exec -it deploy/<release>-blablador-token-generator -- python -m
  app.manage create-local-admin --email … --name …`. It prompts for the
  password without echoing it; `-it` gives it a terminal. (`--password-stdin`
  reads a piped password and refuses a terminal.)

OAuth accounts cannot have passwords.

## Tokens tab

Lists every token, newest first, 100 per page, with its owner. Administrators
can revoke or delete any token, and **Delete Revoked** removes all revoked
tokens at once.

**Search** finds the owner of a token value someone reports (for example one
found in a public repository): paste the value; it is hashed and compared,
sent in the request body and never logged. Then revoke it and inform the
owner.

## Users tab

| Action | Effect |
| --- | --- |
| **Make Admin** / **Remove Admin** | Changes the role; the account's sessions end. |
| **Reset Password** | Local accounts only; sessions end. |
| **Revoke All Credentials** | Revokes every token of the account and ends its sessions. The person can sign in again and create new tokens. |
| **Delete** | Deletes the account and its tokens and records a deletion. The account cannot sign in again until restored. |
| **Restore Disabled OAuth Account** | Lets a deleted OAuth subject sign in again. They get a new, empty account. |

The OAuth subject shown under each OAuth account identifies it; the email
does not: the identity provider may report an unverified address, and two
accounts can show the same one. Confirmation dialogs therefore name the
account's name, email and subject. The subject is also what `admin_subjects`
and **Restore** expect. Record it before deleting an account you might restore
later: deletion records keep only a keyed hash of it. The audit log refers to
deleted and restored identities by a short keyed reference (`identity=oauth:…`)
that is the same in both events.

Deleting an account here does not affect the person's identity provider
account, and the identity provider disabling a person does not delete their
account here. Connect both in your leaver process; see
[Incident response](incidents.md#someone-leaves-the-organisation).
