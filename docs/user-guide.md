# User guide

## Sign in

Open the service and choose **Login with JSC Login**. You are sent to the
identity provider and back. The first sign-in creates your account; your name
and (verified) email address are taken from the identity provider.

If the page says your account has been disabled, an administrator deleted it.
Signing in again does not recreate it: ask an administrator to restore it.

## Create a token

On the dashboard, enter a name that tells you later where the token is used
(for example `laptop scripts` or `CI pipeline`), pick an expiry date and
choose **Create Token**.

!!! warning "The token is shown once"
    Copy it immediately with **Copy** (or reveal it with **View**). The service
    stores only a keyed hash and cannot show the value again. If you lose it,
    rotate the token or create a new one.

Tokens look like `blablador-` followed by 64 hexadecimal characters. The
expiry date can be at most the configured maximum (365 days by default) in the
future.

## Use a token

Send the token as a bearer credential, the way OpenAI-compatible clients send
an API key:

```bash
curl https://<blablador-api>/v1/models \
     -H "Authorization: Bearer $BLABLADOR_TOKEN"
```

Keep tokens out of source code, URLs, logs and chat messages; use your tool's
secret store or an environment variable.

## Manage your tokens

The table lists each token's name, creation time, last use (updated at most
once a minute), expiry and status. Times are shown in your browser's time zone.

| Action | What happens | Use it when |
| --- | --- | --- |
| **Renew** | Moves the expiry date; the token value stays the same. Also works for expired tokens. | A token you still control is about to expire. |
| **Rotate** | Replaces the value; the old value stops working immediately. The new value is shown once. | A token may have leaked, or as routine hygiene. |
| **Revoke** | The token stops working at once; it stays listed as *Revoked*. | You no longer need it, or it leaked. |
| **Delete** | Removes a revoked token from the list. | Cleaning up. |
| **Revoke All Tokens and Sessions** | Revokes every token you own and signs out all your browser sessions. | You suspect your account or a device is compromised. |

Rotating an expired token needs a new expiry date: renew it first, or create a
new token.

!!! tip "If a token leaked"
    Rotate or revoke it right away, then check **Last Used** for activity you
    do not recognise. Renewing does **not** help: it keeps the leaked value.

There is a limit on how many tokens one account can hold (100 by default,
counting revoked and expired ones). Delete revoked tokens you no longer need.

## Sign out

**Logout** ends the session on the server, so a copied session cookie stops
working too. Sessions also end on their own after at most 24 hours (one hour
for administrators).
