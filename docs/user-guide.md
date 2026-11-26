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

## Courses

If an administrator made you a teacher, the dashboard has a **Courses** card.

1. Enter the course name, the first and last day, and the number of seats, and
   accept the terms. A course lasts at most 21 days and has at most 60 seats
   by default; you can run one course at a time.
2. Copy the **join link** and share it with your students only. It is shown
   once; **New join link** replaces it (the old one stops working).
3. Each student signs in, opens the link and presses **Join and get my token**.
   They get one token, `blablador-course-…`, that works from the first day
   until the end of the last day (UTC). Course tokens cannot be renewed or
   rotated, and a student cannot join a second time.
   Or press **Invite by email**: paste the students' addresses, adjust the
   message, and the service mails each of them a personal link that works
   once. Each invitation holds a seat until it is used or you cancel it;
   **Resend** mails a new link and disables the old one. Students may sign in
   with any account, not only the address you used.
4. **Students** lists who joined, and the invitations with their state, when each token was last used and how often.
   A token used far more than the others may have been shared: **Revoke** it.
   A revoked student's seat stays used.
5. **Revoke all and close** ends the course at once: every token stops working
   and the link is disabled.

Once all seats are claimed the link stops working, so a leaked link can be
used at most as many times as there are seats.

## Sign out

**Logout** ends the session on the server, so a copied session cookie stops
working too. Sessions also end on their own after at most 24 hours (one hour
for administrators).
