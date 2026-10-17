# Configuration reference

Configuration is one YAML file, read from `CONFIG_PATH` (default:
`config.yaml` in the repository root; `/app/config/config.yaml` in the
container image). Start from
[`config.yaml.example`](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/blob/main/config.yaml.example).
Unknown keys are rejected, so a typo stops the service from starting instead of
being ignored.

## Environment variables

Secrets and deployment-specific values can come from the environment instead
of the file; the environment wins.

| Variable | Overrides |
| --- | --- |
| `APP_ENVIRONMENT` | `app.environment` |
| `JWT_SECRET_KEY` | `app.secret_key` |
| `TOKEN_HASH_KEY` | `app.token_hash_key` |
| `OAUTH_CLIENT_SECRET` | `oauth.client_secret` |
| `DATABASE_URL` | `database.url` |
| `DATABASE_SSL_CA_FILE` | `database.ssl_ca_file` |
| `RATE_LIMIT_STORAGE_URI` | `rate_limits.storage_uri` |

The process launchers read a few more: `WORKERS` (Uvicorn worker processes,
1–32, default 2), `FORWARDED_ALLOW_IPS` (proxies whose `X-Forwarded-*` headers
are trusted, default `127.0.0.1`), `GRACEFUL_SHUTDOWN_SECONDS` (container
only, default 20) and `HOST`/`PORT` (`start.sh` only).

## Production checks

With `app.environment: production` (the default) the service refuses to start
unless:

- `secret_key` and `token_hash_key` are different, at least 32 characters, and
  not a known default or `REPLACE_…`/`YOUR_…` placeholder;
- `debug` is off and `secure_cookies` is on;
- sign-in is possible: a complete OAuth client (`client_id`, `client_secret`
  and all four URLs) or `local.enabled`;
- `app.api_url` and the OAuth URLs are `https://` without credentials or
  fragments;
- the database is PostgreSQL (`postgresql+asyncpg://`) with TLS, verified
  against `ssl_ca_file` or with `ssl=verify-full`;
- rate-limit counters are in Redis over verified TLS (`rediss://`, certificate
  and host name checked);
- the database and Redis URLs do not repeat a query parameter (clients
  disagree on which copy counts);
- `FORWARDED_ALLOW_IPS` and `token_validation_exempt` contain only IP
  addresses or networks written without host bits (`10.42.0.0/16`, not
  `10.42.0.7/16`, which Uvicorn would silently ignore), each no wider than
  `/8`, and never `*`;
- the database role is not a superuser and cannot create roles or databases,
  replicate or bypass row security; it is not a member of the predefined roles
  that reach server files and programs, every table (`pg_read_all_data`,
  `pg_write_all_data`), subscriptions or other sessions; and it has no
  `EXECUTE` on the server-file functions (`pg_read_file`, `lo_export`, …) and
  no `SET`/`ALTER SYSTEM` grant on server parameters. Monitoring roles such
  as `pg_monitor` are allowed.

`development` relaxes the transport and storage rules (SQLite, in-memory
counters, plain HTTP) for local work. Never use it for a shared deployment.

## `app`

| Key | Default | Description |
| --- | --- | --- |
| `environment` | `production` | `production` or `development`; see above. |
| `name` | `Token Generator` | Shown in page titles and headers. |
| `host`, `port` | `0.0.0.0`, `8080` | Only used by `python -m app.main`; the launchers bind on their own. |
| `secret_key` | — (required) | Signs session cookies (JWT, HS256). Rotating it signs everyone out but keeps API tokens valid. |
| `token_hash_key` | — (required) | Keys the HMAC-SHA256 of stored API tokens and of deleted-account records. **Never change it** without a migration plan: every token stops working. |
| `debug` | `false` | Exposes interactive API docs at `/docs`. Development only. |
| `api_url` | `https://localhost:8080` | Public base URL, shown in the dashboard's usage example. |
| `secure_cookies` | `true` | `Secure` cookies with the `__Host-` prefix. Disable only for plain HTTP on localhost. |
| `jwt_expiration_hours` | `24` | Session lifetime, 1–24. |
| `admin_jwt_expiration_hours` | `1` | Session lifetime for administrators, 1–24, at most `jwt_expiration_hours`. |
| `log_level` | `INFO` | Level of the `token_generator.*` loggers. Audit events are always kept at `INFO`. |
| `access_log` | `true` | One line per request (route template, status, duration, client); never query strings. |
| `max_body_bytes` | `65536` | Largest accepted request body, 1 KiB–1 MiB. |
| `body_timeout_seconds` | `10` | Deadline for receiving a request body (`408` after), up to 60. |
| `max_concurrent_requests` | `128` | Requests in progress per worker before answering `503`, 1–4096. |
| `readiness_timeout_seconds` | `2` | Deadline for each `/readyz` dependency check, up to 10. |

## `database`

| Key | Default | Description |
| --- | --- | --- |
| `url` | `sqlite+aiosqlite:///./tokens.db` | SQLAlchemy URL. Production: `postgresql+asyncpg://user:password@host:5432/db`; percent-encode reserved characters in the password. |
| `echo` | `false` | Log SQL statements (bound values are never logged). |
| `ssl_ca_file` | none | CA certificate that signed the PostgreSQL server certificate; enables verified TLS with host-name checking. |
| `auto_migrate` | `true` | Apply pending schema migrations at startup. If `false`, startup refuses an outdated schema; run `python -m app.migrate`. See [Upgrades](operations/upgrades.md). |
| `connect_timeout_seconds` | `5` | Connection deadline, up to 30. |
| `statement_timeout_seconds` | `5` | Per-statement deadline (server-side `statement_timeout`), up to 60. Migrations use 120 s. |
| `lock_timeout_seconds` | `2` | Lock-wait deadline, up to 30 and at most the statement timeout. |
| `idle_transaction_timeout_seconds` | `15` | Ends transactions left idle, up to 120 and at least the statement timeout. |

## `oauth`

The identity provider. Leave `client_id` empty to disable OAuth sign-in.

| Key | Default | Description |
| --- | --- | --- |
| `client_id`, `client_secret` | empty | Confidential client credentials. |
| `authorize_url`, `token_url`, `userinfo_url` | empty | Provider endpoints. For JSC Login: `https://login.jsc.fz-juelich.de/oauth2-as/oauth2-authz`, `…/oauth2/token`, `…/oauth2/userinfo`. |
| `redirect_uri` | empty | Must be registered exactly: `https://<host>/oauth/openid/callback`. |
| `scopes` | `[]` | Usually `openid`, `profile`, `email`. |
| `trust_provider_emails` | `false` | Treat the provider's email as verified even without `email_verified: true`. Only if the provider guarantees it. |
| `request_timeout_seconds` | `10` | Overall deadline for the token and user-info calls, up to 60. |
| `max_response_bytes` | `65536` | Largest accepted provider response. |

Accounts are identified by the provider's subject (`sub`) only; the email is
profile data and never links or takes over another account.

## `login`

| Key | Default | Description |
| --- | --- | --- |
| `name` | `Login` | Name on the sign-in button ("Login with …"), e.g. `JSC Login`. |
| `description` | `Authenticate to create and manage API tokens for your applications.` | Text on the start page. |

## `local`

Password accounts created by administrators (there is no self-registration).

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable the `/login/local` form. |
| `allow_registration` | `false` | Must stay `false`; public registration is not supported. |
| `max_concurrent_password_operations` | `4` | bcrypt operations at once per worker; more answer `503`. |
| `blocked_passwords` | a short list | Passwords refused when set or reset (compared case-insensitively). Extend it with your organisation's list. |

## `tokens`

| Key | Default | Description |
| --- | --- | --- |
| `default_expiration_days` | `90` | Lifetime when none is chosen; the dashboard's preset date. |
| `max_expiration_days` | `365` | Longest allowed lifetime, 1–365. |
| `token_length_bytes` | `32` | Random bytes per token (hex-encoded), 16–127. |
| `token_prefix` | `blablador` | Text before the `-`; helps secret scanners and people recognise the token. |
| `max_tokens_per_user` | `100` | Tokens one account may hold, in any state. |
| `last_used_update_seconds` | `60` | How often a token's *last used* time is written at most. |

## `rate_limits`

Limits use the [limits](https://limits.readthedocs.io/) syntax, such as
`120/minute` or `10/second`.

| Key | Default | Description |
| --- | --- | --- |
| `storage_uri` | `memory://` | Counter storage. Production: `rediss://:<password>@<host>:6379/0?ssl_ca_certs=<ca file>&ssl_cert_reqs=required&ssl_check_hostname=true`. |
| `storage_timeout_seconds` | `0.5` | Redis connect/read deadline. |
| `preauth` | `240/minute` | Admission budget for every request except token validation, per client address (IPv6: per /64). |
| `pages` | `120/minute` | Pages and the sign-in redirect, per address. |
| `oauth_callback` | `60/minute` | OAuth callback, per address. |
| `local_login` | `10/minute` | Password sign-in attempts per address. |
| `local_login_account` | `5/minute` | Password sign-in attempts per account. Fails closed when Redis is unavailable. |
| `tokens_read` | `60/minute` | Token listing, per user. |
| `tokens_write` | `30/minute` | Token changes, per user. |
| `session` | `30/minute` | Logout, per user. |
| `account_delete` | `5/minute` | Account deletion, per user. |
| `admin` | `120/minute` | Administration, per user. |
| `token_validation` | `600/minute` | Validation API, per address; also its admission budget. |
| `token_validation_exempt` | `[]` | Addresses or networks (for example the API gateway) exempt from validation limits. |

## `admin`

Bootstrap rules that make an account an administrator **when it is first
created**. Changing them later does not affect existing accounts; manage roles
in the admin panel. See [Administration](operations/administration.md).

| Key | Default | Description |
| --- | --- | --- |
| `admin_subjects` | `[]` | OAuth subjects. Preferred: a subject cannot be chosen by the user. |
| `admin_emails` | `[]` | Emails, honoured only when the provider marks the email verified (or `oauth.trust_provider_emails`). |

## `blablador`

| Key | Default | Description |
| --- | --- | --- |
| `api_url` | `https://ptj.blablador.fz-juelich.de` | Reserved; not used by this release. |
| `models` | `[]` | Reserved; not used by this release. |
