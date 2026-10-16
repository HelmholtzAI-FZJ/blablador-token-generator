#!/bin/sh
set -eu

if [ -z "${POSTGRES_USER:-}" ] || [ -z "${POSTGRES_PASSWORD:-}" ] || [ -z "${TOKEN_DB_USER:-}" ] || [ -z "${TOKEN_DB_PASSWORD:-}" ]; then
    printf '%s\n' 'Separate PostgreSQL administrator and runtime credentials are required.' >&2
    exit 1
fi
if [ "$TOKEN_DB_USER" = "$POSTGRES_USER" ] || [ "$TOKEN_DB_PASSWORD" = "$POSTGRES_PASSWORD" ]; then
    printf '%s\n' 'PostgreSQL runtime and administrator credentials must differ.' >&2
    exit 1
fi

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-psqlrc \
    --set=ON_ERROR_STOP=1 --set=runtime_user="$TOKEN_DB_USER" \
    --set=runtime_password="$TOKEN_DB_PASSWORD" --set=runtime_database="$POSTGRES_DB" <<'SQL'
CREATE ROLE :"runtime_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'runtime_password';
REVOKE ALL ON DATABASE :"runtime_database" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"runtime_database" TO :"runtime_user";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO :"runtime_user";
SQL

if [ "${TOKEN_DB_REQUIRE_TLS:-false}" = true ]; then
    umask 077
    { printf 'hostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\n'; cat "$PGDATA/pg_hba.conf"; } > "$PGDATA/pg_hba.conf.tmp"
    mv "$PGDATA/pg_hba.conf.tmp" "$PGDATA/pg_hba.conf"
fi
