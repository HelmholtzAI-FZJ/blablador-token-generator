#!/bin/sh
set -eu
umask 077

password_hash=$(printf '%s' "$REDIS_PASSWORD" | sha256sum)
password_hash=${password_hash%% *}
# Counters (read and write commands) and the Lua scripts the rate limiter
# loads and runs; nothing else (no FUNCTION, no administration).
printf 'user default on #%s ~* &* +@read +@write +ping +eval +evalsha +script|load +script|exists -@dangerous\n' "$password_hash" > /data/users.acl
exec redis-server --aclfile /data/users.acl "$@"
