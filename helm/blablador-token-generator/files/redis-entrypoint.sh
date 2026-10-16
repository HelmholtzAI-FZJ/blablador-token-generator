#!/bin/sh
set -eu
umask 077

password_hash=$(printf '%s' "$REDIS_PASSWORD" | sha256sum)
password_hash=${password_hash%% *}
printf 'user default on #%s ~* &* +@read +@write +@scripting +ping -@dangerous\n' "$password_hash" > /data/users.acl
exec redis-server --aclfile /data/users.acl "$@"
