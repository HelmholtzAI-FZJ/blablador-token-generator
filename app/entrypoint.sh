#!/bin/sh
set -eu

WORKERS="${WORKERS:-2}"
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"
GRACEFUL_SHUTDOWN_SECONDS="${GRACEFUL_SHUTDOWN_SECONDS:-20}"
case "$GRACEFUL_SHUTDOWN_SECONDS" in
    ''|*[!0-9]*) echo "GRACEFUL_SHUTDOWN_SECONDS must be a whole number of seconds." >&2; exit 1 ;;
esac
case "$WORKERS" in
    ''|*[!0-9]*) echo "WORKERS must be between 1 and 32." >&2; exit 1 ;;
esac
if [ "${#WORKERS}" -gt 2 ] || [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 32 ]; then
    echo "WORKERS must be between 1 and 32." >&2
    exit 1
fi
case "$FORWARDED_ALLOW_IPS" in
    *'*'*) echo "Proxy trust must name specific addresses or networks." >&2; exit 1 ;;
esac
# No WebSocket support: the service has no WebSocket routes, and Uvicorn
# would log every handshake's path and query string. The keep-alive timeout
# outlasts the ingress's idle upstream connections (60 s in ingress-nginx).
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers "$WORKERS" --proxy-headers --forwarded-allow-ips "$FORWARDED_ALLOW_IPS" --no-access-log --ws none --no-server-header --timeout-keep-alive 75 --timeout-graceful-shutdown "$GRACEFUL_SHUTDOWN_SECONDS"
