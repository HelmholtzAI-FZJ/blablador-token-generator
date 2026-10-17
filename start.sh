#!/bin/bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

show_usage() {
    echo "Usage: $0 [development|production]"
    echo "HOST defaults to 127.0.0.1, PORT to 8080, and WORKERS to 2."
    echo "Production requires the configured shared Redis backend and HTTPS proxy."
    echo "FORWARDED_ALLOW_IPS defaults to 127.0.0.1; trust only the proxy's addresses."
}

case "${1:-development}" in
    help|--help|-h)
        show_usage
        exit 0
        ;;
    development|production)
        mode="${1:-development}"
        ;;
    *)
        show_usage >&2
        exit 1
        ;;
esac

if [[ ! -x .venv/bin/python || ! -f .venv/bin/activate ]]; then
    echo "Missing project virtualenv; install the frozen dependencies with uv sync." >&2
    exit 1
fi
source .venv/bin/activate

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
WORKERS="${WORKERS:-2}"
if [[ ! "$PORT" =~ ^[0-9]+$ || "$PORT" -lt 1 || "$PORT" -gt 65535 ]]; then
    echo "PORT must be between 1 and 65535." >&2
    exit 1
fi
if [[ ! "$WORKERS" =~ ^[0-9]+$ || "$WORKERS" -lt 1 || "$WORKERS" -gt 32 ]]; then
    echo "WORKERS must be between 1 and 32." >&2
    exit 1
fi
if [[ "${FORWARDED_ALLOW_IPS:-127.0.0.1}" == *'*'* ]]; then
    echo "FORWARDED_ALLOW_IPS must name the trusted proxy addresses, never *." >&2
    exit 1
fi

export APP_ENVIRONMENT="$mode"
if [[ "$mode" == development ]]; then
    exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload --no-access-log --ws none --no-server-header
fi
exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --workers "$WORKERS" --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" --no-access-log --ws none --no-server-header --timeout-keep-alive 75
