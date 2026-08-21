#!/bin/bash

# Token Generator Service Startup Script

source .venv/bin/activate

# Get number of CPU cores (default to 4 if detection fails)
CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Default settings
HOST="0.0.0.0"
PORT="8080"
WORKERS=$CPU_CORES

show_usage() {
    echo "Usage: $0 [development|production]"
    echo ""
    echo "  development  - Start with auto-reload (single worker)"
    echo "  production   - Start with multiple workers"
    echo ""
    echo "Environment variables (optional):"
    echo "  HOST         - Server host (default: 0.0.0.0)"
    echo "  PORT         - Server port (default: 8080)"
    echo "  WORKERS      - Number of workers (default: $CPU_CORES)"
    exit 1
}

case "${1:-development}" in
    development)
        echo "Starting in development mode..."
        exec uvicorn app.main:app --host "${HOST}" --port "${PORT}" --reload
        ;;
    production)
        echo "Starting in production mode with ${WORKERS} workers..."
        exec uvicorn app.main:app --host "${HOST}" --port "${PORT}" --workers "${WORKERS}"
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo "Unknown option: $1"
        show_usage
        ;;
esac
cloudflared tunnel --url localhost:8080/ | grep trycloudflare.com
