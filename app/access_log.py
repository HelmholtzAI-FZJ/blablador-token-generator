import logging
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.clients import loggable_address

logger = logging.getLogger("token_generator.access")

# Kubelet probes would otherwise dominate the log.
QUIET_PATHS = {"/healthz", "/readyz"}


class AccessLogMiddleware:
    """One line per request, safe to ship to a central log store.

    Uvicorn's access log is disabled because it records query strings, which
    carry OAuth authorization codes. This logs the matched route template
    (never the raw path or query), the status and the duration. Requests
    that ended before any response was sent (the client went away) are
    logged with status=-.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in QUIET_PATHS:
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = "-"

        async def record_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = str(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, record_status)
        finally:
            route = getattr(scope.get("route"), "path", None)
            if route is None:
                route = "/static" if scope["path"].startswith("/static/") else "unmatched"
            client = scope.get("client")
            logger.info("method=%s route=%s status=%s duration_ms=%.1f client=%s",
                        scope["method"], route, status, (time.perf_counter() - started) * 1000,
                        loggable_address(client[0] if client else None))
