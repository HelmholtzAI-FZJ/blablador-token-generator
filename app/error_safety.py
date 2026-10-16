import logging

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("token_generator.audit")


class ErrorSafetyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracked_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except Exception as exc:
            route = getattr(scope.get("route"), "path", "unmatched")
            logger.error("action=request_failed method=%s path=%s error_type=%s",
                         scope["method"], route, type(exc).__name__)
            if started:
                raise RuntimeError("HTTP response interrupted") from None
            await JSONResponse({"detail": "Request could not be completed"}, status_code=500)(scope, receive, send)
