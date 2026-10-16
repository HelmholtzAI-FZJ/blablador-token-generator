import asyncio

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Reject request bodies larger than max_bytes with 413.

    FastAPI reads and parses a body before authentication and rate limiting
    run, so without a cap anonymous clients could make every worker buffer
    and parse large payloads. The body (at most max_bytes) is read up front,
    covering both Content-Length and chunked uploads, then replayed to the app.
    """

    def __init__(self, app: ASGIApp, max_bytes: int, timeout_seconds: float = 10.0) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and (len(declared) > 20 or not declared.isdigit() or int(declared) > self.max_bytes):
            await self._reject(scope, receive, send)
            return

        body = bytearray()
        more_body = True
        try:
            async with asyncio.timeout(self.timeout_seconds):
                while more_body:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > self.max_bytes:
                        await self._reject(scope, receive, send)
                        return
                    more_body = message.get("more_body", False)
        except TimeoutError:
            await JSONResponse({"detail": "Request body timed out"}, status_code=408)(scope, receive, send)
            return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse({"detail": "Request body too large"}, status_code=413)
        await response(scope, receive, send)
