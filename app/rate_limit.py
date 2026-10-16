import asyncio
from functools import wraps
from ipaddress import ip_address, ip_network

from fastapi import HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from app.auth import decode_access_token
from app.config import get_config
from app.cookies import SESSION_COOKIE

RATE_LIMITS = get_config().rate_limits
_TOKEN_VALIDATION_EXEMPT = [
    ip_network(entry, strict=False) for entry in RATE_LIMITS.token_validation_exempt
]


class AsyncLimiter(Limiter):
    def limit(self, *args, **kwargs):
        decorate = super().limit(*args, **kwargs)

        def async_decorate(func):
            wrapped = decorate(func)

            @wraps(wrapped)
            async def check_then_call(*args, **kwargs):
                request = kwargs.get("request") or (args[0] if args else None)
                if self.enabled and not getattr(request.state, "_rate_limiting_complete", False):
                    await asyncio.to_thread(self._check_request_limit, request, func, False)
                    request.state._rate_limiting_complete = True
                return await wrapped(*args, **kwargs)

            check_then_call.__wrapped__ = func
            return check_then_call

        return async_decorate


def build_limiter(storage_uri: str) -> Limiter:
    """Rate limiter keyed by client IP unless a route says otherwise.

    Counters live in storage_uri (Redis in production) so they are shared
    across workers and replicas. If that storage becomes unreachable, each
    process keeps enforcing the same limits in memory until it recovers,
    instead of failing every request (token validation included).
    """
    options = {}
    if storage_uri.startswith(("redis://", "rediss://")):
        timeout = RATE_LIMITS.storage_timeout_seconds
        options = {"socket_timeout": timeout, "socket_connect_timeout": timeout}
    return AsyncLimiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        storage_options=options,
        in_memory_fallback_enabled=True,
        swallow_errors=True,
    )


def user_or_ip(request: Request) -> str:
    """Key for authenticated endpoints: the signed-in user, else the client IP.

    Users behind one NAT address must not share a budget.
    """
    session = request.cookies.get(SESSION_COOKIE)
    if session:
        try:
            return f"user:{decode_access_token(session)['sub']}"
        except HTTPException:
            pass
    return get_remote_address(request)


def is_token_validation_exempt(request: Request) -> bool:
    try:
        client = ip_address(get_remote_address(request))
    except ValueError:
        return False
    return any(client in network for network in _TOKEN_VALIDATION_EXEMPT)


limiter = build_limiter(RATE_LIMITS.storage_uri)
