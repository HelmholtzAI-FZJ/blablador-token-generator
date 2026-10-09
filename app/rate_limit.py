from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_config


def build_limiter(storage_uri: str) -> Limiter:
    """Rate limiter keyed by client IP.

    Counters live in storage_uri (Redis in production) so they are shared
    across workers and replicas. If that storage becomes unreachable, each
    process keeps enforcing the same limits in memory until it recovers,
    instead of failing every request (token validation included).
    """
    return Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        in_memory_fallback_enabled=True,
        swallow_errors=True,
    )


limiter = build_limiter(get_config().app.rate_limit_storage_uri)
