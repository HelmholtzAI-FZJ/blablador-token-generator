from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_config

# Rate limiter: limits by client IP address.
# Applied to sensitive endpoints (login, token validation, OAuth callbacks)
# to prevent brute-force attacks and token enumeration. Counters live in
# rate_limit_storage_uri (Redis in production) so they are shared across
# workers and replicas.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=get_config().app.rate_limit_storage_uri,
)
