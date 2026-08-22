from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limiter: limits by client IP address.
# Applied to sensitive endpoints (login, token validation, OAuth callbacks)
# to prevent brute-force attacks and token enumeration.
limiter = Limiter(key_func=get_remote_address)
