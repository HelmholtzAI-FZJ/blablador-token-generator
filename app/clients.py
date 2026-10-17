"""Client addresses for rate limiting and logging."""
import re
from ipaddress import ip_address, ip_network

from starlette.requests import Request

_UNSAFE_LOG_CHARACTERS = re.compile(r"[^0-9A-Za-z.:_-]")


def client_address(request: Request) -> str:
    """Key under which a client's requests are counted.

    IPv6 clients are counted per /64: one host or home network usually
    controls a whole /64 and could otherwise rotate through countless keys.
    """
    host = request.client.host if request.client else ""
    try:
        address = ip_address(host)
    except ValueError:
        return host or "-"
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ip_network((address, 64), strict=False))
    return str(address)


def loggable_address(host: str | None) -> str:
    """The client address as one log field.

    Behind a trusted proxy the address comes from X-Forwarded-For, so it is
    not guaranteed to be an IP address; keep it from splitting the field.
    """
    if not host:
        return "-"
    try:
        return str(ip_address(host))
    except ValueError:
        return _UNSAFE_LOG_CHARACTERS.sub("?", host)[:64]
