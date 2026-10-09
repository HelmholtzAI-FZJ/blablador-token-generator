from starlette.responses import Response

from app.config import get_config

config = get_config()


def cookie_name(base: str) -> str:
    """Cookie name, with the __Host- prefix whenever cookies are Secure.

    Browsers only accept a __Host- cookie from this exact host over HTTPS,
    host-only and with Path=/, so pages on other hosts of the same site
    (any *.fz-juelich.de) cannot plant or overwrite it.
    """
    return f"__Host-{base}" if config.app.secure_cookies else base


SESSION_COOKIE = cookie_name("access_token")
CSRF_COOKIE = cookie_name("csrf_token")
OAUTH_STATE_COOKIE = cookie_name("oauth_state")


def set_cookie(response: Response, name: str, value: str, max_age: int | None = None) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        path="/",
        secure=config.app.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def delete_cookie(response: Response, name: str) -> None:
    # A __Host- cookie can only be cleared with the same attributes it was set with.
    response.delete_cookie(
        name, path="/", secure=config.app.secure_cookies, httponly=True, samesite="lax"
    )
