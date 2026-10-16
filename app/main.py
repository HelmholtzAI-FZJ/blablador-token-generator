import asyncio
from contextlib import asynccontextmanager
import logging as _logging
from urllib.parse import urlencode
import secrets as _secrets
from secrets import compare_digest
from fastapi import FastAPI, Request, Depends, HTTPException, Form, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from sqlalchemy.orm import joinedload
from app.config import get_config
from app.database import init_db, close_db, get_db, lock_user_for_update
from app import database as database_module
from app.admission import AdmissionMiddleware, enforce_account_login_limit
from app.security_headers import SecurityHeadersMiddleware, headers_for_path
from app.error_safety import ErrorSafetyMiddleware
from app.models import User, Token
from app.tombstones import record_deletion
from app.auth import (
    get_current_user, get_current_admin,
    get_or_create_user, get_unity_userinfo, create_session_token,
    hash_token, authenticate_local_user, new_pkce_verifier, pkce_challenge,
    decode_access_token, revoke_jwt,
)
from app.api import tokens, validate, admin
from app.rate_limit import limiter, RATE_LIMITS, user_or_ip
from app.logging_config import configure_logging
from app.body_limit import BodySizeLimitMiddleware
from app.cookies import (
    CSRF_COOKIE, OAUTH_STATE_COOKIE, OAUTH_VERIFIER_COOKIE, SESSION_COOKIE,
    delete_cookie, set_cookie,
)

config = get_config()
configure_logging(config.app.log_level)
_audit = _logging.getLogger("token_generator.audit")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title=config.app.name,
    description=f"Token authentication infrastructure on top of {config.login.name}",
    lifespan=lifespan,
    docs_url=None if not config.app.debug else "/docs",
    redoc_url=None if not config.app.debug else "/redoc",
    openapi_url=None if not config.app.debug else "/openapi.json",
)

# Register rate limiter state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


from fastapi import HTTPException
from fastapi.responses import JSONResponse


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    if exc.status_code == 302:
        if request.url.path.startswith(("/api/", "/tokens")) or request.method != "GET":
            return JSONResponse(status_code=401, content={"detail": "Authentication required"}, headers=exc.headers)
        return RedirectResponse(url="/", status_code=303)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


from datetime import datetime
templates = Jinja2Templates(directory="app/templates")
templates.env.globals['now'] = datetime.utcnow


# CSRF protection: double-submit cookie pattern.
# Safe methods (GET, HEAD, OPTIONS, TRACE) receive an HttpOnly CSRF cookie;
# pages expose the same value in <meta name="csrf-token"> for scripts.
# State-changing requests must send it in the X-CSRF-Token header (fetch
# API) or as a "csrf_token" form field (plain HTML forms).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def secure_equals(a: str, b: str) -> bool:
    """Constant-time comparison; compare_digest raises on non-ASCII str."""
    return compare_digest(a.encode(), b.encode())

FORM_CSRF_PATHS = {"/login/local", "/admin/tokens/search"}
BEARER_PATH_PREFIX = "/api/v1/"


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    # Bearer-token API calls are not vulnerable to CSRF: the token is
    # explicitly supplied by the client, not auto-sent by the browser
    # like a cookie.  Skip the CSRF check for these requests.
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer ") and request.url.path.startswith(BEARER_PATH_PREFIX):
        return await call_next(request)

    cookie_token = request.cookies.get(CSRF_COOKIE)
    # Pages render this value into forms, so on a first visit the form
    # token matches the cookie set on the same response.
    request.state.csrf_token = cookie_token or _secrets.token_hex(32)

    if request.method in SAFE_METHODS:
        response = await call_next(request)
        if not cookie_token:
            set_cookie(response, CSRF_COOKIE, request.state.csrf_token)
        return response

    # State-changing request: validate CSRF token
    header_token = request.headers.get("x-csrf-token")

    if header_token:
        # Fetch API: header must match cookie
        if not cookie_token or not secure_equals(cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or invalid"}
            )
    else:
        # No header token: only endpoints that validate a csrf_token form
        # field themselves may accept plain form submissions.
        if request.url.path not in FORM_CSRF_PATHS:
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or invalid"}
            )

    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [{key: item[key] for key in ("loc", "msg", "type") if key in item}
              for item in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception):
    route = getattr(request.scope.get("route"), "path", "unmatched")
    _audit.error("action=request_failed method=%s path=%s error_type=%s",
                 request.method, route, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Request could not be completed"},
                        headers=headers_for_path(request.url.path))


app.add_middleware(BodySizeLimitMiddleware, max_bytes=config.app.max_body_bytes,
                   timeout_seconds=config.app.body_timeout_seconds)
app.add_middleware(AdmissionMiddleware)
app.add_middleware(ErrorSafetyMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


def get_oauth_login_url(state: str, code_challenge: str) -> str:
    params = {
        "response_type": "code",
        "client_id": config.oauth.client_id,
        "redirect_uri": config.oauth.redirect_uri,
        "scope": " ".join(config.oauth.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{config.oauth.authorize_url}?{urlencode(params)}"


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    try:
        async with asyncio.timeout(config.app.readiness_timeout_seconds):
            async with database_module.async_session_maker() as db:
                await db.execute(text("SELECT 1"))
            healthy = await asyncio.to_thread(limiter._storage.check)
            if not healthy:
                raise RuntimeError("rate-limit backend unavailable")
    except Exception as exc:
        _audit.error("action=readiness_failed error_type=%s", type(exc).__name__)
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return {"status": "ready"}


@app.get("/", response_class=HTMLResponse)
@limiter.limit(RATE_LIMITS.pages)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "app_name": config.app.name,
        "login_name": config.login.name,
        "login_description": config.login.description,
        "config": config
    })


@app.get("/login")
@limiter.limit(RATE_LIMITS.pages)
async def login(request: Request):
    # Random state (login CSRF) and PKCE verifier (code interception), both
    # kept in short-lived cookies until the callback.
    state = _secrets.token_hex(16)
    verifier = new_pkce_verifier()
    response = RedirectResponse(get_oauth_login_url(state, pkce_challenge(verifier)))
    set_cookie(response, OAUTH_STATE_COOKIE, state, max_age=300)
    set_cookie(response, OAUTH_VERIFIER_COOKIE, verifier, max_age=300)
    return response


@app.get("/oauth/openid/callback")
@limiter.limit(RATE_LIMITS.oauth_callback)
async def openid_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None, db: AsyncSession = Depends(get_db)):
    if error:
        return {"detail": "OAuth authentication failed"}

    # Verify OAuth state to prevent login CSRF
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    verifier = request.cookies.get(OAUTH_VERIFIER_COOKIE)
    if not state or not cookie_state or not verifier or not secure_equals(state, cookie_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    if not code:
        return {"detail": "No authorization code provided"}

    userinfo = await get_unity_userinfo(code, verifier)
    user = await get_or_create_user(userinfo, db)
    _audit.info("user=%s action=login method=oauth", user.id)

    response = RedirectResponse(url="/dashboard", status_code=303)
    set_cookie(response, SESSION_COOKIE, create_session_token(user),
               max_age=config.app.jwt_expiration_hours * 3600)
    delete_cookie(response, OAUTH_STATE_COOKIE)
    delete_cookie(response, OAUTH_VERIFIER_COOKIE)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
@limiter.limit(RATE_LIMITS.pages, key_func=user_or_ip)
async def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token)
        .where(Token.user_id == user.id)
        .order_by(Token.created_at.desc())
    )
    user_tokens = result.scalars().all()

    return templates.TemplateResponse(request, "dashboard.html", {
        "app_name": config.app.name,
            "api_url": config.app.api_url,
            "user": user,
            "tokens": user_tokens,
            "token_default_expiration_days": config.tokens.default_expiration_days,
            "token_max_expiration_days": config.tokens.max_expiration_days,
            "login_name": config.login.name
        }
    )


def form_csrf_valid(request: Request, submitted: str) -> bool:
    """Check a csrf_token form field against the cookie (for FORM_CSRF_PATHS)."""
    cookie_token = request.cookies.get(CSRF_COOKIE)
    return bool(cookie_token) and secure_equals(submitted, cookie_token)


def render_admin_tokens(request: Request, admin: User, tokens: list[Token], searched: bool):
    return templates.TemplateResponse(request, "admin.html", {
        "app_name": config.app.name,
        "user": admin,
        "tokens_with_users": [{"token": t, "user": t.user} for t in tokens],
        "searched": searched,
        "csrf_token": request.state.csrf_token,
        "login_name": config.login.name,
    })


@app.get("/admin/tokens", response_class=HTMLResponse)
@limiter.limit(RATE_LIMITS.admin, key_func=user_or_ip)
async def admin_tokens(
    request: Request,
    page: int = Query(1, ge=1, le=1000000),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    page_size = 100
    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user))
        .order_by(Token.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return render_admin_tokens(request, admin, list(result.scalars().all()), searched=False)


@app.post("/admin/tokens/search", response_class=HTMLResponse)
@limiter.limit(RATE_LIMITS.admin, key_func=user_or_ip)
async def admin_token_search(
    request: Request,
    token: str = Form(..., max_length=256),
    csrf_token: str = Form(..., max_length=256),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    # A POST body keeps the plaintext token out of URLs, access logs,
    # proxy logs and browser history.
    if not form_csrf_valid(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    result = await db.execute(
        select(Token)
        .options(joinedload(Token.user))
        .where(Token.token_hash == hash_token(token.strip()))
    )
    found = result.scalar_one_or_none()
    return render_admin_tokens(request, admin, [found] if found else [], searched=True)


@app.post("/logout")
@limiter.limit(RATE_LIMITS.session, key_func=user_or_ip)
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    # Revoke the JWT so it can't be replayed after logout
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        try:
            payload = decode_access_token(token)
            await revoke_jwt(payload, db)
        except HTTPException as exc:
            if exc.status_code != 401:
                raise

    response = JSONResponse(status_code=200, content={"detail": "Logged out"})
    delete_cookie(response, SESSION_COOKIE)
    _audit.info("action=logout")
    return response


_account_logger = _logging.getLogger("token_generator.account")


@app.post("/account/delete")
@limiter.limit(RATE_LIMITS.account_delete, key_func=user_or_ip)
async def delete_my_account(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Self-service account deletion: revokes all tokens, then removes the account.

    The user is logged out immediately.  A tombstone is written so the account
    cannot be recreated via OAuth until an admin explicitly re-creates it.
    """
    user = await lock_user_for_update(db, user.id, admin_membership=True)
    if user is None:
        raise HTTPException(status_code=401, detail="Account unavailable")
    if request.cookies.get(SESSION_COOKIE):
        user = await get_current_user(request, db)
    if user.is_admin and await admin.is_last_admin(db, user.id):
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining admin")

    user_id = user.id
    result = await db.execute(select(Token).where(Token.user_id == user.id))
    tokens = result.scalars().all()
    # 2. Write tombstone (blocks OAuth resurrection)
    record_deletion(db, user)

    # 3. Delete the user row (tokens via ORM cascade, revoked_jwts via FK)
    await db.delete(user)

    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        _account_logger.error("user=%s action=account_deletion_failed error_type=%s", user_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to delete account")

    # 4. Log deletion (safe — only internal IDs, no secrets)
    _account_logger.info(
        "user=%s action=account_deleted token_count=%d",
        user_id,
        len(tokens),
    )

    # 5. Sessions of a deleted user are rejected because the user lookup
    # fails; just clear the cookie.
    response = JSONResponse(
        status_code=200,
        content={"detail": "Account deleted. All tokens have been revoked."},
    )
    delete_cookie(response, SESSION_COOKIE)
    return response


@app.get("/login/local", response_class=HTMLResponse)
@limiter.limit(RATE_LIMITS.pages)
async def login_local_form(request: Request):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")
    return templates.TemplateResponse(request, "login_local.html", {
        "app_name": config.app.name,
        "csrf_token": request.state.csrf_token,
        "error": None
    })


@app.post("/login/local")
@limiter.limit(RATE_LIMITS.local_login)
async def login_local(
    request: Request,
    email: str = Form(..., max_length=255),
    password: str = Form(..., max_length=128),
    csrf_token: str = Form(..., max_length=256),
    db: AsyncSession = Depends(get_db)
):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")

    if not form_csrf_valid(request, csrf_token):
        return templates.TemplateResponse(request, "login_local.html", {
            "app_name": config.app.name,
            "csrf_token": request.state.csrf_token,
            "error": "Invalid CSRF token"
        }, status_code=403)

    await enforce_account_login_limit(email)
    user = await authenticate_local_user(email, password, db)
    if not user:
        client = request.client.host if request.client else "-"
        _audit.warning("action=login_failed method=local client=%s", client)
        return templates.TemplateResponse(request, "login_local.html", {
            "app_name": config.app.name,
            "csrf_token": request.state.csrf_token,
            "error": "Invalid email or password"
        }, status_code=401)

    _audit.info("user=%s action=login method=local", user.id)
    response = RedirectResponse(url="/dashboard", status_code=303)
    set_cookie(response, SESSION_COOKIE, create_session_token(user),
               max_age=config.app.jwt_expiration_hours * 3600)
    return response


app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Register API routers
app.include_router(tokens.router)
app.include_router(validate.router)
app.include_router(admin.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.app.host, port=config.app.port, access_log=False)
