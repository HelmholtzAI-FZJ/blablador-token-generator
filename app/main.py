from contextlib import asynccontextmanager
from urllib.parse import urlencode
import secrets as _secrets
from secrets import compare_digest
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from app.config import get_config
from app.database import init_db, close_db, get_db
from app.models import User, Token, DeletedUser
from app.auth import (
    get_current_user, get_current_admin,
    get_or_create_user, get_unity_userinfo, create_access_token,
    hash_token, authenticate_local_user,
    decode_access_token, revoke_jwt,
)
from app.api import tokens, validate, admin
from app.rate_limit import limiter

config = get_config()


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
        return RedirectResponse(url="/")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


from datetime import datetime
templates = Jinja2Templates(directory="app/templates")
templates.env.globals['now'] = datetime.utcnow


# CSRF protection: double-submit cookie pattern.
# Safe methods (GET, HEAD, OPTIONS, TRACE) receive a csrf_token cookie.
# State-changing requests must send the cookie value in the X-CSRF-Token
# header (fetch API) or as a "csrf_token" form field (plain HTML forms).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
FORM_CSRF_PATHS = {"/login/local"}
BEARER_PATH_PREFIX = "/api/v1/"


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    # Bearer-token API calls are not vulnerable to CSRF: the token is
    # explicitly supplied by the client, not auto-sent by the browser
    # like a cookie.  Skip the CSRF check for these requests.
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer ") and request.url.path.startswith(BEARER_PATH_PREFIX):
        return await call_next(request)

    if request.method in SAFE_METHODS:
        response = await call_next(request)
        # Set/refresh CSRF cookie on safe requests
        if not request.cookies.get("csrf_token"):
            response.set_cookie(
                key="csrf_token",
                value=_secrets.token_hex(32),
                httponly=False,
                samesite="lax",
                secure=config.app.secure_cookies,
                path="/",
            )
        return response

    # State-changing request: validate CSRF token
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("x-csrf-token")

    if header_token:
        # Fetch API: header must match cookie
        if not cookie_token or not compare_digest(cookie_token, header_token):
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


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


def get_oauth_login_url(state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": config.oauth.client_id,
        "redirect_uri": config.oauth.redirect_uri,
        "scope": " ".join(config.oauth.scopes),
        "state": state,
    }
    return f"{config.oauth.authorize_url}?{urlencode(params)}"


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": config.app.name,
        "login_name": config.login.name,
        "login_description": config.login.description,
        "config": config
    })


@app.get("/login")
@limiter.limit("30/minute")
async def login(request: Request):
    # Generate a random state and store it in a short-lived cookie
    state = _secrets.token_hex(16)
    response = RedirectResponse(get_oauth_login_url(state))
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        secure=config.app.secure_cookies,
        path="/",
        max_age=300  # 5 minutes
    )
    return response


@app.get("/oauth/openid/callback")
@limiter.limit("10/minute")
async def openid_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None, db: AsyncSession = Depends(get_db)):
    if error:
        return {"detail": "OAuth authentication failed"}

    # Verify OAuth state to prevent login CSRF
    cookie_state = request.cookies.get("oauth_state")
    if not state or not cookie_state or not compare_digest(state, cookie_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    if not code:
        return {"detail": "No authorization code provided"}

    userinfo = await get_unity_userinfo(code)
    user = await get_or_create_user(userinfo, db)

    access_token = create_access_token(data={"sub": user.id})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=config.app.secure_cookies,
        path="/",
        max_age=config.app.jwt_expiration_hours * 3600
    )
    # Clear the OAuth state cookie
    response.delete_cookie("oauth_state", path="/")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
@limiter.limit("60/minute")
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

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "app_name": config.app.name,
            "api_url": config.app.api_url,
            "user": user,
            "tokens": user_tokens,
            "login_name": config.login.name
        }
    )


@app.get("/admin/tokens", response_class=HTMLResponse)
@limiter.limit("60/minute")
async def admin_tokens(
    request: Request,
    search: str | None = None,
    page: int = 1,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    # Cap search length to prevent abuse
    if search and len(search) > 128:
        search = search[:128]

    tokens_with_users = []

    if search:
        search_hash = hash_token(search)
        result = await db.execute(
            select(Token)
            .options(joinedload(Token.user))
            .where(Token.token_hash == search_hash)
        )
        token = result.scalar_one_or_none()
        if token:
            tokens_with_users.append({
                "token": token,
                "user": token.user
            })
    else:
        page_size = 100
        offset = (page - 1) * page_size
        result = await db.execute(
            select(Token)
            .options(joinedload(Token.user))
            .order_by(Token.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        tokens = result.scalars().all()
        for t in tokens:
            tokens_with_users.append({
                "token": t,
                "user": t.user
            })

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "app_name": config.app.name,
            "user": admin,
            "tokens_with_users": tokens_with_users,
            "search": search or "",
            "login_name": config.login.name
        }
    )


@app.post("/logout")
@limiter.limit("10/minute")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    # Revoke the JWT so it can't be replayed after logout
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = decode_access_token(token)
            await revoke_jwt(payload, db)
        except HTTPException:
            pass  # Token is invalid, proceed with logout anyway

    response = JSONResponse(status_code=200, content={"detail": "Logged out"})
    response.delete_cookie("access_token")
    return response


import logging as _logging
_account_logger = _logging.getLogger("token_generator.account")


@app.post("/account/delete")
@limiter.limit("5/minute")
async def delete_my_account(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Self-service account deletion: revokes all tokens, then removes the account.

    The user is logged out immediately.  A tombstone is written so the account
    cannot be recreated via OAuth until an admin explicitly re-creates it.
    """
    # 1. Revoke every token belonging to the user
    now = datetime.utcnow()
    result = await db.execute(select(Token).where(Token.user_id == user.id))
    tokens = result.scalars().all()
    for t in tokens:
        if t.revoked_at is None:
            t.revoked_at = now

    # 2. Write tombstone (blocks OAuth resurrection)
    db.add(DeletedUser(unity_id=user.unity_id, email=user.email))

    # 3. Delete the user row (cascades to revoke_jwt rows via FK)
    await db.delete(user)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete account")

    # 4. Log deletion (safe — only internal IDs, no secrets)
    _account_logger.info(
        "user=%s action=account_deleted token_count=%d",
        user.id,
        len(tokens),
    )

    # 5. Revoke the current session JWT so the browser is immediately logged out
    cookie = request.cookies.get("access_token")
    if cookie:
        try:
            payload = decode_access_token(cookie)
            await revoke_jwt(payload, db)
        except HTTPException:
            pass

    return JSONResponse(
        status_code=200,
        content={"detail": "Account deleted. All tokens have been revoked."},
    )


@app.get("/login/local", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def login_local_form(request: Request):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")
    # Use the cookie value if the browser already has one; otherwise generate
    # one now so the form hidden field matches the cookie that the CSRF
    # middleware will set on the response.
    csrf_value = request.cookies.get("csrf_token")
    if not csrf_value:
        csrf_value = _secrets.token_hex(32)
    return templates.TemplateResponse("login_local.html", {
        "request": request,
        "app_name": config.app.name,
        "csrf_token": csrf_value,
        "error": None
    })


@app.post("/login/local")
@limiter.limit("5/minute")
async def login_local(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")

    # Validate CSRF token: form field must match cookie value
    cookie_csrf = request.cookies.get("csrf_token")
    if not cookie_csrf or not compare_digest(csrf_token, cookie_csrf):
        return templates.TemplateResponse("login_local.html", {
            "request": request,
            "app_name": config.app.name,
            "error": "Invalid CSRF token"
        }, status_code=403)

    user = await authenticate_local_user(email, password, db)
    if not user:
        return templates.TemplateResponse("login_local.html", {
            "request": request,
            "app_name": config.app.name,
            "error": "Invalid email or password"
        }, status_code=401)

    access_token = create_access_token(data={"sub": user.id})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=config.app.secure_cookies,
        path="/",
        max_age=config.app.jwt_expiration_hours * 3600
    )
    return response


# Register API routers
app.include_router(tokens.router)
app.include_router(validate.router)
app.include_router(admin.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.app.host, port=config.app.port)
