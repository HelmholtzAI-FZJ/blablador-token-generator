from contextlib import asynccontextmanager
from urllib.parse import urlencode
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from app.config import get_config
from app.database import init_db, close_db, get_db
from app.models import User, Token
from app.auth import (
    get_current_user, get_current_admin, 
    get_or_create_user, get_unity_userinfo, create_access_token,
    hash_token, authenticate_local_user
)
from app.api import tokens, validate, admin

config = get_config()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title=config.app.name,
    description=f"Token authentication infrastructure on top of {config.login.name}",
    lifespan=lifespan
)


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


def get_oauth_login_url() -> str:
    params = {
        "response_type": "code",
        "client_id": config.oauth.client_id,
        "redirect_uri": config.oauth.redirect_uri,
        "scope": " ".join(config.oauth.scopes),
    }
    return f"{config.oauth.authorize_url}?{urlencode(params)}"


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "app_name": config.app.name,
        "login_name": config.login.name,
        "login_description": config.login.description,
        "config": config
    })


@app.get("/login")
async def login():
    return RedirectResponse(get_oauth_login_url())


@app.get("/callback")
async def callback(code: str, db: AsyncSession = Depends(get_db)):
    userinfo = await get_unity_userinfo(code)
    user = await get_or_create_user(userinfo, db)
    
    access_token = create_access_token(data={"sub": user.id})
    
    response = RedirectResponse(url="/dashboard")
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax"
    )
    return response


@app.get("/oauth/openid/callback")
async def openid_callback(request: Request, code: str | None = None, error: str | None = None, error_description: str | None = None, db: AsyncSession = Depends(get_db)):
    print(f"Callback - code: {code}, error: {error}, error_desc: {error_description}")
    print(f"Full query: {request.query_params}")
    
    if error:
        return {"detail": f"OAuth error: {error} - {error_description}"}
    
    if not code:
        return {"detail": "No code provided"}
    
    userinfo = await get_unity_userinfo(code)
    print(f"User info: {userinfo}")
    user = await get_or_create_user(userinfo, db)
    print(f"User created/retrieved: {user.id}, {user.email}")
    
    access_token = create_access_token(data={"sub": user.id})
    print(f"Access token created: {access_token[:20]}...")
    
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
        max_age=86400
    )
    print("Cookie set, redirecting to dashboard")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
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
async def admin_tokens(
    request: Request,
    search: str | None = None,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
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
        result = await db.execute(
            select(Token)
            .options(joinedload(Token.user))
            .order_by(Token.created_at.desc())
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


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    return response

@app.get("/login/local", response_class=HTMLResponse)
async def login_local_form(request: Request):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")
    return templates.TemplateResponse("login_local.html", {
        "request": request,
        "app_name": config.app.name,
        "error": None
    })

@app.post("/login/local")
async def login_local(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if not config.local.enabled:
        raise HTTPException(status_code=404, detail="Local login disabled")
    
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
        secure=False,
        path="/",
        max_age=86400
    )
    return response


@app.delete("/admin/api/tokens/revoked")
async def delete_revoked_tokens_api(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    from datetime import datetime
    result = await db.execute(
        select(Token).where(Token.revoked_at.isnot(None))
    )
    tokens = result.scalars().all()
    
    count = 0
    for token in tokens:
        await db.delete(token)
        count += 1
    
    await db.commit()
    
    return {"message": f"Deleted {count} revoked tokens"}


app.include_router(tokens.router)
@app.delete("/admin/tokens/{token_id}/permanent")
async def delete_token_admin_api(
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    await db.delete(token)
    await db.commit()
    
    return {"message": "Token deleted successfully"}


@app.delete("/admin/tokens/{token_id}/revoke")
async def revoke_token_admin_api(
    token_id: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Token).where(Token.id == token_id)
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token.revoked_at = datetime.utcnow()
    await db.commit()
    
    return {"message": "Token revoked successfully"}


app.include_router(validate.router)
app.include_router(admin.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.app.host, port=config.app.port)