import asyncio
import logging

from limits import parse
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_config
from app.auth import hash_token, normalize_email
from app.rate_limit import is_token_validation_exempt

logger = logging.getLogger('token_generator.audit')


async def enforce_account_login_limit(email: str) -> None:
    from fastapi import HTTPException
    from app.rate_limit import limiter

    key = hash_token('local-login:' + normalize_email(email))
    budget = parse(get_config().rate_limits.local_login_account)
    try:
        allowed = await asyncio.to_thread(FixedWindowRateLimiter(limiter._storage).hit,
                                         budget,
                                         'local-account', key)
    except Exception as exc:
        logger.error('action=login_storage_failed error_type=%s', type(exc).__name__)
        raise HTTPException(status_code=503, detail='Login temporarily unavailable') from None
    if not allowed:
        raise HTTPException(status_code=429, detail='Too many login attempts', headers={'Retry-After': str(budget.get_expiry())})


class AdmissionMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.config = get_config()
        uri = self.config.rate_limits.storage_uri
        options = {}
        if uri.startswith(('redis://', 'rediss://')):
            timeout = self.config.rate_limits.storage_timeout_seconds
            options = {'socket_timeout': timeout, 'socket_connect_timeout': timeout}
        self.storage = storage_from_string(uri, **options)
        self.counter = FixedWindowRateLimiter(self.storage)
        self.budget = parse(self.config.rate_limits.preauth)
        self.active = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        if scope['path'] == '/healthz' and scope['method'] == 'GET':
            await JSONResponse({'status': 'ok'})(scope, receive, send)
            return
        if self.active >= self.config.app.max_concurrent_requests:
            await JSONResponse({'detail': 'Service busy'}, status_code=503)(scope, receive, send)
            return
        self.active += 1
        try:
            request = Request(scope)
            exempt = scope['path'] == '/api/v1/auth/validate' and is_token_validation_exempt(request)
            if not exempt:
                client = request.client.host if request.client else '-'
                try:
                    allowed = await asyncio.to_thread(self.counter.hit, self.budget, 'admission', client)
                except Exception as exc:
                    logger.error('action=admission_storage_failed error_type=%s', type(exc).__name__)
                    await JSONResponse({'detail': 'Authentication service temporarily unavailable'}, status_code=503)(scope, receive, send)
                    return
                if not allowed:
                    await JSONResponse({'detail': 'Too many requests'}, status_code=429,
                                       headers={'Retry-After': str(self.budget.get_expiry())})(scope, receive, send)
                    return
            await self.app(scope, receive, send)
        finally:
            self.active -= 1
