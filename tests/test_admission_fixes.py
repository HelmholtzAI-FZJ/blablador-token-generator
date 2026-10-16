import asyncio
from pathlib import Path
import subprocess
import time

import pytest
from limits import parse

from app.admission import AdmissionMiddleware
from app.body_limit import BodySizeLimitMiddleware
from app.config import AppConfig, Config, DatabaseConfig, LocalAuthConfig, RateLimitConfig, TokenConfig
from app.rate_limit import AsyncLimiter
from app.security_headers import SecurityHeadersMiddleware
from app.error_safety import ErrorSafetyMiddleware
from starlette.requests import Request


def production_config() -> Config:
    return Config(
        app=AppConfig(secret_key="synthetic-jwt-" + "x" * 40, token_hash_key="synthetic-hmac-" + "y" * 40),
        database=DatabaseConfig(url="postgresql+asyncpg://user:password@database/tokens", ssl_ca_file="/synthetic/ca.crt"),
        rate_limits=RateLimitConfig(storage_uri="rediss://:password@redis/0"),
        local=LocalAuthConfig(enabled=True),
    )


@pytest.mark.parametrize("change", [
    lambda config: setattr(config.app, "secret_key", "REPLACE_WITH_PUBLIC_KEY_" + "x" * 40),
    lambda config: setattr(config.app, "secret_key", "  REPLACE_WITH_PUBLIC_KEY_" + "x" * 40),
    lambda config: setattr(config.app, "secret_key", " " * 64),
    lambda config: setattr(config.app, "debug", True),
    lambda config: setattr(config.app, "secure_cookies", False),
    lambda config: setattr(config.app, "api_url", "http://example.com"),
    lambda config: setattr(config.database, "url", "sqlite+aiosqlite:///tokens.db"),
    lambda config: setattr(config.database, "ssl_ca_file", None),
    lambda config: setattr(config.rate_limits, "storage_uri", "memory://"),
    lambda config: setattr(config.rate_limits, "storage_uri", "redis://redis/0"),
    lambda config: setattr(config.rate_limits, "storage_uri", "rediss://redis/0?ssl_cert_reqs=none"),
    lambda config: setattr(config.rate_limits, "storage_uri", "rediss://redis/0?ssl_check_hostname=false"),
])
def test_production_rejects_unsafe_configuration(change, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    config = production_config()
    config.validate_security()
    change(config)
    with pytest.raises(ValueError):
        config.validate_security()


@pytest.mark.parametrize("trusted", ["*", "0.0.0.0/0", "::/0"])
def test_production_rejects_universal_proxy_trust(trusted, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", trusted)
    with pytest.raises(ValueError):
        production_config().validate_security()


@pytest.mark.parametrize("kwargs", [
    {"token_length_bytes": 127}, {"max_expiration_days": 1}, {"max_tokens_per_user": 0},
])
def test_invalid_token_policies_rejected(kwargs):
    with pytest.raises(ValueError):
        TokenConfig(**kwargs)


def test_unknown_security_configuration_rejected():
    with pytest.raises(ValueError):
        AppConfig(secure_cookie=False)


def scope(path="/dashboard", headers=None):
    return {"type": "http", "path": path, "method": "GET", "scheme": "http", "query_string": b"",
            "headers": headers or [], "client": ("192.0.2.42", 8080), "server": ("test", 80)}


async def empty_receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def capture(app, request_scope=None, receive=empty_receive):
    messages = []

    async def send(message):
        messages.append(message)

    await app(request_scope or scope(), receive, send)
    return messages


@pytest.mark.asyncio
async def test_admission_limits_before_body_or_authentication():
    calls = 0

    async def expensive_app(request_scope, receive, send):
        nonlocal calls
        calls += 1
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AdmissionMiddleware(expensive_app)
    middleware.budget = parse("2/minute")
    assert (await capture(middleware))[0]["status"] == 200
    assert (await capture(middleware))[0]["status"] == 200

    async def forbidden_receive():
        raise AssertionError("Body consumed after admission rejection")

    messages = await capture(SecurityHeadersMiddleware(middleware), receive=forbidden_receive)
    assert messages[0]["status"] == 429 and calls == 2
    assert dict(messages[0]["headers"])[b"cache-control"] == b"no-store"


@pytest.mark.asyncio
async def test_admission_storage_failure_degrades_to_local_limits():
    import logging

    async def ok_app(request_scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AdmissionMiddleware(ok_app)
    middleware.budget = parse("2/minute")
    attempts = 0

    def unavailable(*args):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("synthetic-secret-must-not-leak")

    middleware.counter.hit = unavailable
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    audit = logging.getLogger("token_generator.audit")
    audit.addHandler(handler)
    try:
        statuses = [(await capture(middleware))[0]["status"] for _ in range(3)]
    finally:
        audit.removeHandler(handler)
    assert statuses == [200, 200, 429], "local counters must keep enforcing the budget"
    assert attempts == 1, "the shared storage is not retried on every request during an outage"
    messages = [record.getMessage() for record in records]
    assert messages == ["action=admission_storage_failed fallback=local error_type=RuntimeError"]
    assert not any("synthetic-secret" in message for message in messages)


@pytest.mark.asyncio
async def test_admission_returns_to_shared_storage_after_retry_interval():
    async def ok_app(request_scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AdmissionMiddleware(ok_app)
    shared_hits = 0

    def recovered(*args):
        nonlocal shared_hits
        shared_hits += 1
        return True

    middleware.storage_retry_at = time.monotonic() - 1
    middleware.counter.hit = recovered
    assert (await capture(middleware))[0]["status"] == 200
    assert shared_hits == 1 and middleware.storage_retry_at == 0.0


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/dashboard", "/readyz"])
async def test_admission_caps_concurrent_requests_and_releases_slot(path):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def waiting_app(request_scope, receive, send):
        entered.set()
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AdmissionMiddleware(waiting_app)
    middleware.config = middleware.config.model_copy(deep=True)
    middleware.config.app.max_concurrent_requests = 1
    first = asyncio.create_task(capture(middleware))
    await entered.wait()
    assert (await capture(middleware, scope(path=path)))[0]["status"] == 503
    release.set()
    assert (await first)[0]["status"] == 200
    assert middleware.active == 0


@pytest.mark.asyncio
async def test_liveness_does_not_wait_for_body_storage_or_concurrency():
    async def forbidden(*args):
        raise AssertionError("Liveness touched expensive work")

    middleware = AdmissionMiddleware(forbidden)
    middleware.active = middleware.config.app.max_concurrent_requests
    middleware.counter.hit = forbidden
    assert (await capture(middleware, scope('/healthz'), receive=forbidden))[0]['status'] == 200


def test_configuration_errors_do_not_disclose_inputs():
    marker = 'synthetic-secret-marker'
    with pytest.raises(ValueError) as error:
        AppConfig(port=marker)
    assert marker not in str(error.value)


@pytest.mark.parametrize("network", ["0.0.0.0/0", "::/0"])
def test_global_gateway_exemption_rejected(network, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    config = production_config()
    config.rate_limits.token_validation_exempt = [network]
    with pytest.raises(ValueError):
        config.validate_security()


@pytest.mark.asyncio
async def test_slow_rate_counter_does_not_block_event_loop():
    limiter = AsyncLimiter(key_func=lambda request: "test", storage_uri="memory://")

    def slow_check(*args):
        time.sleep(0.05)
        args[0].state.view_rate_limit = None

    limiter._check_request_limit = slow_check

    @limiter.limit("1/minute")
    async def endpoint(request: Request):
        return True

    task = asyncio.create_task(endpoint(request=Request(scope())))
    await asyncio.sleep(0.01)
    assert not task.done()
    assert await task is True


@pytest.mark.asyncio
async def test_slow_body_rejected_with_security_headers():
    async def forbidden_app(*args):
        raise AssertionError("Slow body reached authentication")

    async def stalled_receive():
        await asyncio.Event().wait()

    middleware = SecurityHeadersMiddleware(BodySizeLimitMiddleware(forbidden_app, 1024, 0.01))
    messages = await capture(middleware, receive=stalled_receive)
    assert messages[0]["status"] == 408
    assert b"content-security-policy" in dict(messages[0]["headers"])


@pytest.mark.asyncio
async def test_huge_declared_body_rejected_before_integer_conversion():
    async def forbidden_app(*args):
        raise AssertionError("Huge body reached application")

    middleware = BodySizeLimitMiddleware(forbidden_app, 1024)
    messages = await capture(middleware, scope(headers=[(b"content-length", b"9" * 5000)]))
    assert messages[0]["status"] == 413


@pytest.mark.asyncio
async def test_unexpected_error_does_not_escape_to_server_traceback(caplog):
    async def broken(*args):
        raise RuntimeError('synthetic-secret-must-not-be-logged')

    messages = await capture(SecurityHeadersMiddleware(ErrorSafetyMiddleware(broken)), scope('/tokens/synthetic-secret-in-path'))
    assert messages[0]['status'] == 500
    assert b'cache-control' in dict(messages[0]['headers'])
    assert b'synthetic-secret' not in messages[1]['body']
    assert 'synthetic-secret' not in caplog.text


@pytest.mark.asyncio
async def test_stream_failure_raises_only_sanitized_exception():
    async def broken(request_scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        raise RuntimeError('synthetic-secret-must-not-be-logged')

    with pytest.raises(RuntimeError, match='HTTP response interrupted') as error:
        await capture(ErrorSafetyMiddleware(broken))
    assert error.value.__suppress_context__


@pytest.mark.parametrize('workers', ['0', '33', '100000000000000000000000', 'invalid'])
def test_image_entrypoint_rejects_invalid_worker_counts(workers):
    script = Path(__file__).resolve().parents[1] / 'app' / 'entrypoint.sh'
    result = subprocess.run(['/bin/sh', str(script)], env={'WORKERS': workers, 'PATH': '/usr/bin:/bin'}, capture_output=True, text=True)
    assert result.returncode == 1 and 'WORKERS must be between 1 and 32' in result.stderr


def test_image_entrypoint_preserves_valid_worker_count(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'app' / 'entrypoint.sh'
    executable = tmp_path / 'uvicorn'
    executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    executable.chmod(0o700)
    result = subprocess.run(['/bin/sh', str(script)],
                            env={'PATH': str(tmp_path), 'WORKERS': '32', 'FORWARDED_ALLOW_IPS': '192.0.2.1'},
                            capture_output=True, text=True)
    assert result.returncode == 0
    arguments = result.stdout.splitlines()
    assert arguments[arguments.index('--workers') + 1] == '32'
    assert arguments[arguments.index('--forwarded-allow-ips') + 1] == '192.0.2.1'
    assert '--no-access-log' in arguments
