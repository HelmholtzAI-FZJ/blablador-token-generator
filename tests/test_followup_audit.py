"""Regression tests for the follow-up security audit (October 2026)."""
import asyncio
import os
import threading
import time
from ipaddress import ip_network

import pytest
from limits import parse
from starlette.requests import Request
from starlette.testclient import TestClient

import app.main as main
import app.rate_limit as rate_limit
from app.admission import AdmissionMiddleware
from app.clients import client_address, loggable_address
from app.database import build_engine, init_db
from app.main import app
from tests.conftest import drop_schema


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    asyncio.run(init_db())
    yield

    async def drop():
        engine = build_engine(os.environ["DATABASE_URL"])
        async with engine.begin() as conn:
            await drop_schema(conn)
        await engine.dispose()

    asyncio.run(drop())


@pytest.fixture
def client():
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def http_scope(path: str = "/", client: str = "198.51.100.7", method: str = "GET") -> dict:
    return {"type": "http", "method": method, "path": path, "headers": [], "client": (client, 1234),
            "query_string": b"", "root_path": "", "scheme": "http", "server": ("testserver", 80)}


async def call(middleware, scope: dict) -> int:
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await middleware(scope, receive, send)
    return messages[0]["status"]


async def ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


class TestRateLimitStorageOutage:
    @pytest.mark.asyncio
    async def test_one_request_at_a_time_probes_a_failed_storage(self):
        middleware = AdmissionMiddleware(ok_app)
        middleware.storage_retry_at = time.monotonic() - 1  # retry is due
        in_probe = threading.Event()
        release = threading.Event()
        probes = 0

        def slow_storage(*args):
            nonlocal probes
            probes += 1
            in_probe.set()
            release.wait(5)
            return True

        middleware.counter.hit = slow_storage
        prober = asyncio.create_task(call(middleware, http_scope()))
        assert await asyncio.to_thread(in_probe.wait, 5)
        # Everyone else is counted locally instead of queueing on the storage.
        assert [await call(middleware, http_scope()) for _ in range(5)] == [200] * 5
        assert probes == 1
        release.set()
        assert await prober == 200
        assert middleware.storage_retry_at == 0.0 and not middleware.probing

    @pytest.mark.asyncio
    async def test_storage_calls_do_not_use_the_default_executor(self):
        middleware = AdmissionMiddleware(ok_app)
        threads = []
        middleware.counter.hit = lambda *args: threads.append(threading.current_thread().name) or True
        await call(middleware, http_scope())
        assert threads and threads[0].startswith("rate-limit-storage")

    def test_swallowed_storage_errors_do_not_turn_into_500(self, client, monkeypatch):
        # SlowAPI's error-swallowing path returns without recording the limit
        # it checked; the response must still be delivered.
        monkeypatch.setattr(main.limiter, "_check_request_limit", lambda *args, **kwargs: None)
        assert client.get("/").status_code == 200

    def test_exempt_gateway_skips_the_route_counter(self, monkeypatch):
        def must_not_run(*args, **kwargs):
            raise AssertionError("route counter consulted for an exempt gateway")

        monkeypatch.setattr(rate_limit, "_TOKEN_VALIDATION_EXEMPT", [ip_network("192.0.2.0/24")])
        monkeypatch.setattr(main.limiter, "_check_request_limit", must_not_run)
        with TestClient(app, client=("192.0.2.10", 4321)) as gateway:
            response = gateway.post("/api/v1/auth/validate", headers={"Authorization": "Bearer unknown"})
        assert response.status_code == 401


class TestAdmissionBudgets:
    @pytest.mark.asyncio
    async def test_token_validation_has_its_own_budget(self):
        middleware = AdmissionMiddleware(ok_app)
        middleware.budget = parse("1/minute")
        middleware.validation_budget = parse("3/minute")
        validate = http_scope("/api/v1/auth/validate", method="POST")
        assert [await call(middleware, dict(validate)) for _ in range(4)] == [200, 200, 200, 429]
        assert [await call(middleware, http_scope("/")) for _ in range(2)] == [200, 429]

    @pytest.mark.asyncio
    async def test_ipv6_clients_share_a_budget_per_64(self):
        middleware = AdmissionMiddleware(ok_app)
        middleware.budget = parse("2/minute")
        statuses = [await call(middleware, http_scope(client=f"2001:db8:1:2::{n:x}")) for n in range(1, 4)]
        assert statuses == [200, 200, 429]
        assert await call(middleware, http_scope(client="2001:db8:1:3::1")) == 200


class TestClientAddresses:
    @staticmethod
    def request(host: str) -> Request:
        return Request(http_scope(client=host))

    def test_keys(self):
        assert client_address(self.request("203.0.113.9")) == "203.0.113.9"
        assert client_address(self.request("2001:db8::1")) == client_address(self.request("2001:db8::ffff")) == "2001:db8::/64"
        assert client_address(self.request("::ffff:203.0.113.9")) == "203.0.113.9"
        assert client_address(self.request("testclient")) == "testclient"

    def test_log_field_stays_one_token(self):
        assert loggable_address("203.0.113.9") == "203.0.113.9"
        assert loggable_address("forged route=/admin status=200") == "forged?route??admin?status?200"
        assert loggable_address(None) == "-"
