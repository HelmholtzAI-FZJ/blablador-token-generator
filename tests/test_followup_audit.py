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


class TestLogging:
    @staticmethod
    def access_lines(caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.name == "token_generator.access"]

    @pytest.mark.asyncio
    async def test_aborted_requests_are_not_logged_as_server_errors(self, caplog):
        from app.access_log import AccessLogMiddleware

        async def client_went_away(scope, receive, send):
            return None

        caplog.set_level("INFO", logger="token_generator.access")
        await call_without_response(AccessLogMiddleware(client_went_away), http_scope("/tokens", method="POST"))
        lines = self.access_lines(caplog)
        assert len(lines) == 1 and " status=- " in lines[0]

    def test_static_files_get_a_route_label(self, client, caplog):
        caplog.set_level("INFO", logger="token_generator.access")
        assert client.get("/static/common.js").status_code == 200
        assert any("route=/static status=200" in line for line in self.access_lines(caplog))

    def test_native_tracing_and_logs_are_off(self):
        assert app._telemetry["tracing"] is False and app._telemetry["logs"] is False

    def test_launchers_disable_websockets_and_server_header(self, tmp_path):
        import subprocess
        from pathlib import Path

        repo = Path(__file__).resolve().parents[1]
        executable = tmp_path / "uvicorn"
        executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        executable.chmod(0o700)
        result = subprocess.run(["/bin/sh", str(repo / "app" / "entrypoint.sh")], env={"PATH": str(tmp_path)},
                                capture_output=True, text=True)
        arguments = result.stdout.splitlines()
        assert arguments[arguments.index("--ws") + 1] == "none"
        assert "--no-server-header" in arguments
        assert int(arguments[arguments.index("--timeout-keep-alive") + 1]) > 60
        for line in (repo / "start.sh").read_text().splitlines():
            if "uvicorn app.main:app" in line:
                assert "--ws none" in line and "--no-server-header" in line


async def call_without_response(middleware, scope: dict) -> None:
    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        raise AssertionError("nothing should be sent")

    await middleware(scope, receive, send)


def production_config():
    from app.config import AppConfig, Config, DatabaseConfig, LocalAuthConfig, RateLimitConfig

    return Config(
        app=AppConfig(secret_key="synthetic-jwt-" + "x" * 40, token_hash_key="synthetic-hmac-" + "y" * 40),
        database=DatabaseConfig(url="postgresql+asyncpg://user:password@database/tokens", ssl_ca_file="/synthetic/ca.crt"),
        rate_limits=RateLimitConfig(storage_uri="rediss://:password@redis/0"),
        local=LocalAuthConfig(enabled=True),
    )


class TestProductionConfiguration:
    @pytest.mark.parametrize("uri", [
        "rediss://:pw@redis/0?ssl_cert_reqs=none&ssl_cert_reqs=required",
        "rediss://:pw@redis/0?ssl_check_hostname=false&ssl_check_hostname=true",
    ])
    def test_repeated_redis_parameters_rejected(self, uri, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
        config = production_config()
        config.rate_limits.storage_uri = uri
        with pytest.raises(ValueError, match="repeat"):
            config.validate_security()

    def test_repeated_database_parameters_rejected(self, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
        config = production_config()
        config.database.url += "?ssl=disable&ssl=verify-full"
        with pytest.raises(ValueError, match="repeat"):
            config.validate_security()

    @pytest.mark.parametrize("trusted", ["10.42.0.7/16", "0.0.0.0/1,128.0.0.0/1", "::/1", "proxy.example"])
    def test_proxy_trust_that_uvicorn_would_misread_or_widen_is_rejected(self, trusted, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", trusted)
        with pytest.raises(ValueError):
            production_config().validate_security()

    @pytest.mark.parametrize("trusted", ["192.0.2.10", "10.42.0.0/16, 10.43.0.0/16", "10.0.0.0/8", "fd00::/8"])
    def test_specific_proxy_networks_accepted(self, trusted, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", trusted)
        production_config().validate_security()

    def test_broad_gateway_exemption_rejected(self, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
        config = production_config()
        config.rate_limits.token_validation_exempt = ["0.0.0.0/1", "128.0.0.0/1"]
        with pytest.raises(ValueError):
            config.validate_security()

    def test_keys_differing_only_in_whitespace_rejected(self, monkeypatch):
        monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
        config = production_config()
        config.app.token_hash_key = config.app.secret_key + " "
        with pytest.raises(ValueError, match="differ"):
            config.validate_security()

    def test_empty_configuration_file(self, tmp_path, monkeypatch):
        from app.config import get_config

        empty = tmp_path / "config.yaml"
        empty.write_text("# nothing configured yet\n")
        monkeypatch.setenv("CONFIG_PATH", str(empty))
        assert get_config.__wrapped__().app.environment == "development"
        empty.write_text("- not a mapping\n")
        with pytest.raises(ValueError, match="mapping"):
            get_config.__wrapped__()


class TestDatabaseRoleCheck:
    """Needs a disposable PostgreSQL where the test user may create roles
    (TEST_DATABASE_URL, as in CI)."""

    @pytest.mark.asyncio
    async def test_reach_beyond_the_application_schema_is_refused(self):
        import uuid
        from sqlalchemy import text
        from app.database import verify_production_database_role

        url = os.environ.get("TEST_DATABASE_URL", "")
        if not url.startswith("postgresql"):
            pytest.skip("Needs PostgreSQL")
        administrator = build_engine(url)
        async with administrator.connect() as connection:
            if not await connection.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")):
                await administrator.dispose()
                pytest.skip("Needs a superuser to create test roles")
            version = int(await connection.scalar(text("SHOW server_version_num")))
        role = "tg_check_" + uuid.uuid4().hex[:10]
        password = uuid.uuid4().hex
        grants = [
            (f'GRANT pg_read_all_data TO "{role}"', f'REVOKE pg_read_all_data FROM "{role}"'),
            (f'GRANT pg_write_all_data TO "{role}"', f'REVOKE pg_write_all_data FROM "{role}"'),
            (f'GRANT pg_signal_backend TO "{role}"', f'REVOKE pg_signal_backend FROM "{role}"'),
            (f'GRANT EXECUTE ON FUNCTION pg_read_binary_file(text) TO "{role}"',
             f'REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM "{role}"'),
            (f'GRANT EXECUTE ON FUNCTION lo_export(oid, text) TO "{role}"',
             f'REVOKE EXECUTE ON FUNCTION lo_export(oid, text) FROM "{role}"'),
        ]
        if version >= 150000:
            grants.append((f'GRANT SET ON PARAMETER session_preload_libraries TO "{role}"',
                           f'REVOKE SET ON PARAMETER session_preload_libraries FROM "{role}"'))
        restricted = None
        try:
            async with administrator.begin() as connection:
                await connection.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
                await connection.execute(text(f'GRANT pg_monitor TO "{role}"'))
            restricted = build_engine(make_url_for(url, role, password))
            async with restricted.connect() as connection:
                await verify_production_database_role(connection)  # monitoring is fine
            for grant, revoke in grants:
                async with administrator.begin() as connection:
                    await connection.execute(text(grant))
                async with restricted.connect() as connection:
                    with pytest.raises(RuntimeError, match="unsafe"):
                        await verify_production_database_role(connection)
                async with administrator.begin() as connection:
                    await connection.execute(text(revoke))
            async with restricted.connect() as connection:
                await verify_production_database_role(connection)
        finally:
            if restricted is not None:
                await restricted.dispose()
            async with administrator.begin() as connection:
                await connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
            await administrator.dispose()


def make_url_for(url: str, username: str, password: str):
    from sqlalchemy.engine import make_url

    return make_url(url).set(username=username, password=password)


def oauth_login(client: TestClient, monkeypatch, subject: str, name: str | None = None, admin: bool = False) -> str:
    """Sign in through the OAuth callback; returns the CSRF token."""
    async def fake_userinfo(code, code_verifier):
        return {"sub": subject, "email": f"{subject}@example.com", "name": name or subject}

    monkeypatch.setattr(main, "get_unity_userinfo", fake_userinfo)
    if admin:
        async def promote():
            from sqlalchemy import update
            from app import database
            from app.models import User

            async with database.async_session_maker() as db:
                await db.execute(update(User).where(User.unity_id == subject).values(is_admin=True))
                await db.commit()

    client.cookies.set("oauth_state", "state")
    client.cookies.set("oauth_verifier", "v" * 43)
    assert client.get("/oauth/openid/callback", params={"state": "state", "code": "code"}).status_code == 303
    if admin:
        client.portal.call(promote)
        client.cookies.set("oauth_state", "state")
        client.cookies.set("oauth_verifier", "v" * 43)
        assert client.get("/oauth/openid/callback", params={"state": "state", "code": "code"}).status_code == 303
    client.get("/")
    return client.cookies.get("csrf_token")


class TestInputValidation:
    @pytest.mark.parametrize("name", ["nul\x00name", "line\nbreak", "evil‮exe.txt", "zero​width"])
    def test_token_names_without_control_or_invisible_characters(self, client, monkeypatch, name):
        csrf = oauth_login(client, monkeypatch, "names-user")
        response = client.post("/tokens", json={"name": name}, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 422

    def test_emoji_sequences_stay_allowed(self, client, monkeypatch):
        csrf = oauth_login(client, monkeypatch, "emoji-user")
        response = client.post("/tokens", json={"name": "\U0001F468‍\U0001F4BB laptop"},
                               headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize("token_id", ["a%00b", "a.b", "x" * 37])
    def test_malformed_ids_are_client_errors(self, client, monkeypatch, token_id):
        csrf = oauth_login(client, monkeypatch, "ids-user")
        for method, path in (("DELETE", f"/tokens/{token_id}"), ("POST", f"/tokens/{token_id}/rotate"),
                             ("DELETE", f"/api/admin/tokens/{token_id}")):
            response = client.request(method, path, headers={"X-CSRF-Token": csrf})
            assert response.status_code in (403, 422), (path, response.status_code)

    def test_login_with_impossible_email_is_an_ordinary_failure(self, client):
        import re
        page = client.get("/login/local")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = client.post("/login/local", data={"email": "a\x00b@example.org", "password": "x" * 20,
                                                     "csrf_token": csrf})
        assert response.status_code == 401

    def test_admin_inputs(self, client, monkeypatch):
        csrf = oauth_login(client, monkeypatch, "validation-admin", admin=True)
        headers = {"X-CSRF-Token": csrf}
        base = {"email": "new-local@example.org", "password": "a long enough local password"}
        assert client.post("/api/admin/users", json={**base, "name": "Mallory‮"}, headers=headers).status_code == 422
        assert client.post("/api/admin/users", json={**base, "name": "M", "is_admin": "yes"}, headers=headers).status_code == 422
        assert client.post("/api/admin/users/restore-oauth", json={"subject": "a\x00b"}, headers=headers).status_code == 422

    def test_provider_names_are_cleaned_not_refused(self, client, monkeypatch):
        from sqlalchemy import select
        from app import database
        from app.models import User

        oauth_login(client, monkeypatch, "named-user", name="Ada\x00 ‮Lovelace")

        async def stored_name():
            async with database.async_session_maker() as db:
                return (await db.execute(select(User.name).where(User.unity_id == "named-user"))).scalar_one()

        assert client.portal.call(stored_name) == "Ada Lovelace"

    def test_command_line_selectors(self):
        import argparse
        from app.manage import non_empty

        with pytest.raises(argparse.ArgumentTypeError):
            non_empty("subject\x00")
        assert non_empty("subject-1") == "subject-1"


def login_form_token(response) -> str:
    import re
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


class TestSessionsAndSignIn:
    def test_logout_of_a_deleted_account_succeeds_quietly(self, client, monkeypatch, caplog):
        from sqlalchemy import delete
        from app import database
        from app.models import User

        csrf = oauth_login(client, monkeypatch, "deleted-before-logout")

        async def remove():
            async with database.async_session_maker() as db:
                await db.execute(delete(User).where(User.unity_id == "deleted-before-logout"))
                await db.commit()

        client.portal.call(remove)
        caplog.set_level("INFO", logger="token_generator.audit")
        response = client.post("/logout", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        assert any("access_token" in header and "Max-Age=0" in header
                   for header in response.headers.get_list("set-cookie"))
        assert not any("session_revocation_failed" in r.getMessage() for r in caplog.records)

    def test_csrf_exemption_is_the_bearer_route_only(self, client, monkeypatch):
        from fastapi.routing import APIRoute
        from app.auth import get_current_admin, get_current_user

        def dependencies(dependant):
            for sub in dependant.dependencies:
                yield sub.call
                yield from dependencies(sub)

        def api_routes():
            # FastAPI 0.143 keeps included routers as their own route entries.
            for route in app.routes:
                contexts = getattr(route, "effective_route_contexts", None)
                if contexts is not None:
                    yield from contexts()
                elif isinstance(route, APIRoute):
                    yield route

        exempt = [route for route in api_routes() if route.path in main.BEARER_PATHS]
        assert [route.path for route in exempt] == ["/api/v1/auth/validate"]
        for route in exempt:
            assert not {get_current_user, get_current_admin} & set(dependencies(route.dependant))
        oauth_login(client, monkeypatch, "csrf-prefix-user")
        assert client.post("/api/v1/anything-else").status_code == 403

    def test_sign_in_form_recovers_from_a_missing_csrf_cookie(self, client):
        page = client.get("/login/local")
        token = login_form_token(page)
        client.cookies.clear()
        first = client.post("/login/local", data={"email": "a@example.org", "password": "p" * 20, "csrf_token": token})
        assert first.status_code == 403 and "form expired" in first.text
        retry = client.post("/login/local", data={"email": "a@example.org", "password": "p" * 20,
                                                  "csrf_token": login_form_token(first)})
        assert retry.status_code == 401 and "Invalid email or password" in retry.text

    def test_sign_in_limits_and_outages_are_pages(self, client, monkeypatch):
        from fastapi import HTTPException

        token = login_form_token(client.get("/login/local"))
        form = {"email": "a@example.org", "password": "p" * 20, "csrf_token": token}

        async def throttled(email):
            raise HTTPException(status_code=429, detail="Too many login attempts", headers={"Retry-After": "60"})

        monkeypatch.setattr(main, "enforce_account_login_limit", throttled)
        response = client.post("/login/local", data=form)
        assert response.status_code == 429 and response.headers["retry-after"] == "60"
        assert response.headers["content-type"].startswith("text/html")

        async def unavailable(email):
            raise HTTPException(status_code=503, detail="Login temporarily unavailable")

        monkeypatch.setattr(main, "enforce_account_login_limit", unavailable)
        response = client.post("/login/local", data=form)
        assert response.status_code == 503 and "temporarily unavailable" in response.text

    def test_per_address_sign_in_limit_is_a_page(self, client, monkeypatch):
        from slowapi.errors import RateLimitExceeded
        from slowapi.wrappers import Limit
        from limits import parse as parse_limit

        token = login_form_token(client.get("/login/local"))
        limit = Limit(parse_limit("1/minute"), lambda request: "k", None, False, None, None, None, 1, False)

        def exceeded(*args, **kwargs):
            raise RateLimitExceeded(limit)

        monkeypatch.setattr(main.limiter, "_check_request_limit", exceeded)
        response = client.post("/login/local", data={"email": "a@example.org", "password": "p" * 20,
                                                     "csrf_token": token})
        assert response.status_code == 429 and response.headers["content-type"].startswith("text/html")

    def test_no_slash_redirects_built_from_the_host_header(self, client):
        response = client.get("/dashboard/", headers={"Host": "attacker.example"})
        assert response.status_code == 404
        assert "location" not in response.headers

    def test_cross_origin_isolation_headers(self, client):
        headers = client.get("/").headers
        assert headers["cross-origin-opener-policy"] == "same-origin"
        assert headers["cross-origin-resource-policy"] == "same-origin"
        assert "camera=()" in headers["permissions-policy"]


class TestAdministration:
    @pytest.mark.asyncio
    async def test_admins_who_cannot_sign_in_do_not_count(self, test_db, monkeypatch):
        from app.api.admin import is_last_admin
        from app.auth import hash_password
        from app.config import get_config
        from app.models import User

        oauth_admin = User(unity_id="only-oauth-admin", email="oauth-admin@example.org", name="O", is_admin=True)
        local_admin = User(email="local-admin@example.org", name="L", is_admin=True,
                           password_hash=hash_password("a long local admin password"))
        test_db.add_all([oauth_admin, local_admin])
        await test_db.commit()
        # On a shared PostgreSQL test database, other tests' admins exist.
        from sqlalchemy import update
        await test_db.execute(update(User).where(User.id.notin_([oauth_admin.id, local_admin.id]))
                              .values(is_admin=False))
        await test_db.commit()
        assert not await is_last_admin(test_db, oauth_admin.id)
        monkeypatch.setattr(get_config().local, "enabled", False)
        assert await is_last_admin(test_db, oauth_admin.id)
        assert not await is_last_admin(test_db, local_admin.id)  # removing it changes nothing

    def test_no_local_accounts_while_local_sign_in_is_off(self, client, monkeypatch):
        from app.config import get_config

        csrf = oauth_login(client, monkeypatch, "admin-local-off", admin=True)
        monkeypatch.setattr(get_config().local, "enabled", False)
        response = client.post("/api/admin/users", headers={"X-CSRF-Token": csrf}, json={
            "email": "cannot-sign-in@example.org", "name": "X", "password": "a long enough local password"})
        assert response.status_code == 400 and "local.enabled" in response.json()["detail"]
        assert 'id="createUserForm"' not in client.get("/admin/tokens").text

    def test_audit_trail_names_roles_identities_and_reads(self, client, monkeypatch, caplog):
        from sqlalchemy import select
        from app import database
        from app.models import User
        from app.tombstones import identity_reference

        csrf = oauth_login(client, monkeypatch, "auditing-admin", admin=True)
        headers = {"X-CSRF-Token": csrf}
        other = TestClient(app, follow_redirects=False)
        with other:
            oauth_login(other, monkeypatch, "audited-user")

        async def user_id(subject):
            async with database.async_session_maker() as db:
                return (await db.execute(select(User.id).where(User.unity_id == subject))).scalar_one()

        target = client.portal.call(user_id, "audited-user")
        caplog.set_level("INFO", logger="token_generator.audit")
        assert client.patch(f"/api/admin/users/{target}", json={"is_admin": True}, headers=headers).status_code == 200
        assert client.get("/api/admin/users").status_code == 200
        assert client.post("/admin/tokens/search", data={"token": "unknown", "csrf_token": csrf}).status_code == 200
        assert client.delete(f"/api/admin/users/{target}", headers=headers).status_code == 200
        assert client.post("/api/admin/users/restore-oauth", json={"subject": "audited-user"},
                           headers=headers).status_code == 200
        lines = [r.getMessage() for r in caplog.records if r.name == "token_generator.audit"]
        reference = identity_reference(subject="audited-user")
        assert any("action=update_user" in line and "was_admin=False is_admin=True" in line for line in lines)
        assert any("action=list_users" in line for line in lines)
        assert any("action=search_token found=False" in line for line in lines)
        assert any("action=delete_user" in line and f"identity={reference}" in line for line in lines)
        assert any("action=restore_oauth_identity" in line and f"identity={reference}" in line for line in lines)
        assert not any("audited-user" in line for line in lines)

    def test_refused_admin_access_is_logged(self, client, monkeypatch, caplog):
        oauth_login(client, monkeypatch, "not-an-admin")
        caplog.set_level("INFO", logger="token_generator.audit")
        assert client.get("/api/admin/users").status_code == 403
        assert any("action=admin_access_denied" in r.getMessage() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_token_listing_is_stable_for_equal_timestamps(self, test_db, test_admin):
        from datetime import datetime
        from app.api.admin import list_all_tokens
        from app.auth import generate_token, hash_token
        from app.models import Token

        moment = datetime(2026, 1, 1)
        test_db.add_all([Token(user_id=test_admin.id, name=f"t{n}", token_hash=hash_token(generate_token()),
                               created_at=moment) for n in range(25)])
        await test_db.commit()
        request = Request(http_scope("/api/admin/tokens"))
        pages = [await list_all_tokens.__wrapped__(request, page=page, page_size=10, admin=test_admin, db=test_db)
                 for page in (1, 2, 3)]
        ids = [token.id for page in pages for token in page]
        assert len(ids) == 25 and len(set(ids)) == 25

    def test_command_line_refuses_local_admins_while_local_sign_in_is_off(self, monkeypatch):
        from app.config import get_config
        from app.manage import CommandError, create_local_admin

        monkeypatch.setattr(get_config().local, "enabled", False)
        with pytest.raises(CommandError, match="grant-admin"):
            asyncio.run(create_local_admin("x@example.org", "X", "a long enough local password"))


class TestTokenLifecycle:
    def test_repeated_revocation_keeps_the_first_time(self, client, monkeypatch):
        from sqlalchemy import select
        from app import database
        from app.models import Token

        csrf = oauth_login(client, monkeypatch, "revoking-user")
        headers = {"X-CSRF-Token": csrf}
        token_id = client.post("/tokens", json={"name": "twice"}, headers=headers).json()["id"]

        async def revoked_at():
            async with database.async_session_maker() as db:
                return (await db.execute(select(Token.revoked_at).where(Token.id == token_id))).scalar_one()

        assert client.delete(f"/tokens/{token_id}", headers=headers).status_code == 200
        first = client.portal.call(revoked_at)
        time.sleep(0.01)
        assert client.delete(f"/tokens/{token_id}", headers=headers).status_code == 200
        assert client.portal.call(revoked_at) == first

    def test_renewal_without_a_body_after_rotation(self, client, monkeypatch):
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import update
        from app import database
        from app.models import Token

        csrf = oauth_login(client, monkeypatch, "renewing-user")
        headers = {"X-CSRF-Token": csrf}
        token_id = client.post("/tokens", json={"name": "rotated", "expires_in_days": 30}, headers=headers).json()["id"]

        async def created_long_ago():
            async with database.async_session_maker() as db:
                await db.execute(update(Token).where(Token.id == token_id)
                                 .values(created_at=datetime(2025, 1, 1)))
                await db.commit()

        client.portal.call(created_long_ago)
        assert client.post(f"/tokens/{token_id}/rotate", json={"expires_in_days": 300},
                           headers=headers).status_code == 200
        renewed = client.post(f"/tokens/{token_id}/renew", headers=headers)
        assert renewed.status_code == 200, renewed.text
        expires = datetime.fromisoformat(renewed.json()["expires_at"])
        assert expires <= datetime.now(timezone.utc) + timedelta(days=365, minutes=1)

    def test_rotation_keeps_the_previous_use_in_the_audit_log(self, client, monkeypatch, caplog):
        csrf = oauth_login(client, monkeypatch, "rotating-user")
        headers = {"X-CSRF-Token": csrf}
        created = client.post("/tokens", json={"name": "leaked"}, headers=headers).json()
        validation = client.post("/api/v1/auth/validate", headers={"Authorization": f"Bearer {created['token']}"})
        assert validation.status_code == 200
        caplog.set_level("INFO", logger="token_generator.audit")
        assert client.post(f"/tokens/{created['id']}/rotate", headers=headers).status_code == 200
        line = next(r.getMessage() for r in caplog.records if "action=rotate_token" in r.getMessage())
        assert "previous_last_used_at=20" in line

    @pytest.mark.asyncio
    async def test_revocations_are_purged_only_well_after_expiry(self, test_db, test_user):
        from datetime import timedelta
        from sqlalchemy import select
        from app.auth import REVOCATION_PURGE_MARGIN, revoke_jwt
        from app.models import RevokedJWT
        from app.timeutil import utcnow

        just_expired = RevokedJWT(jti="just-expired", user_id=test_user.id,
                                  expires_at=utcnow() - REVOCATION_PURGE_MARGIN / 2)
        long_expired = RevokedJWT(jti="long-expired", user_id=test_user.id,
                                  expires_at=utcnow() - REVOCATION_PURGE_MARGIN - timedelta(minutes=1))
        test_db.add_all([just_expired, long_expired])
        await test_db.commit()
        from datetime import UTC, datetime
        await revoke_jwt({"jti": "new-session", "sub": test_user.id,
                          "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())}, test_db)
        remaining = set((await test_db.execute(select(RevokedJWT.jti))).scalars())
        assert {"just-expired", "new-session"} <= remaining and "long-expired" not in remaining


class TestOperatorCommands:
    def test_password_stdin_refuses_a_terminal(self, monkeypatch):
        from app.manage import CommandError, read_password

        class Terminal:
            def isatty(self):
                return True

            def readline(self):
                raise AssertionError("must not read an echoed password")

        monkeypatch.setattr("sys.stdin", Terminal())
        with pytest.raises(CommandError, match="piped"):
            read_password(True)
