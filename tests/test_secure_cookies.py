"""Cookie behaviour with secure_cookies enabled (production settings).

Configuration is read once at import time, so these checks run the app in a
separate interpreter with its own config.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = textwrap.dedent('''
    import re
    from starlette.testclient import TestClient
    from app import database
    from app.auth import create_session_token
    from app.main import app
    from app.models import User

    def attrs(response, name):
        for header in response.headers.get_list("set-cookie"):
            if header.startswith(name + "="):
                return [part.strip().lower() for part in header.split(";")[1:]]
        raise AssertionError(f"{name} not set")

    async def seed():
        async with database.async_session_maker() as db:
            user = User(email="secure@example.com", name="S", unity_id="secure-sub")
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return create_session_token(user)

    with TestClient(app, base_url="https://testserver", follow_redirects=False) as client:
        home = client.get("/")
        csrf_attrs = attrs(home, "__Host-csrf_token")
        assert {"secure", "httponly", "path=/"} <= set(csrf_attrs), csrf_attrs
        assert not any(a.startswith("domain") for a in csrf_attrs), csrf_attrs

        state_attrs = attrs(client.get("/login"), "__Host-oauth_state")
        assert {"secure", "httponly", "path=/"} <= set(state_attrs), state_attrs

        # A cookie planted by another host cannot use the __Host- prefix;
        # an unprefixed one must be ignored.
        planted = TestClient(app, base_url="https://testserver")
        planted.cookies.set("csrf_token", "evil")
        r = planted.post("/tokens", json={"name": "x"}, headers={"X-CSRF-Token": "evil"})
        assert r.status_code == 403, r.status_code

        client.cookies.set("__Host-access_token", client.portal.call(seed))
        page = client.get("/dashboard")
        assert page.status_code == 200, page.status_code
        meta = re.search(r'<meta name="csrf-token" content="([^"]+)"', page.text).group(1)
        assert meta == client.cookies.get("__Host-csrf_token")
    print("OK")
''')


def test_secure_cookie_mode(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        Path(__file__).with_name("config.test.yaml").read_text().replace(
            "secure_cookies: false", "secure_cookies: true"
        )
    )
    env = {
        **os.environ,
        "CONFIG_PATH": str(config),
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path}/app.db",
        "RATE_LIMIT_STORAGE_URI": "memory://",
        "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
    }
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0 and "OK" in result.stdout, result.stderr[-2000:]
