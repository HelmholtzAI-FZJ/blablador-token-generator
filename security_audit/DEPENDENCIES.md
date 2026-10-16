# Token Generator dependency inventory

Audit date: 11 October 2026. Package names and versions come from the frozen production export and the installed virtual environment. Both pip-audit scans reported no known advisories or skipped dependencies. This does not include the base image package installer or operating system; see CONTAINER_VULNERABILITIES.md.

The frozen production export was re-audited on 12 October 2026 with pip-audit 2.10.1: 38 packages, zero reported advisories and zero skips. Raw final results are in [final-production-dependencies.json](evidence/final-production-dependencies.json). Runtime CPython is 3.12.15, the current security release for that series at review time; the official [release page](https://www.python.org/downloads/release/python-31215/) and [schedule](https://peps.python.org/pep-0693/) identify security support through October 2028. Host test Python is 3.12.3; image smoke tests exercise the shipped interpreter separately. Package audits do not exhaustively fuzz the interpreter/standard library.

## Production packages

| Package | Version | Known advisories in this scan |
| --- | --- | --- |
| aiosqlite | 0.22.1 | 0 |
| annotated-doc | 0.0.5 | 0 |
| annotated-types | 0.8.0 | 0 |
| anyio | 4.14.2 | 0 |
| asyncpg | 0.32.0 | 0 |
| bcrypt | 5.0.0 | 0 |
| certifi | 2026.7.22 | 0 |
| click | 8.4.2 | 0 |
| deprecated | 3.0.0 | 0 |
| fastapi | 0.141.1 | 0 |
| greenlet | 3.5.5 | 0 |
| h11 | 0.16.0 | 0 |
| httpcore | 1.0.9 | 0 |
| httptools | 0.8.0 | 0 |
| httpx | 0.28.1 | 0 |
| idna | 3.19 | 0 |
| jinja2 | 3.1.6 | 0 |
| limits | 5.8.0 | 0 |
| markupsafe | 3.0.3 | 0 |
| packaging | 26.3 | 0 |
| pydantic | 2.13.4 | 0 |
| pydantic-core | 2.46.4 | 0 |
| pydantic-settings | 2.15.0 | 0 |
| pyjwt | 2.15.1 | 0 |
| python-dotenv | 1.2.3 | 0 |
| python-multipart | 0.0.32 | 0 |
| pyyaml | 6.0.3 | 0 |
| redis | 8.1.0 | 0 |
| slowapi | 0.1.10 | 0 |
| sqlalchemy | 2.0.52 | 0 |
| starlette | 1.6.0 | 0 |
| typing-extensions | 4.16.0 | 0 |
| typing-inspection | 0.4.4 | 0 |
| uvicorn | 0.52.4 | 0 |
| uvloop | 0.22.1 | 0 |
| watchfiles | 1.2.0 | 0 |
| websockets | 17.0.1 | 0 |
| wrapt | 2.5.0 | 0 |

## Lockfile and installed environment

The universal lock contains platform and Python-version alternatives. An absent platform-specific package does not by itself indicate drift; two Deprecated versions are conditional alternatives. Production scanner ran under local Python 3.12, so other Python/platform combinations still need their own release checks.

| Package | Locked version | Installed version |
| --- | --- | --- |
| aiosqlite | 0.22.1 | 0.22.1 |
| annotated-doc | 0.0.5 | 0.0.5 |
| annotated-types | 0.8.0 | 0.8.0 |
| anyio | 4.14.2 | 4.14.2 |
| async-timeout | 5.0.1 | not installed on this platform |
| asyncpg | 0.32.0 | 0.32.0 |
| bcrypt | 5.0.0 | 5.0.0 |
| certifi | 2026.7.22 | 2026.7.22 |
| click | 8.4.2 | 8.4.2 |
| colorama | 0.4.6 | not installed on this platform |
| coverage | 7.15.4 | 7.15.4 |
| deprecated | 1.3.1 | 3.0.0 |
| deprecated | 3.0.0 | 3.0.0 |
| fastapi | 0.141.1 | 0.141.1 |
| greenlet | 3.5.5 | 3.5.5 |
| h11 | 0.16.0 | 0.16.0 |
| httpcore | 1.0.9 | 1.0.9 |
| httptools | 0.8.0 | 0.8.0 |
| httpx | 0.28.1 | 0.28.1 |
| idna | 3.19 | 3.19 |
| iniconfig | 2.3.0 | 2.3.0 |
| jinja2 | 3.1.6 | 3.1.6 |
| limits | 5.8.0 | 5.8.0 |
| markupsafe | 3.0.3 | 3.0.3 |
| packaging | 26.3 | 26.3 |
| pluggy | 1.6.0 | 1.6.0 |
| pydantic | 2.13.4 | 2.13.4 |
| pydantic-core | 2.46.4 | 2.46.4 |
| pydantic-settings | 2.15.0 | 2.15.0 |
| pygments | 2.21.0 | 2.21.0 |
| pyjwt | 2.15.1 | 2.15.1 |
| pytest | 9.1.1 | 9.1.1 |
| pytest-asyncio | 1.4.0 | 1.4.0 |
| pytest-cov | 7.1.0 | 7.1.0 |
| python-dotenv | 1.2.3 | 1.2.3 |
| python-multipart | 0.0.32 | 0.0.32 |
| pyyaml | 6.0.3 | 6.0.3 |
| redis | 8.1.0 | 8.1.0 |
| slowapi | 0.1.10 | 0.1.10 |
| sqlalchemy | 2.0.52 | 2.0.52 |
| starlette | 1.6.0 | 1.6.0 |
| tomli | 2.4.1 | not installed on this platform |
| typing-extensions | 4.16.0 | 4.16.0 |
| typing-inspection | 0.4.4 | 0.4.4 |
| uvicorn | 0.52.4 | 0.52.4 |
| uvloop | 0.22.1 | 0.22.1 |
| watchfiles | 1.2.0 | 1.2.0 |
| websockets | 17.0.1 | 17.0.1 |
| wrapt | 2.5.0 | 2.5.0 |
