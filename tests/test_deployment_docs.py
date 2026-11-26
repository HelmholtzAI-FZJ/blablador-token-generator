"""The secret-creation commands in docs/deployment/kubernetes.md work."""
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest

DOC = Path(__file__).resolve().parents[1] / "docs/deployment/kubernetes.md"


def credential_blocks() -> str:
    text = DOC.read_text()
    blocks = []
    for heading in ("**PostgreSQL credentials**", "**Redis credentials**"):
        section = text.split(heading, 1)[1]
        blocks.append(re.search(r"```bash\n(.*?)```", section, re.S).group(1))
    return "\n".join(blocks)


@pytest.mark.skipif(not shutil.which("openssl") or not shutil.which("bash"), reason="needs openssl and bash")
def test_documented_credentials_match_their_urls(tmp_path):
    script = credential_blocks()
    # Record what kubectl would store instead of calling it.
    stub = (
        'kubectl() { shift 3; name=$1; shift; mkdir -p "$OUT/$name";'
        ' for arg in "$@"; do f=${arg#--from-file=}; cp "$f" "$OUT/$name/"; done; }\n'
    )
    subprocess.run(["bash", "-euc", stub + script], check=True, env={"OUT": str(tmp_path), "PATH": "/usr/bin:/bin"})

    pg = tmp_path / "tokens-postgresql-credentials"
    redis = tmp_path / "tokens-redis-credentials"
    for secret in (pg / "admin-password", pg / "password", redis / "password"):
        value = secret.read_bytes()
        assert re.fullmatch(rb"[0-9a-f]{64}", value), f"{secret.name} is not a bare hex password: {value!r}"
    assert urlsplit((pg / "database-url").read_text()).password == (pg / "password").read_text()
    assert urlsplit((redis / "storage-uri").read_text()).password == (redis / "password").read_text()
    assert (pg / "admin-password").read_bytes() != (pg / "password").read_bytes()
