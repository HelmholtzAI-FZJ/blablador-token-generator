import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml

CHART = Path(__file__).resolve().parents[1]
ROOT = CHART.parents[1]


def render(values: dict, valid: bool = True) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="token-generator-chart-test-") as directory:
        value_file = Path(directory) / "values.yaml"
        value_file.write_text(yaml.safe_dump(values))
        result = subprocess.run(
            ["helm", "template", "security-test", str(CHART), "-f", str(value_file)],
            capture_output=True,
            text=True,
        )
    if not valid:
        assert result.returncode != 0, "Unsafe values unexpectedly rendered"
        return []
    assert result.returncode == 0, result.stderr
    return [resource for resource in yaml.safe_load_all(result.stdout) if resource]


def index(resources: list[dict]) -> dict[tuple[str, str], dict]:
    return {(resource["kind"], resource["metadata"]["name"]): resource for resource in resources}


def test_chart() -> None:
    values = {
        "image": {"tag": "reviewed-release"},
        "config": {
            "app": {
                "secret_key": "s" * 64,
                "token_hash_key": "h" * 64,
                "jwt_expiration_hours": 2,
                "admin_jwt_expiration_hours": 1,
                "max_body_bytes": 1024,
                "body_timeout_seconds": 3.0,
                "max_concurrent_requests": 16,
                "readiness_timeout_seconds": 1.0,
                "log_level": "WARNING",
            },
            "local": {"enabled": True, "max_concurrent_password_operations": 2},
        },
        "postgresql": {"image": {"tag": "reviewed-postgres-release"}, "password": "p" * 64, "adminPassword": "a" * 64, "tls": {"existingSecret": "postgres-tls"}},
        "redis": {"image": {"tag": "reviewed-redis-release"}, "password": "r" * 64, "tls": {"existingSecret": "redis-tls"}},
        "forwardedAllowIps": "192.0.2.1",
        "networkPolicy": {
            "app": {
                "from": [{"ipBlock": {"cidr": "192.0.2.1/32"}}],
                "egress": {"extraRules": [{"to": [{"ipBlock": {"cidr": "192.0.2.2/32"}}], "ports": [{"port": 443, "protocol": "TCP"}]}]},
            }
        },
    }
    resources = render(values)
    name = "security-test-blablador-token-generator"
    mapped = index(resources)
    app = mapped[("Deployment", name)]
    pg = mapped[("StatefulSet", name + "-postgresql")]
    redis = mapped[("Deployment", name + "-redis")]
    config = yaml.safe_load(mapped[("Secret", name + "-config")]["stringData"]["config.yaml"])
    for key, value in values["config"]["app"].items():
        assert config["app"][key] == value
    assert config["local"]["enabled"] is True
    assert config["database"]["ssl_ca_file"] == "/app/tls/postgresql/ca.crt"
    for workload in (app, pg, redis):
        pod = workload["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        container = pod["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert app["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert mapped[("NetworkPolicy", name)]["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert "noeviction" in redis["spec"]["template"]["spec"]["containers"][0]["args"]
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION" in mapped[("ConfigMap", name + "-postgresql-init")]["data"]["10-runtime-role.sh"]
    assert mapped[("Secret", name + "-redis")]["stringData"]["storage-uri"].startswith("rediss://")
    rotated = copy.deepcopy(values)
    rotated["postgresql"]["password"] = "P" * 64
    rotated["redis"]["password"] = "R" * 64
    after = index(render(rotated))
    for key in (("Deployment", name), ("StatefulSet", name + "-postgresql"), ("Deployment", name + "-redis")):
        assert mapped[key]["spec"]["template"] != after[key]["spec"]["template"]
    external = copy.deepcopy(values)
    external.update(configExistingSecret="app-config", secretRevision="rotated-2")
    external["postgresql"].update(existingSecret="pg-credentials", password="", adminPassword="")
    external["redis"].update(existingSecret="redis-credentials", password="")
    external["config"]["app"].update(secret_key="", token_hash_key="")
    assert all(resource["kind"] != "Secret" for resource in render(external))
    pinned = copy.deepcopy(values)
    pinned["image"]["digest"] = "sha256:" + "0" * 64
    pinned_app = index(render(pinned))[("Deployment", name)]
    assert "@sha256:" in pinned_app["spec"]["template"]["spec"]["containers"][0]["image"]
    for mutation in (
        {"image": {"tag": "latest"}},
        {"forwardedAllowIps": "*"},
        {"forwardedAllowIps": "10.0.0.0/8"},
        {"networkPolicy": {"app": {"enabled": False}}},
        {"networkPolicy": {"app": {"from": [{"namespaceSelector": {}}]}}},
        {"networkPolicy": {"app": {"egress": {"extraRules": [{}]}}}},
        {"postgresql": {"tls": {"enabled": False}}},
        {"postgresql": {"username": "token_admin"}},
        {"postgresql": {"password": "a" * 64}},
        {"postgresql": {"existingSecret": "opaque-credentials", "username": "token_admin"}},
        {"redis": {"tls": {"enabled": False}}},
        {"databaseBackend": "sqlite"},
    ):
        unsafe = copy.deepcopy(values)
        def merge(target: dict, changes: dict) -> None:
            for key, value in changes.items():
                if isinstance(value, dict):
                    merge(target.setdefault(key, {}), value)
                else:
                    target[key] = value
        merge(unsafe, mutation)
        render(unsafe, valid=False)
    render({}, valid=False)
    print("Helm security rendering checks passed")


def test_startup() -> None:
    with tempfile.TemporaryDirectory(prefix="token-generator-start-test-") as directory:
        work = Path(directory)
        shutil.copyfile(ROOT / "start.sh", work / "start.sh")
        binaries = work / ".venv" / "bin"
        binaries.mkdir(parents=True)
        (binaries / "activate").write_text("true\n")
        executable = binaries / "python"
        executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        executable.chmod(0o700)
        environment = dict(os.environ, HOST="127.0.0.2", PORT="9123", WORKERS="3", FORWARDED_ALLOW_IPS="192.0.2.1")
        result = subprocess.run(["bash", str(work / "start.sh"), "production"], env=environment, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        arguments = result.stdout.splitlines()
        for flag, expected in (("--host", "127.0.0.2"), ("--port", "9123"), ("--workers", "3")):
            assert arguments[arguments.index(flag) + 1] == expected
        environment["FORWARDED_ALLOW_IPS"] = "*"
        assert subprocess.run(["bash", str(work / "start.sh"), "production"], env=environment, capture_output=True).returncode != 0
    print("Startup binding and override checks passed")


def test_postgresql_separation() -> None:
    credential_names = ("POSTGRES_USER", "POSTGRES_PASSWORD", "TOKEN_DB_USER", "TOKEN_DB_PASSWORD")
    with tempfile.TemporaryDirectory(prefix="token-generator-role-guard-test-") as directory:
        work = Path(directory)
        marker = work / "psql-called"
        executable = work / "psql"
        executable.write_text('#!/bin/sh\nprintf "called\\n" >> "$AUDIT_PSQL_MARKER"\ncat >/dev/null\n')
        executable.chmod(0o700)
        environment = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"],
            AUDIT_PSQL_MARKER=str(marker), POSTGRES_USER="token_admin", POSTGRES_DB="tokens",
            POSTGRES_PASSWORD="SyntheticSeparateAdminPassword", TOKEN_DB_USER="tokens",
            TOKEN_DB_PASSWORD="SyntheticSeparateRuntimePassword", TOKEN_DB_REQUIRE_TLS="false")
        cases = [
            {"TOKEN_DB_USER": environment["POSTGRES_USER"]},
            {"TOKEN_DB_PASSWORD": environment["POSTGRES_PASSWORD"]},
            *({name: ""} for name in credential_names),
        ]
        for overrides in cases:
            unsafe = dict(environment, **overrides)
            result = subprocess.run(["sh", str(CHART / "files/init-runtime-role.sh")], env=unsafe,
                capture_output=True, text=True)
            assert result.returncode != 0
            assert not marker.exists(), "Unsafe credentials reached psql"
            for name in credential_names:
                if unsafe[name]:
                    assert unsafe[name] not in result.stdout + result.stderr, "Credential value leaked"
        for name in credential_names:
            missing = dict(environment)
            del missing[name]
            result = subprocess.run(["sh", str(CHART / "files/init-runtime-role.sh")], env=missing,
                capture_output=True, text=True)
            assert result.returncode != 0 and not marker.exists()
        safe = subprocess.run(["sh", str(CHART / "files/init-runtime-role.sh")], env=environment,
            capture_output=True, text=True)
        assert safe.returncode == 0, safe.stderr
        assert marker.read_text() == "called\n"
    print("PostgreSQL credential separation guards passed before SQL")


if __name__ == "__main__":
    test_chart()
    test_startup()
    test_postgresql_separation()
