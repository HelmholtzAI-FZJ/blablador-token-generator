"""Verify an already built local image without production secrets or networking."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "security_audit/evidence"
SCRATCH = Path("/private/tmp/token-generator-audit-container")
IMAGE = "token-generator-security-audit:remediated"
TRIVY = "aquasec/trivy:0.75.0"


def run(arguments: list[str]) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def main() -> None:
    inspected = json.loads(run(["docker", "image", "inspect", IMAGE]))[0]
    metadata = {key: inspected[key] for key in (
        "Id", "RepoDigests", "RepoTags", "Created", "Architecture", "Os", "Size"
    )}
    metadata.update(user=inspected["Config"]["User"],
                    environment=inspected["Config"]["Env"],
                    command=inspected["Config"]["Cmd"])
    (EVIDENCE / "final-app-image-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    restrictions = ["--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--pids-limit", "128",
                    "--memory", "512m", "--cpus", "1"]
    code = """import hashlib, importlib.metadata, importlib.util, json, os, sys
from pathlib import Path
print(json.dumps({
 'python':sys.version,'uid':os.getuid(),
 'runtime_pip_module':importlib.util.find_spec('pip') is not None,
 'base_pip_directory':any(Path('/usr/local/lib/python3.12/site-packages').glob('pip*')),
 'ensurepip_directory':Path('/usr/local/lib/python3.12/ensurepip').exists(),
 'sources':{str(p.relative_to('/app')):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path('/app/app').rglob('*')) if p.is_file() and '__pycache__' not in p.parts},
 'packages':sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions()),
 'systemd_homed_present':any(Path(p).exists() for p in ('/usr/lib/systemd/systemd-homed','/lib/systemd/systemd-homed')),
 'perl_archive_tar_present':any(Path('/usr').rglob('Archive/Tar.pm'))
}))
"""
    runtime = json.loads(run(["docker", "run", *restrictions, "--entrypoint", "python", IMAGE, "-c", code]))
    expected = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((ROOT / "app").rglob("*"))
                if p.is_file() and "__pycache__" not in p.parts}
    assert runtime["sources"] == expected, "Built application differs from reviewed sources"
    assert runtime["uid"] == 10001
    assert not any(runtime[name] for name in (
        "runtime_pip_module", "base_pip_directory", "ensurepip_directory",
        "systemd_homed_present", "perl_archive_tar_present"
    ))
    runtime.update(image_id=metadata["Id"], all_source_hashes_match=True,
                   runtime_restrictions=restrictions)
    (EVIDENCE / "final-app-runtime.json").write_text(json.dumps(runtime, indent=2) + "\n")
    smoke = run(["docker", "run", *restrictions,
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=10001,gid=10001,mode=0700",
                 "--mount", f"type=bind,source={ROOT / 'security_audit/probes'},target=/audit/probes,readonly",
                 "--mount", f"type=bind,source={ROOT / 'tests/config.test.yaml'},target=/audit/config.test.yaml,readonly",
                 "--entrypoint", "python", IMAGE, "/audit/probes/image_smoke.py"])
    (EVIDENCE / "final-app-smoke.txt").write_text(smoke)
    run(["docker", "save", "--output", str(SCRATCH / "final.tar"), IMAGE])
    base = ["docker", "run", "--rm", "--network", "none",
            "--mount", f"type=bind,source={SCRATCH},target=/audit",
            TRIVY, "image", "--input", "/audit/final.tar", "--cache-dir", "/audit/cache",
            "--skip-db-update", "--skip-java-db-update", "--offline-scan"]
    run([*base, "--scanners", "vuln,secret", "--format", "json", "--output", "/audit/final-trivy.json"])
    run([*base, "--format", "cyclonedx", "--output", "/audit/final-sbom.json"])
    for scratch_name, evidence_name in (("final-trivy.json", "final-app-trivy.json"),
                                       ("final-sbom.json", "final-app-sbom.json")):
        (EVIDENCE / evidence_name).write_bytes((SCRATCH / scratch_name).read_bytes())
    scan = json.loads((EVIDENCE / "final-app-trivy.json").read_text())
    assert scan["Metadata"]["ImageID"] == metadata["Id"]
    vulnerabilities = [v for result in scan["Results"] for v in result.get("Vulnerabilities") or []]
    secrets = [s for result in scan["Results"] for s in result.get("Secrets") or []]
    assert not secrets
    print(json.dumps({"image_id": metadata["Id"], "source_match": True,
                      "runtime_and_smoke": "passed", "vulnerability_entries": len(vulnerabilities),
                      "secret_alerts": len(secrets)}))


if __name__ == "__main__":
    main()
