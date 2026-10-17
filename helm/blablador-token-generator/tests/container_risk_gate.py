import argparse
from datetime import date, timedelta
import json
from pathlib import Path

# A reviewed exception is a dated assessment, not a permanent waiver.
MAX_EXCEPTION_DAYS = 120


def reviewed_exceptions(exceptions: dict, today: date) -> set[tuple[str, str, str]]:
    reviewed = set()
    for entry in exceptions.get("exceptions", []):
        if entry.get("status") != "not_affected" or not entry.get("reason", "").strip():
            raise ValueError("Risk exceptions require a not_affected assessment and reason")
        expires = date.fromisoformat(entry["expires"])
        if expires > today + timedelta(days=MAX_EXCEPTION_DAYS):
            raise ValueError(f"Risk exceptions may last at most {MAX_EXCEPTION_DAYS} days "
                             f"({entry['vulnerability_id']} expires {entry['expires']})")
        if expires >= today:
            reviewed.add((entry["vulnerability_id"], entry["package_name"], entry["installed_version"]))
    return reviewed


def unreviewed_binary_findings(scan: dict, exceptions: dict, today: date) -> list[str]:
    """Grype: HIGH/CRITICAL findings in programs installed outside the package
    manager, such as the PostgreSQL and Redis servers, which Trivy does not
    see. Operating-system packages are left to the Trivy gate."""
    if not isinstance(scan.get("matches"), list) or not scan.get("source") or not scan.get("distro"):
        raise ValueError("The Grype scan has no valid matches, source or distribution")
    reviewed = reviewed_exceptions(exceptions, today)
    blocked = []
    for match in scan["matches"]:
        artifact, vulnerability = match["artifact"], match["vulnerability"]
        if artifact.get("type") != "binary" or vulnerability.get("severity") not in {"High", "Critical"}:
            continue
        identity = (vulnerability["id"], artifact["name"], artifact["version"])
        if identity not in reviewed:
            blocked.append(" ".join([vulnerability["severity"].upper(), *identity]))
    return blocked


def unreviewed_findings(scan: dict, exceptions: dict, today: date) -> list[str]:
    """HIGH/CRITICAL vulnerabilities without a current assessment, and secrets.

    Fails closed (ValueError) on a scan that cannot be trusted to be complete:
    no results, no identified operating system or no package results for it,
    or an operating system past its end of support (no more fixes).
    """
    if not isinstance(scan.get("Results"), list):
        raise ValueError("The scan has no valid Results array")
    system = (scan.get("Metadata") or {}).get("OS") or {}
    if not system.get("Family"):
        raise ValueError("The scan did not identify the image's operating system")
    if system.get("EOSL"):
        raise ValueError(f"{system['Family']} {system.get('Name', '')} is past its end of support")
    if not any(result.get("Class") == "os-pkgs" for result in scan["Results"]):
        raise ValueError("The scan has no operating-system package results")
    reviewed = reviewed_exceptions(exceptions, today)
    blocked = []
    for result in scan["Results"]:
        for vulnerability in result.get("Vulnerabilities") or []:
            if vulnerability.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            identity = (
                vulnerability["VulnerabilityID"],
                vulnerability["PkgName"],
                vulnerability["InstalledVersion"],
            )
            if identity not in reviewed:
                blocked.append(" ".join([vulnerability["Severity"], *identity]))
        for secret in result.get("Secrets") or []:
            blocked.append(f"SECRET {secret.get('RuleID', 'unknown')} in {result.get('Target', '?')}")
    return blocked


def self_test() -> None:
    vulnerability = {"VulnerabilityID": "CVE-test", "PkgName": "test", "InstalledVersion": "1", "Severity": "HIGH"}
    metadata = {"OS": {"Family": "debian", "Name": "13.1"}}

    def scan(*results):
        return {"Metadata": metadata, "Results": [{"Class": "os-pkgs", "Target": "image"}, *results]}

    vulnerable = scan({"Class": "os-pkgs", "Vulnerabilities": [vulnerability]})
    exception = {"vulnerability_id": "CVE-test", "package_name": "test", "installed_version": "1", "expires": "2026-11-10", "status": "not_affected", "reason": "Specific unreachable feature"}
    assert not unreviewed_findings(vulnerable, {"exceptions": [exception]}, date(2026, 10, 11))
    assert unreviewed_findings(vulnerable, {"exceptions": [exception]}, date(2026, 11, 11))
    exception["installed_version"] = "2"
    assert unreviewed_findings(vulnerable, {"exceptions": [exception]}, date(2026, 10, 11))
    assert unreviewed_findings(vulnerable, {"exceptions": []}, date(2026, 10, 11))
    assert unreviewed_findings(scan({"Class": "secret", "Target": "/app/key.pem", "Secrets": [{"RuleID": "private-key"}]}),
                               {"exceptions": []}, date(2026, 10, 11))
    distant = dict(exception, installed_version="1", expires="9999-12-31")
    untrusted = (
        ({}, {}),
        ({"Results": []}, {}),
        ({"Metadata": metadata, "Results": []}, {}),
        ({"Metadata": {"OS": {"Family": "alpine", "Name": "3.21.8", "EOSL": True}}, "Results": scan()["Results"]}, {}),
        (vulnerable, {"exceptions": [distant]}),
    )
    for candidate, candidate_exceptions in untrusted:
        try:
            unreviewed_findings(candidate, candidate_exceptions, date(2026, 10, 11))
        except ValueError:
            continue
        raise AssertionError(f"Untrusted input must fail closed: {candidate}")
    server = {"artifact": {"type": "binary", "name": "redis", "version": "8.0.0"},
              "vulnerability": {"id": "CVE-binary", "severity": "Critical"}}
    package = {"artifact": {"type": "apk", "name": "busybox", "version": "1"},
               "vulnerability": {"id": "CVE-package", "severity": "High"}}
    grype = {"source": {"type": "image"}, "distro": {"name": "alpine"}, "matches": [server, package]}
    assert unreviewed_binary_findings(grype, {"exceptions": []}, date(2026, 10, 11)) == ["CRITICAL CVE-binary redis 8.0.0"]
    accepted = dict(exception, vulnerability_id="CVE-binary", package_name="redis", installed_version="8.0.0")
    assert not unreviewed_binary_findings(grype, {"exceptions": [accepted]}, date(2026, 10, 11))
    try:
        unreviewed_binary_findings({"matches": []}, {}, date(2026, 10, 11))
    except ValueError:
        pass
    else:
        raise AssertionError("An incomplete Grype scan must fail closed")
    print("Container risk gate regression checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scan", nargs="?")
    parser.add_argument("exceptions", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--grype", action="store_true", help="the scan is Grype JSON (binaries only)")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    else:
        if not arguments.scan or not arguments.exceptions:
            parser.error("scan and exceptions paths are required")
        check = unreviewed_binary_findings if arguments.grype else unreviewed_findings
        blocked = check(json.loads(Path(arguments.scan).read_text()), json.loads(Path(arguments.exceptions).read_text()), date.today())
        for finding in blocked:
            print(finding)
        if blocked:
            raise SystemExit(1)
        print("No unreviewed HIGH or CRITICAL container vulnerabilities or secrets")
