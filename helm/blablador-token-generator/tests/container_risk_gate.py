import argparse
from datetime import date
import json
from pathlib import Path


def unreviewed_findings(scan: dict, exceptions: dict, today: date) -> list[dict]:
    if not isinstance(scan.get("Results"), list):
        raise ValueError("The scan has no valid Results array")
    reviewed = set()
    for entry in exceptions.get("exceptions", []):
        if entry.get("status") != "not_affected" or not entry.get("reason", "").strip():
            raise ValueError("Risk exceptions require a not_affected assessment and reason")
        if date.fromisoformat(entry["expires"]) >= today:
            reviewed.add((entry["vulnerability_id"], entry["package_name"], entry["installed_version"]))
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
                blocked.append(vulnerability)
    return blocked


def self_test() -> None:
    vulnerability = {"VulnerabilityID": "CVE-test", "PkgName": "test", "InstalledVersion": "1", "Severity": "HIGH"}
    scan = {"Results": [{"Vulnerabilities": [vulnerability]}]}
    exception = {"vulnerability_id": "CVE-test", "package_name": "test", "installed_version": "1", "expires": "2026-11-10", "status": "not_affected", "reason": "Specific unreachable feature"}
    assert not unreviewed_findings(scan, {"exceptions": [exception]}, date(2026, 10, 11))
    assert unreviewed_findings(scan, {"exceptions": [exception]}, date(2026, 11, 11))
    exception["installed_version"] = "2"
    assert unreviewed_findings(scan, {"exceptions": [exception]}, date(2026, 10, 11))
    assert unreviewed_findings(scan, {"exceptions": []}, date(2026, 10, 11))
    try:
        unreviewed_findings({}, {}, date(2026, 10, 11))
    except ValueError:
        pass
    else:
        raise AssertionError("Missing scans must fail closed")
    print("Container risk gate regression checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scan", nargs="?")
    parser.add_argument("exceptions", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    else:
        if not arguments.scan or not arguments.exceptions:
            parser.error("scan and exceptions paths are required")
        blocked = unreviewed_findings(json.loads(Path(arguments.scan).read_text()), json.loads(Path(arguments.exceptions).read_text()), date.today())
        for finding in blocked:
            print(f'{finding["Severity"]} {finding["VulnerabilityID"]} {finding["PkgName"]} {finding["InstalledVersion"]}')
        if blocked:
            raise SystemExit(1)
        print("No unreviewed HIGH or CRITICAL container vulnerabilities")
