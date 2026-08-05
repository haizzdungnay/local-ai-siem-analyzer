"""Fail CI for vulnerable Python dependencies unless a dated exception matches."""
import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path


def _load_allowlist(path: Path) -> dict[tuple[str, str], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("allowlist exceptions must be a list")
    allowlist = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("allowlist entry must be an object")
        vulnerability = entry.get("id")
        package = entry.get("package")
        expiry = entry.get("expires")
        reason = entry.get("reason")
        if not all(isinstance(value, str) and value for value in (vulnerability, package, expiry, reason)):
            raise ValueError("allowlist entry requires id, package, expires and reason")
        try:
            expiry_date = dt.date.fromisoformat(expiry)
        except ValueError as exc:
            raise ValueError(f"invalid allowlist expiry: {expiry}") from exc
        if expiry_date < dt.date.today():
            raise ValueError(f"expired vulnerability exception: {vulnerability} for {package}")
        key = (package.lower(), vulnerability)
        if key in allowlist:
            raise ValueError(f"duplicate vulnerability exception: {package} {vulnerability}")
        allowlist[key] = entry
    return allowlist


def _audit(requirements: Path) -> list[dict]:
    completed = subprocess.run(
        [sys.executable, "-m", "pip_audit", "-r", str(requirements), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or "pip-audit did not complete")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("pip-audit did not return JSON") from exc
    if isinstance(payload, dict):
        payload = payload.get("dependencies")
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise RuntimeError("pip-audit JSON has an unexpected dependency format")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit dependencies with expiring exceptions")
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    args = parser.parse_args()

    allowlist = _load_allowlist(args.allowlist)
    findings = []
    for dependency in _audit(args.requirements):
        package = dependency.get("name")
        for vulnerability in dependency.get("vulns", []):
            vulnerability_id = vulnerability.get("id")
            if isinstance(package, str) and isinstance(vulnerability_id, str):
                findings.append((package.lower(), vulnerability_id))

    finding_set = set(findings)
    unused = set(allowlist) - finding_set
    if unused:
        details = ", ".join(f"{package}:{vulnerability}" for package, vulnerability in sorted(unused))
        raise SystemExit(f"remove stale vulnerability exception(s): {details}")
    unwaived = finding_set - set(allowlist)
    if unwaived:
        details = ", ".join(f"{package}:{vulnerability}" for package, vulnerability in sorted(unwaived))
        raise SystemExit(f"unwaived dependency vulnerability/vulnerabilities: {details}")
    print(f"dependency audit passed; {len(findings)} documented exception(s) remain active")


if __name__ == "__main__":
    main()
