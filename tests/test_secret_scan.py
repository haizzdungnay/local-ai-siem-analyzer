import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_scanner():
    path = ROOT / "scripts" / "check_tracked_secrets.py"
    spec = importlib.util.spec_from_file_location("check_tracked_secrets", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_secret_scan_allows_placeholders_and_ignores_source_fixtures():
    scanner = load_scanner()

    assert scanner.scan_text("config.example.yaml", 'password: "CHANGE_ME"\n') == []
    assert scanner.scan_text("tests/test_example.py", 'raw = "password=fixture-secret"\n') == []


def test_secret_scan_flags_live_assignment_private_key_and_basic_auth_url():
    scanner = load_scanner()

    findings = scanner.scan_text(
        "docs/runbook.md",
        "password: a-long-live-value\nhttps://analyst:another-secret@example.test\n"
        "-----BEGIN PRIVATE KEY-----\n",
    )

    assert any("credential assignment" in finding for finding in findings)
    assert any("basic-auth URL" in finding for finding in findings)
    assert any("private key" in finding for finding in findings)


def test_secret_scan_decodes_staged_git_blobs_as_utf8(monkeypatch):
    scanner = load_scanner()

    class Completed:
        stdout = "Tài liệu UTF-8\n".encode("utf-8")

    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: Completed())

    assert scanner._read_path("docs/runbook.md", staged=True) == "Tài liệu UTF-8\n"
