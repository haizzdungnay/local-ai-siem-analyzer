"""Detect likely live secrets in tracked configuration and documentation files."""
import argparse
import re
import subprocess
import sys
from pathlib import Path


SCAN_SUFFIXES = {".md", ".yaml", ".yml", ".env", ".ini", ".toml"}
ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret)\b
    \s*(?:[:=]|is|là)\s*[`"']?
    (?!CHANGE_ME\b|REDACTED\b|<[^>]+>\b)
    [A-Za-z0-9_+/=-]{6,}
    """
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
BASIC_AUTH_URL_RE = re.compile(r"https?://[^\s/:]+:[^\s@/]+@", re.IGNORECASE)


def _should_scan(path: str) -> bool:
    candidate = Path(path)
    return candidate.suffix.lower() in SCAN_SUFFIXES or candidate.name.lower().startswith("config.")


def _line_numbers(pattern: re.Pattern, text: str) -> list[int]:
    return [text.count("\n", 0, match.start()) + 1 for match in pattern.finditer(text)]


def scan_text(path: str, text: str) -> list[str]:
    if not _should_scan(path):
        return []
    findings = []
    for label, pattern in (
        ("credential assignment", ASSIGNMENT_RE),
        ("private key", PRIVATE_KEY_RE),
        ("basic-auth URL", BASIC_AUTH_URL_RE),
    ):
        findings.extend(f"{path}:{line}: {label}" for line in _line_numbers(pattern, text))
    return findings


def _git_paths(staged: bool) -> list[str]:
    command = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"] if staged else ["git", "ls-files"]
    completed = subprocess.run(command, capture_output=True, check=True)
    return [line for line in completed.stdout.decode("utf-8").splitlines() if line]


def _read_path(path: str, staged: bool) -> str:
    if staged:
        completed = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True)
        # Git emits UTF-8 blobs; Windows' process default can otherwise be cp1252.
        return completed.stdout.decode("utf-8")
    return Path(path).read_text(encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan tracked configuration/docs for live credential material")
    parser.add_argument("--staged", action="store_true", help="scan staged Git blobs instead of the worktree")
    args = parser.parse_args()

    findings = []
    for path in _git_paths(args.staged):
        if not _should_scan(path):
            continue
        try:
            findings.extend(scan_text(path, _read_path(path, args.staged)))
        except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
            raise SystemExit(f"cannot scan {path}: {type(exc).__name__}") from exc
    if findings:
        print("potential tracked secret material found:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        raise SystemExit(1)
    print("tracked configuration/documentation secret scan passed")


if __name__ == "__main__":
    main()
