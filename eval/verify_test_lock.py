"""
eval/verify_test_lock.py — kiểm tra tập test/held-out đã khóa (eval/test_set_lock.json) không bị đổi.

- File export local (eval/raw_exports/, gitignored): so SHA-256 nếu file có trên máy; thiếu file
  thì báo MISSING (máy khác không có bản local là bình thường), khác hash thì FAIL.
- Bộ eval tracked (eval/cases, eval/expected, eval/stratified_370): so git tree hash tại HEAD.
- `forbidden_hashes()` dùng cho pipeline SFT: từ chối mọi file đầu vào có hash nằm trong tập khóa.

Chạy từ thư mục gốc repo:
    python eval/verify_test_lock.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "eval" / "test_set_lock.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lock(path: Path = LOCK_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def forbidden_hashes(lock: dict | None = None) -> set[str]:
    lock = lock if lock is not None else load_lock()
    return {entry["sha256"] for entry in lock.get("files", [])}


def assert_not_test_data(path: Path, lock: dict | None = None) -> None:
    """Gọi trước khi dùng một file làm dữ liệu train; raise nếu file là dữ liệu test đã khóa."""
    if sha256_file(Path(path)) in forbidden_hashes(lock):
        raise ValueError(f"{path} nằm trong tập test đã khóa (eval/test_set_lock.json) — không được dùng để train")


def _git_tree(spec: str) -> str | None:
    try:
        done = subprocess.run(["git", "-C", str(ROOT), "rev-parse", f"HEAD:{spec}"],
                              capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return done.stdout.decode("ascii").strip()


def verify(lock: dict, root: Path = ROOT, check_git: bool = True) -> tuple[list[str], list[str]]:
    failures, notes = [], []
    for entry in lock.get("files", []):
        path = root / entry["path"]
        if not path.exists():
            notes.append(f"MISSING {entry['path']} (không có bản local trên máy này)")
            continue
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            failures.append(f"FAIL {entry['path']}: sha256 {actual[:12]}… != {entry['sha256'][:12]}…")
        else:
            notes.append(f"OK   {entry['path']}")
    if check_git:
        for spec, expected in (lock.get("tracked_eval_sets", {}).get("git_tree") or {}).items():
            actual = _git_tree(spec)
            if actual is None:
                notes.append(f"SKIP {spec} (không đọc được git tree)")
            elif actual != expected:
                failures.append(f"FAIL {spec}: git tree {actual[:12]}… != {expected[:12]}…")
            else:
                notes.append(f"OK   {spec} (git tree)")
    return failures, notes


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    failures, notes = verify(load_lock())
    for line in notes + failures:
        print(line)
    if failures:
        raise SystemExit(f"\nTập test đã bị thay đổi ({len(failures)} mục). Không chạy thí nghiệm cho tới khi giải thích được.")
    print("\nTập test khớp với eval/test_set_lock.json")


if __name__ == "__main__":
    main()
