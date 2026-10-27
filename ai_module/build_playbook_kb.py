#!/usr/bin/env python3
"""build_playbook_kb.py — Trich playbook dieu tra/ung pho tu Elastic detection-rules.

Nguon: https://github.com/elastic/detection-rules (Elastic License 2.0).
Moi rule TOML co truong `rule.note` (investigation guide) gom cac muc
"Possible investigation steps", "False positive analysis", "Response and
remediation", va `rule.threat` gan MITRE ATT&CK technique ID. Script tach
3 muc do thanh danh sach buoc, gan theo technique ID de tra cuu chinh xac
voi `rule.mitre.id` cua alert Wazuh.

Output KHONG commit len repo public (ELv2); chi commit script nay. Chay lai:

    git clone https://github.com/elastic/detection-rules.git <dir>
    git -C <dir> checkout <commit>
    python ai_module/build_playbook_kb.py <dir> -o ai_module/rag_data/elastic_playbooks.json
"""
import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

DEFAULT_DIRS = ("linux", "cross-platform")

SECTION_ALIASES = {
    "possible investigation steps": "investigation",
    "investigation steps": "investigation",
    "false positive analysis": "false_positives",
    "false positive considerations": "false_positives",
    "response and remediation": "response",
}

# Buoc phu thuoc cong cu Elastic -> khong ap dung duoc cho Wazuh.
# "Timeline"/"Session View" viet hoa = tinh nang Kibana; "timeline of events" la
# thuat ngu dieu tra chung nen giu lai.
ELASTIC_TOOLING_RE = re.compile(
    r"(?i:\b(?:osquery|kibana|fleet|elastic agent)\b)|\bTimelines?\b|\bSession View\b"
)
HEADING_RE = re.compile(r"^\s*#{1,6}\s*(.+?)\s*#*\s*$")
BULLET_RE = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$")
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def _clean(text: str) -> str:
    text = LINK_RE.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_note(note: str) -> tuple[dict, int]:
    """Tach note markdown -> {investigation, false_positives, response}, so buoc bi loai."""
    sections = {"investigation": [], "false_positives": [], "response": []}
    current = None
    item = None
    item_indent = 0
    dropped = 0

    def flush():
        nonlocal item, dropped
        if current and item:
            step = _clean(item)
            if "!{" in step or ELASTIC_TOOLING_RE.search(step):
                dropped += 1
            elif step and step not in sections[current]:
                sections[current].append(step)
        item = None

    for line in (note or "").splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            flush()
            current = SECTION_ALIASES.get(heading.group(1).strip().lower().rstrip(":"))
            continue
        if current is None:
            continue
        bullet = BULLET_RE.match(line)
        if bullet:
            indent = len(bullet.group(1).expandtabs(4))
            if item is not None and indent > item_indent:
                item += "; " + bullet.group(2)   # bullet con -> gop vao buoc cha
                continue
            flush()
            item, item_indent = bullet.group(2), indent
        elif line.strip() and item is not None and line.startswith((" ", "\t")):
            item += " " + line.strip()   # dong noi tiep cua bullet
        else:
            flush()
    flush()
    return sections, dropped


def _techniques(threat: list) -> tuple[list, list]:
    techniques, tactics = [], []
    for entry in threat or []:
        if entry.get("framework") != "MITRE ATT&CK":
            continue
        tactic = (entry.get("tactic") or {}).get("name")
        if tactic and tactic not in tactics:
            tactics.append(tactic)
        for tech in entry.get("technique") or []:
            for tid in [tech.get("id")] + [s.get("id") for s in tech.get("subtechnique") or []]:
                if tid and tid not in techniques:
                    techniques.append(tid)
    return techniques, tactics


def build(repo: Path, dirs=DEFAULT_DIRS) -> tuple[list, dict]:
    stats = {"files": 0, "kept": 0, "no_note": 0, "no_technique": 0,
             "not_production": 0, "empty_sections": 0, "dropped_tooling_steps": 0}
    out = []
    for sub in dirs:
        for path in sorted((repo / "rules" / sub).glob("*.toml")):
            stats["files"] += 1
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            rule = data.get("rule", {})
            if data.get("metadata", {}).get("maturity") != "production":
                stats["not_production"] += 1
                continue
            if not rule.get("note"):
                stats["no_note"] += 1
                continue
            techniques, tactics = _techniques(rule.get("threat"))
            if not techniques:
                stats["no_technique"] += 1
                continue
            sections, dropped = parse_note(rule["note"])
            stats["dropped_tooling_steps"] += dropped
            if not any(sections.values()):
                stats["empty_sections"] += 1
                continue
            out.append({
                "id": rule["rule_id"],
                "name": rule.get("name", ""),
                "description": _clean(rule.get("description", "")),
                "techniques": techniques,
                "tactics": tactics,
                **sections,
                "source_path": path.relative_to(repo).as_posix(),
            })
            stats["kept"] += 1
    out.sort(key=lambda rec: (rec["techniques"][0], rec["id"]))
    return out, stats


def _repo_commit(repo: Path) -> str:
    try:
        done = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, check=True)
        return done.stdout.decode("ascii").strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="Thu muc clone elastic/detection-rules")
    ap.add_argument("-o", "--output", default="elastic_playbooks.json")
    ap.add_argument("--dirs", nargs="+", default=list(DEFAULT_DIRS),
                    help="Thu muc con trong rules/ (mac dinh: linux cross-platform)")
    args = ap.parse_args()

    repo = Path(args.repo)
    if not (repo / "rules").is_dir():
        sys.exit(f"!! Khong thay {repo / 'rules'}")
    playbooks, stats = build(repo, args.dirs)
    doc = {
        "source": "https://github.com/elastic/detection-rules",
        "commit": _repo_commit(repo),
        "license": "Elastic License 2.0",
        "dirs": args.dirs,
        "stats": stats,
        "playbooks": playbooks,
    }
    Path(args.output).write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    print(f"[OK] {stats}", file=sys.stderr)
    print(f"[OK] Ghi {len(playbooks)} playbook -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
