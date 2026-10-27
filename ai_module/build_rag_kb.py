#!/usr/bin/env python3
"""build_rag_kb.py — Trích rule Wazuh từ ruleset XML -> wazuh_rules.json cho RAG KB."""
import argparse
import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

_AMP = re.compile(r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)')


def _load_root(path: Path):
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw = _AMP.sub("&amp;", raw)
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)
    wrapped = "<root>" + raw + "</root>"
    try:
        return ET.fromstring(wrapped)
    except ET.ParseError as e:
        print(f"  [WARN] parse loi {path.name}: {e}", file=sys.stderr)
        return None


def _iter_rules(elem, parent_group=None):
    for child in list(elem):
        if child.tag == "group":
            pg = child.get("name") or parent_group
            yield from _iter_rules(child, pg)
        elif child.tag == "rule":
            yield child, parent_group
        else:
            yield from _iter_rules(child, parent_group)


def _txt(rule, tag):
    el = rule.find(tag)
    return (el.text or "").strip() if el is not None else ""


def _rule_to_dict(rule, parent_group, filename):
    groups = set()
    if parent_group:
        groups.update(g.strip() for g in parent_group.split(",") if g.strip())
    for g in rule.findall("group"):
        if g.text:
            groups.update(x.strip() for x in g.text.split(",") if x.strip())

    mitre = []
    m = rule.find("mitre")
    if m is not None:
        for mid in m.findall("id"):
            if mid.text and mid.text.strip():
                mitre.append(mid.text.strip())

    d = {
        "id": rule.get("id"),
        "level": rule.get("level"),
        "frequency": rule.get("frequency"),
        "timeframe": rule.get("timeframe"),
        "description": _txt(rule, "description"),
        "groups": sorted(groups),
        "mitre": mitre,
        "if_sid": _txt(rule, "if_sid"),
        "if_matched_sid": _txt(rule, "if_matched_sid"),
        "file": filename,
    }
    parts = [f"Rule {d['id']} (level {d['level']}): {d['description']}"]
    if d["mitre"]:
        parts.append("MITRE: " + ", ".join(d["mitre"]))
    if d["groups"]:
        parts.append("Groups: " + ", ".join(d["groups"]))
    if d["if_sid"]:
        parts.append(f"Kich hoat tu rule {d['if_sid']}")
    if d["if_matched_sid"]:
        parts.append(f"Tuong quan tu rule {d['if_matched_sid']} "
                     f"(freq={d['frequency']}, timeframe={d['timeframe']})")
    d["text"] = ". ".join(parts)
    return d


def build(rules_dir: Path):
    files = sorted(rules_dir.glob("*.xml"))
    if not files:
        print(f"!! Khong thay *.xml trong {rules_dir}", file=sys.stderr)
        sys.exit(1)

    rules = {}
    dupes = 0
    for f in files:
        root = _load_root(f)
        if root is None:
            continue
        for rule, pg in _iter_rules(root):
            rid = rule.get("id")
            if not rid:
                continue
            rec = _rule_to_dict(rule, pg, f.name)
            if rid in rules:
                dupes += 1
            rules[rid] = rec

    out = list(rules.values())
    print(f"[OK] {len(files)} file -> {len(out)} rule (unique)"
          f"{f', {dupes} override' if dupes else ''}", file=sys.stderr)
    withdesc = sum(1 for r in out if r["description"])
    withmitre = sum(1 for r in out if r["mitre"])
    print(f"     {withdesc} co description, {withmitre} co MITRE", file=sys.stderr)
    return out


def main():
    ap = argparse.ArgumentParser(description="Trich rule Wazuh -> JSON cho RAG")
    ap.add_argument("rules_dir", help="Thu muc chua *.xml")
    ap.add_argument("-o", "--output", default="wazuh_rules.json")
    args = ap.parse_args()

    out = build(Path(args.rules_dir))
    Path(args.output).write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    print(f"[OK] Ghi {len(out)} rule -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()