#!/usr/bin/env python3
"""Create unlabeled, privacy-minimized candidate records from JSONL event logs.

This does NOT infer attack success, severity or ready-to-train assistant outputs.
No external libraries are required. Input/output paths should remain untracked.
"""
import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path

SECRET = re.compile(r"(?i)\b(?:authorization|bearer|api[_ -]?key|password|passwd|token|secret)\b\s*[:=]\s*[^\s,;]+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def scrub(text):
    text = SECRET.sub("[REDACTED_SECRET]", str(text))
    text = EMAIL.sub("[REDACTED_EMAIL]", text)
    def substitute(match):
        address = match.group()
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            return address
        return "[REDACTED_IP]"
    return IPV4.sub(substitute, text)


def convert(source_path, output_path, source_id, scenario_id, max_events):
    source_path, output_path = Path(source_path), Path(output_path)
    if source_path.resolve() == output_path.resolve():
        raise ValueError("Output must differ from input")
    if max_events <= 0 or max_events > 100000:
        raise ValueError("max-events outside safe range")
    count, malformed = 0, 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with source_path.open("r", encoding="utf-8", errors="replace") as input_stream, output_path.open("w", encoding="utf-8") as output_stream:
        for line_number, line in enumerate(input_stream, 1):
            if count >= max_events:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(event, dict):
                malformed += 1
                continue
            canonical = json.dumps(event, sort_keys=True, ensure_ascii=False)
            case_id = hashlib.sha256(f"{source_id}:{scenario_id}:{line_number}:{canonical}".encode()).hexdigest()[:20]
            # Whitelist only small fields. Avoid unreviewed raw command lines and event blobs.
            selected = {}
            for key in ("EventCode", "EventID", "EventId", "Provider_Name", "source", "sourcetype", "host", "Computer", "Channel", "Message"):
                value = event.get(key)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    selected[key] = scrub(str(value)[:1000]) if key == "Message" else scrub(str(value)[:200])
            candidate = {
                "case_id": f"candidate-{case_id}",
                "source_id": source_id,
                "scenario_id": scenario_id,
                "split_group_id": scenario_id,
                "event": selected,
                "review_status": "unreviewed",
                "attack_outcome": "unknown",
                "disposition": None,
                "severity": None,
                "mitre_ids": [],
                "evidence_reviewed": False,
                "train_ready": False,
            }
            output_stream.write(json.dumps(candidate, ensure_ascii=False) + "\n")
            count += 1
    return {"candidates": count, "malformed_or_non_object": malformed, "output": str(output_path)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--source-id", required=True)
    p.add_argument("--scenario-id", required=True)
    p.add_argument("--max-events", type=int, default=500)
    a = p.parse_args()
    print(json.dumps(convert(a.input, a.out, a.source_id, a.scenario_id, a.max_events), indent=2))


if __name__ == "__main__":
    main()
