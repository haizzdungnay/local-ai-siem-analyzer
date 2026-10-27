#!/usr/bin/env python3
"""Build Wazuh/ATT&CK JSON files compatible with existing ai_module/rag.py.

Standard library only; no network in starter mode. MITRE mode downloads a fixed
STIX release and records the source URL and SHA256. Does not change active index.
"""
import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "research" / "rag" / "generated"
STARTER = ROOT / "research" / "rag" / "starter"
MITRE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
             "master/enterprise-attack/enterprise-attack-20.0.json")
TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


def extract_mitre(data):
    """Retain active ATT&CK Enterprise technique objects, skip revoked/deprecated."""
    result = {}
    for obj in data.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references") or []
        ids = [ref.get("external_id") for ref in refs
               if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"]
        tech_id = next((v for v in ids if isinstance(v, str) and TECHNIQUE_ID.fullmatch(v)), None)
        if not tech_id:
            continue
        phases = obj.get("kill_chain_phases") or []
        tactics = sorted({p.get("phase_name", "").replace("-", " ").title()
                          for p in phases if isinstance(p, dict)
                          and p.get("kill_chain_name") == "mitre-attack"
                          and isinstance(p.get("phase_name"), str)})
        result[tech_id] = {
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:2000],
            "tactic": ", ".join(tactics),
        }
    return [result[key] for key in sorted(result)]


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build(mode, output, stix_file=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rules_bytes = (STARTER / "wazuh_rules.json").read_bytes()
    rules = json.loads(rules_bytes)
    write_json(output / "wazuh_rules.json", rules)
    source = "bundled starter"
    if mode == "starter":
        raw = (STARTER / "mitre_techniques.json").read_bytes()
        techniques = json.loads(raw)
    else:
        if stix_file:
            raw = Path(stix_file).read_bytes()
            source = str(Path(stix_file).resolve())
        else:
            request = urllib.request.Request(MITRE_URL, headers={"User-Agent": "AI-SIEM-research-RAG/1.0"})
            with urllib.request.urlopen(request, timeout=90) as response:
                raw = response.read(90 * 1024 * 1024 + 1)
            if len(raw) > 90 * 1024 * 1024:
                raise ValueError("STIX input exceeds 90 MiB")
            source = MITRE_URL
        techniques = extract_mitre(json.loads(raw))
        if len(techniques) < 100:
            raise ValueError("Suspiciously small ATT&CK corpus; refusing to overwrite")
    write_json(output / "mitre_techniques.json", techniques)
    manifest = {
        "schema_version": 1,
        "mode": mode,
        "source": source,
        "mitre_version": "20.0" if mode == "mitre-20.0" else "starter-curated",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "wazuh_rules_count": len(rules),
        "mitre_techniques_count": len(techniques),
        "wazuh_source_sha256": hashlib.sha256(rules_bytes).hexdigest(),
        "note": "Knowledge corpus only, not labels or ground truth. Check MITRE terms of use.",
    }
    write_json(output / "corpus_source_manifest.json", manifest)
    print(json.dumps(manifest, indent=2))
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("starter", "mitre-20.0"), default="starter")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--stix-file", type=Path, help="Optional offline STIX 2.1 bundle (MITRE v20.0)")
    args = parser.parse_args()
    if args.stix_file and args.mode != "mitre-20.0":
        parser.error("--stix-file only valid for --mode mitre-20.0")
    build(args.mode, args.output, args.stix_file)


if __name__ == "__main__":
    main()
