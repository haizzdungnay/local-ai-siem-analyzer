#!/usr/bin/env python3
"""build_mitre_kb.py — Trich MITRE ATT&CK tu mitre.db (Wazuh) -> mitre_techniques.json."""
import argparse
import json
import sqlite3
import sys
from pathlib import Path


def tables(con):
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def cols(con, t):
    return [r[1] for r in con.execute(f"PRAGMA table_info('{t}')")]


def dump_schema(con):
    print("[SCHEMA]", file=sys.stderr)
    for t in tables(con):
        print(f"  {t}: {cols(con, t)}", file=sys.stderr)


def first_present(candidates, available):
    for c in candidates:
        if c in available:
            return c
    return None


def build(db_path):
    con = sqlite3.connect(db_path)
    tbls = tables(con)
    dump_schema(con)

    if "technique" not in tbls:
        print("!! Khong thay bang 'technique'. Xem schema o tren.", file=sys.stderr)
        sys.exit(1)

    tactic_name = {}
    if "tactic" in tbls:
        tc = cols(con, "tactic")
        idc = first_present(["id"], tc) or tc[0]
        namec = first_present(["name", "short_name"], tc)
        for r in con.execute(f"SELECT * FROM tactic"):
            d = dict(zip(tc, r))
            tactic_name[d.get(idc)] = d.get(namec) if namec else None

    tech_tactics = {}
    link_tbl = first_present(["phase", "has_phase", "technique_has_phase"], tbls)
    if link_tbl:
        lc = cols(con, link_tbl)
        techc = first_present(["tech_id", "technique_id", "id_technique", "source_id"], lc)
        tacc = first_present(["tactic_id", "id_tactic", "target_id", "tactic"], lc)
        if techc and tacc:
            for r in con.execute(f"SELECT * FROM {link_tbl}"):
                d = dict(zip(lc, r))
                tech, tac = d.get(techc), d.get(tacc)
                if tech:
                    nm = tactic_name.get(tac, tac)
                    tech_tactics.setdefault(tech, [])
                    if nm and nm not in tech_tactics[tech]:
                        tech_tactics[tech].append(nm)

    mit_name = {}
    if "mitigation" in tbls:
        mc = cols(con, "mitigation")
        idc = first_present(["id"], mc) or mc[0]
        namec = first_present(["name"], mc)
        for r in con.execute("SELECT * FROM mitigation"):
            d = dict(zip(mc, r))
            mit_name[d.get(idc)] = d.get(namec) if namec else None

    tech_mit = {}
    mlink = first_present(["mitigate", "has_mitigation", "technique_has_mitigation"], tbls)
    if mlink:
        lc = cols(con, mlink)
        mc_ = first_present(["source_id", "id_mitigation", "mitigation_id"], lc)
        tc_ = first_present(["target_id", "id_technique", "technique_id", "tech_id"], lc)
        if mc_ and tc_:
            for r in con.execute(f"SELECT * FROM {mlink}"):
                d = dict(zip(lc, r))
                mit, tech = d.get(mc_), d.get(tc_)
                if tech:
                    nm = mit_name.get(mit, mit)
                    tech_mit.setdefault(tech, [])
                    if nm and nm not in tech_mit[tech]:
                        tech_mit[tech].append(nm)

    # STIX id (attack-pattern--...) -> ATT&CK external id (T1110). Alert Wazuh
    # mang rule.mitre.id dang T-ID, rag.py/test cung ky vong T-ID.
    ext_id = {}
    if "reference" in tbls:
        for sid, eid in con.execute(
                "SELECT id, external_id FROM reference "
                "WHERE source='mitre-attack' AND external_id LIKE 'T%'"):
            ext_id.setdefault(sid, eid)

    tc = cols(con, "technique")
    idc = first_present(["id"], tc) or tc[0]
    namec = first_present(["name"], tc)
    descc = first_present(["description"], tc)
    detc = first_present(["mitre_detection", "detection"], tc)
    subc = first_present(["subtechnique_of"], tc)

    out = []
    skipped = {"revoked": 0, "deprecated": 0, "no_external_id": 0}
    for r in con.execute("SELECT * FROM technique"):
        d = dict(zip(tc, r))
        tid = d.get(idc)
        if d.get("revoked_by"):
            skipped["revoked"] += 1
            continue
        if d.get("deprecated") in (1, "1", True):
            skipped["deprecated"] += 1
            continue
        if tid not in ext_id:
            skipped["no_external_id"] += 1
            continue
        parent = d.get(subc) if subc else ""
        rec = {
            "id": ext_id[tid],
            "name": d.get(namec) if namec else "",
            "description": (d.get(descc) or "").strip() if descc else "",
            "tactics": tech_tactics.get(tid, []),
            "detection": (d.get(detc) or "").strip() if detc else "",
            "mitigations": tech_mit.get(tid, []),
            "subtechnique_of": ext_id.get(parent, parent or ""),
        }
        parts = [f"{rec['id']} {rec['name']}"]
        if rec["tactics"]:
            parts.append("Tactic: " + ", ".join(rec["tactics"]))
        if rec["description"]:
            parts.append(rec["description"])
        if rec["mitigations"]:
            parts.append("Mitigations: " + ", ".join(rec["mitigations"]))
        rec["text"] = ". ".join(parts)
        out.append(rec)

    withdesc = sum(1 for r in out if r["description"])
    withtac = sum(1 for r in out if r["tactics"])
    print(f"[OK] {len(out)} technique ({withdesc} co description, "
          f"{withtac} co tactic); bo qua {skipped}", file=sys.stderr)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db", help="Path toi mitre.db")
    ap.add_argument("-o", "--output", default="mitre_techniques.json")
    ap.add_argument("--schema", action="store_true", help="Chi in schema roi thoat")
    args = ap.parse_args()

    if args.schema:
        con = sqlite3.connect(args.db)
        dump_schema(con)
        return

    out = build(args.db)
    out.sort(key=lambda rec: rec["id"])
    Path(args.output).write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    print(f"[OK] Ghi {len(out)} technique -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()