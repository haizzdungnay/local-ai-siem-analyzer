"""Test cho script build KB: build_mitre_kb.py (mitre.db) va build_playbook_kb.py (Elastic)."""
import json
import sqlite3
import textwrap

import build_mitre_kb
import build_playbook_kb


def _mitre_db(path):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE technique (id TEXT, name TEXT, description TEXT, mitre_detection TEXT,
                                revoked_by TEXT, deprecated INTEGER, subtechnique_of TEXT);
        CREATE TABLE tactic (id TEXT, name TEXT, short_name TEXT);
        CREATE TABLE phase (tactic_id TEXT, tech_id TEXT);
        CREATE TABLE mitigation (id TEXT, name TEXT);
        CREATE TABLE mitigate (id TEXT, source_id TEXT, target_id TEXT, description TEXT);
        CREATE TABLE reference (id TEXT, source TEXT, external_id TEXT);
    """)
    con.executemany("INSERT INTO technique VALUES (?,?,?,?,?,?,?)", [
        ("ap--bf", "Brute Force", "Guess passwords. (Citation: X)", "Watch auth logs.", None, 0, None),
        ("ap--pg", "Password Guessing", "Guess one.", "", None, 0, "ap--bf"),
        ("ap--old", "Old Technique", "Revoked.", "", "ap--bf", 0, None),
        ("ap--dep", "Deprecated Technique", "Deprecated.", "", None, 1, None),
    ])
    con.execute("INSERT INTO tactic VALUES ('ta--ca', 'Credential Access', 'credential-access')")
    con.executemany("INSERT INTO phase VALUES (?,?)", [("ta--ca", "ap--bf"), ("ta--ca", "ap--pg")])
    con.execute("INSERT INTO mitigation VALUES ('coa--m1036', 'Account Use Policies')")
    con.execute("INSERT INTO mitigate VALUES ('rel', 'coa--m1036', 'ap--bf', "
                "'Set account lockout. (Citation: NIST)')")
    con.executemany("INSERT INTO reference VALUES (?,?,?)", [
        ("ap--bf", "mitre-attack", "T1110"),
        ("ap--pg", "mitre-attack", "T1110.001"),
        ("ap--old", "mitre-attack", "T1999"),
        ("ap--dep", "mitre-attack", "T1998"),
        ("coa--m1036", "mitre-attack", "M1036"),
        ("ap--bf", "capec", "CAPEC-49"),
    ])
    con.commit()
    con.close()


def test_mitre_kb_uses_attack_ids_and_skips_revoked(tmp_path, capsys):
    db = tmp_path / "mitre.db"
    _mitre_db(db)
    out = {rec["id"]: rec for rec in build_mitre_kb.build(str(db))}
    capsys.readouterr()

    assert set(out) == {"T1110", "T1110.001"}
    brute = out["T1110"]
    assert brute["tactics"] == ["Credential Access"]
    assert brute["description"] == "Guess passwords."
    assert brute["mitigations"] == ["Account Use Policies"]
    assert brute["mitigation_details"] == [
        {"id": "M1036", "name": "Account Use Policies", "guidance": "Set account lockout."}
    ]
    assert out["T1110.001"]["subtechnique_of"] == "T1110"


def test_mitre_kb_cli_writes_utf8_lf_sorted(tmp_path, monkeypatch):
    db = tmp_path / "mitre.db"
    _mitre_db(db)
    output = tmp_path / "mitre_techniques.json"
    monkeypatch.setattr("sys.argv", ["build_mitre_kb.py", str(db), "-o", str(output)])
    build_mitre_kb.main()

    raw = output.read_bytes()
    assert b"\r\n" not in raw
    assert [rec["id"] for rec in json.loads(raw.decode("utf-8"))] == ["T1110", "T1110.001"]


NOTE = textwrap.dedent("""\
    ## Triage and analysis

    ### Investigating SSH brute force

    Intro paragraph that is not a step.

    #### Possible investigation steps

    - Investigate the source IP address of the failed [ssh](https://example.test) attempts.
    - Review other alerts for the host:
      - same user
      - same source IP
    - Use Timeline to pivot on the process.
    - !{osquery{"label":"x"}}

    ### False positive analysis

    - Service account password expired.

    ### Response and remediation

    1. Terminate active sessions.
    2. Reset passwords for affected
       accounts.
    """)


def test_parse_note_sections_nested_and_tooling():
    sections, dropped = build_playbook_kb.parse_note(NOTE)

    assert sections["investigation"] == [
        "Investigate the source IP address of the failed ssh attempts.",
        "Review other alerts for the host:; same user; same source IP",
    ]
    assert sections["false_positives"] == ["Service account password expired."]
    assert sections["response"] == [
        "Terminate active sessions.",
        "Reset passwords for affected accounts.",
    ]
    assert dropped == 2


def test_parse_note_keeps_generic_timeline_wording():
    sections, dropped = build_playbook_kb.parse_note(
        "### Possible investigation steps\n- Check the timeline of events around the alert.\n"
    )
    assert sections["investigation"] == ["Check the timeline of events around the alert."]
    assert dropped == 0


def _rule(path, maturity="production", note=NOTE, threat=True):
    threat_block = textwrap.dedent("""\
        [[rule.threat]]
        framework = "MITRE ATT&CK"
        [[rule.threat.technique]]
        id = "T1110"
        name = "Brute Force"
        [[rule.threat.technique.subtechnique]]
        id = "T1110.001"
        name = "Password Guessing"
        [rule.threat.tactic]
        id = "TA0006"
        name = "Credential Access"
        """) if threat else ""
    path.write_text(
        f'[metadata]\nmaturity = "{maturity}"\n\n[rule]\n'
        f'rule_id = "{path.stem}"\nname = "Rule {path.stem}"\n'
        f'description = "Detects brute force."\nnote = """{note}"""\n\n{threat_block}',
        encoding="utf-8",
    )


def test_build_playbooks_filters_and_maps_techniques(tmp_path):
    rules = tmp_path / "rules" / "linux"
    rules.mkdir(parents=True)
    _rule(rules / "a.toml")
    _rule(rules / "b.toml", maturity="development")
    _rule(rules / "c.toml", threat=False)
    _rule(rules / "d.toml", note="")

    playbooks, stats = build_playbook_kb.build(tmp_path, ["linux"])

    assert [pb["id"] for pb in playbooks] == ["a"]
    assert playbooks[0]["techniques"] == ["T1110", "T1110.001"]
    assert playbooks[0]["tactics"] == ["Credential Access"]
    assert playbooks[0]["source_path"] == "rules/linux/a.toml"
    assert stats["not_production"] == 1
    assert stats["no_technique"] == 1
    assert stats["no_note"] == 1
