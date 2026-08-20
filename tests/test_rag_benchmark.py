import os, sys, json, pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(ROOT, "eval")
sys.path.insert(0, os.path.join(ROOT, "ai_module"))

def test_full_knowledge_base_integrity():
    kb_path = os.path.join(ROOT, "ai_module", "rag_data_full")
    wazuh_rules_file = os.path.join(kb_path, "wazuh_rules.json")
    mitre_tech_file = os.path.join(kb_path, "mitre_techniques.json")
    
    assert os.path.exists(wazuh_rules_file)
    assert os.path.exists(mitre_tech_file)
    
    with open(wazuh_rules_file, encoding="utf-8") as f:
        rules = json.load(f)
    with open(mitre_tech_file, encoding="utf-8") as f:
        techs = json.load(f)
        
    assert len(rules) >= 20
    assert len(techs) >= 25
    assert all("id" in r and "description" in r for r in rules)
    assert all("id" in t and "name" in t and "tactic" in t for t in techs)

def test_rag_benchmark_script_runs():
    import subprocess
    env = os.environ.copy()
    env["NO_PROXY"] = "localhost,127.0.0.1"
    env["HTTP_PROXY"] = ""
    env["HTTPS_PROXY"] = ""
    res = subprocess.run([sys.executable, os.path.join(EVAL_DIR, "rag_benchmark.py")], capture_output=True, text=True, env=env)
    assert res.returncode == 0
    assert "Hit Rate@k" in res.stdout
    assert "Recall@k" in res.stdout
    assert "MRR" in res.stdout