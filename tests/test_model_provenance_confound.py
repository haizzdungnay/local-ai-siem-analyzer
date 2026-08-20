import os, sys, json, pytest, urllib.request

def test_model_provenance_and_parameters():
    url = "http://127.0.0.1:11434/api/show"
    
    # 1. Verify qwen2.5:7b specs
    req = urllib.request.Request(url, data=json.dumps({"model": "qwen2.5:7b"}).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        details = data.get("details", {})
        assert details.get("family") == "qwen2"
        assert details.get("quantization_level") == "Q4_K_M"
        assert "7.6B" in details.get("parameter_size", "") or "7B" in details.get("parameter_size", "")

    # 2. Verify notmythos-8b true specs
    req = urllib.request.Request(url, data=json.dumps({"model": "CyberCrew/notmythos-8b"}).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        details = data.get("details", {})
        assert details.get("family") == "llama"
        assert details.get("quantization_level") == "Q4_K_M"
        # Confirm that despite the tag -8b, the true parameter size is 3.2B
        assert "3.2B" in details.get("parameter_size", "") or "3B" in details.get("parameter_size", "")

def test_dinhchinh_document_exists():
    doc_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "SoLieuC4_DinhChinh.md")
    assert os.path.exists(doc_path)
    with open(doc_path, encoding="utf-8") as f:
        content = f.read()
    assert "L??ng t? h?a (Quantization)" in content
    assert "Y?U T? G?Y NHI?U (CONFOUNDING FACTORS)" in content
    assert "3.2B" in content
    assert "7.6B" in content