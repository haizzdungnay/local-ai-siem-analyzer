import os, sys, json, pytest, urllib.request, urllib.error

# Models used by the tests in this file.
_REQUIRED_MODELS = {"qwen2.5:7b", "CyberCrew/notmythos-8b"}


def _ollama_reachable() -> bool:
    """Return True when the local Ollama API responds within 2 s."""
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2):
            return True
    except (urllib.error.URLError, OSError):
        return False


def _ollama_has_models(needed: set[str]) -> tuple[bool, set[str]]:
    """Check whether *needed* models are pulled.  Returns (ok, missing)."""
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        installed = {m.get("name", m.get("model", "")) for m in body.get("models", [])}
        missing = needed - installed
        return len(missing) == 0, missing
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        return False, needed


def test_model_provenance_and_parameters():
    if not _ollama_reachable():
        pytest.skip("Ollama not running on localhost:11434 (timeout 2 s)")
    ok, missing = _ollama_has_models(_REQUIRED_MODELS)
    if not ok:
        pytest.skip(f"Ollama running but required model(s) not pulled: {missing}")

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