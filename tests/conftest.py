"""Test bootstrap for the standalone modules in ai_module/."""
import importlib.util
import sys
import types
from pathlib import Path


AI_MODULE = Path(__file__).resolve().parents[1] / "ai_module"
sys.path.insert(0, str(AI_MODULE))


def _stub_missing_dependency(name: str) -> None:
    if importlib.util.find_spec(name) is not None:
        return

    module = types.ModuleType(name)
    module.Client = None
    if name == "chromadb":
        module.PersistentClient = None
    sys.modules[name] = module


_stub_missing_dependency("ollama")
_stub_missing_dependency("chromadb")
