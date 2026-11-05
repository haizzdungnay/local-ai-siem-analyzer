import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research" / "training"))

import build_sft_jsonl as sft  # noqa: E402
import train_qlora  # noqa: E402

TARGET = {
    "summary": "Chuỗi sudo su từ tài khoản dịch vụ.", "severity": "medium",
    "key_findings": ["5402 x3 trên agent lab"], "mitre": ["T1548.003"],
    "next_steps": ["Xác minh tài khoản chạy sudo và phiên đăng nhập trước đó"],
    "response_language": "vi", "confidence": 70,
    "assessment_basis": {"observed_facts": ["5402 x3"], "inferences": ["có thể là quản trị"],
                         "uncertainties": ["chưa rõ phiên gốc"], "limitations": ["chỉ một cửa sổ"]},
}


def sample(i, group, **over):
    row = {"sample_id": f"s{i}", "split_group_id": group, "window_text": f"Rule 5402 x{i}",
           "language": "vi", "target": dict(TARGET), "target_origin": "distilled",
           "review_status": "reviewed", "reviewed_by": ["Nguyen"], "source": {"sha256": f"h{i}"}}
    row.update(over)
    return row


def test_build_messages_match_production_window_prompt():
    msgs = sft.build_messages("Rule 5402 x1", TARGET, "vi")
    assert [m["role"] for m in msgs] == ["system", "user", "assistant"]
    assert msgs[0]["content"] == sft.llm.build_effective_system_prompt("window", "vi")
    assert msgs[1]["content"].startswith(sft.llm._untrusted_message("WINDOW_DATA", "Rule 5402 x1"))
    assert json.loads(msgs[2]["content"]) == TARGET


def test_validate_rejects_unreviewed_locked_and_bad_schema():
    forbidden = {"locked"}
    assert sft.validate(sample(1, "g1"), forbidden) is None
    assert "review" in sft.validate(sample(2, "g1", review_status="draft"), forbidden)
    assert "test" in sft.validate(sample(3, "g1", source={"sha256": "locked"}), forbidden)
    bad = dict(TARGET)
    bad.pop("next_steps")
    assert "SCHEMA" in sft.validate(sample(4, "g1", target=bad), forbidden)


def test_split_never_puts_one_group_in_both_sets(tmp_path, monkeypatch):
    rows = [sample(i, f"g{i % 5}") for i in range(20)]
    src = tmp_path / "cand.jsonl"
    src.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["x", "--input", str(src), "--out-dir", str(tmp_path / "out"),
                                      "--val-ratio", "0.2"])
    sft.main()
    groups = {}
    for split in ("train", "val"):
        for line in (tmp_path / "out" / f"{split}.jsonl").read_text(encoding="utf-8").splitlines():
            groups.setdefault(json.loads(line)["split_group_id"], set()).add(split)
    assert all(len(v) == 1 for v in groups.values())
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["train"] + manifest["counts"]["val"] == 20


class FakeTokenizer:
    """Template giả: mỗi message -> [role_id, *content_chars]; generation prompt -> [99]."""
    ROLE = {"system": 1, "user": 2, "assistant": 3}

    def __init__(self):
        self.kwargs = []

    def apply_chat_template(self, messages, tokenize=True, add_generation_prompt=False, **kw):
        self.kwargs.append(kw)
        ids = []
        for m in messages:
            ids += [self.ROLE[m["role"]]] + [ord(c) % 50 + 100 for c in m["content"]]
        if add_generation_prompt:
            ids += [3]
        return ids


def test_tokenize_masks_prompt_and_drops_too_long():
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "u"},
            {"role": "assistant", "content": "ok"}]
    enc = train_qlora.tokenize_example(msgs, FakeTokenizer(), max_len=100)
    n_prompt = len(FakeTokenizer().apply_chat_template(msgs[:-1], add_generation_prompt=True))
    assert enc["labels"][:n_prompt] == [-100] * n_prompt
    assert enc["labels"][n_prompt:] == enc["input_ids"][n_prompt:] and len(enc["labels"][n_prompt:]) == 2
    assert train_qlora.tokenize_example(msgs, FakeTokenizer(), max_len=5) is None


def test_configs_parse():
    import yaml
    for name in ("qwen2.5-3b-qlora.yaml", "qwen2.5-7b-qlora.yaml"):
        cfg = yaml.safe_load((ROOT / "research" / "training" / "configs" / name).read_text(encoding="utf-8"))
        assert cfg["base_model"].startswith("Qwen/Qwen2.5-") and cfg["lora"]["r"] == 16


def test_tokenize_passes_template_kwargs():
    tok = FakeTokenizer()
    msgs = [{"role": "user", "content": "u"}, {"role": "assistant", "content": "ok"}]
    train_qlora.tokenize_example(msgs, tok, max_len=100, template_kwargs={"enable_thinking": False})
    assert tok.kwargs == [{"enable_thinking": False}] * 2


def test_pentest_config_is_marked_extension():
    import yaml
    path = ROOT / "research" / "training" / "configs" / "qwen35-9b-pentest-qlora.yaml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert cfg["chat_template_kwargs"] == {"enable_thinking": False}
    assert cfg["init_adapter"] == {"repo": "HRB25/qwen35-9b-pentest-v5", "subfolder": "adapter",
                                   "revision": "b888232"}
    assert "external comparator" in path.read_text(encoding="utf-8")
