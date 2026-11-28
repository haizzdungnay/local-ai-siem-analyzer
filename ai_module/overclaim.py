"""Kiểm tra code-only: LLM khẳng định leo thang đặc quyền đã xác nhận trong khi nhánh playbook chưa xác minh.

Chỉ sinh cảnh báo (provenance); không sửa summary/severity. Heuristic từ khóa Việt + Anh,
có thể bỏ sót cách diễn đạt khác (ví dụ "kiểm soát máy").
"""
import re
import unicodedata

# su lên root thành công (5303/5304): bằng chứng thành công; 5402/5715 có thể là actor khác nên không tính.
SUCCESS_EVIDENCE_RULE_IDS = frozenset({"5303", "5304"})
MAX_CLAUSE_CHARS = 200

_FLAGS = re.IGNORECASE
_SPLIT = re.compile(r"[.;,\n!?]|\b(?:nhưng|tuy nhiên|but|however)\b", _FLAGS)
_TOPIC = re.compile(r"leo thang|nâng quyền|quyền root|lên root|privilege escalation|\broot\b", _FLAGS)
_ASSERT = re.compile(
    r"đã xác nhận|xác nhận|thành công|đã giành|đã chiếm|confirmed|successful(?:ly)?|succeeded", _FLAGS)
_HEDGE = re.compile(
    r"\bnghi\b|nghi ngờ|có thể|dấu hiệu|\bthử\b|cố gắng|cần xác minh|chưa xác minh|"
    r"possible|possibly|attempt(?:ed|s)?|suspected|potential", _FLAGS)
_NEG = re.compile(r"^(?:không|chưa|not|no|never|un)$", _FLAGS)
_FAILURE = re.compile(
    r"không\s+thành\s+công|thất bại|failed|unsuccessful|authentication failure", _FLAGS)
_ABSENCE = re.compile(
    r"không phát hiện|chưa phát hiện|không thấy|chưa thấy|không ghi nhận|chưa ghi nhận|"
    r"không có bằng chứng|chưa có bằng chứng|không có dấu vết|no evidence|not observed|"
    r"not detected|no sign", _FLAGS)
_WORD = re.compile(r"\w+")


def _negated(clause: str, match: re.Match) -> bool:
    """Phủ định chỉ tính khi nằm trong 2 từ ngay trước cụm ASSERT."""
    previous = _WORD.findall(clause[:match.start()])[-2:]
    return any(_NEG.match(token) for token in previous)


def _clause_texts(text: str):
    text = unicodedata.normalize("NFC", text)
    return [part.strip() for part in _SPLIT.split(text) if part and part.strip()]


def find_overclaims(text: str) -> dict:
    overclaims, failures = [], []
    if not isinstance(text, str):
        return {"overclaims": overclaims, "failure_mentions": failures}
    for clause in _clause_texts(text):
        if not _TOPIC.search(clause):
            continue
        if _FAILURE.search(clause):
            failures.append(clause[:MAX_CLAUSE_CHARS])
            continue
        asserts = list(_ASSERT.finditer(clause))
        if not asserts or _HEDGE.search(clause):
            continue
        # Cụm "không có bằng chứng..." trước ASSERT: phủ định tầm xa, không phải khẳng định.
        if _ABSENCE.search(clause[:asserts[0].start()]):
            continue
        if any(_negated(clause, m) for m in asserts):
            continue
        overclaims.append(clause[:MAX_CLAUSE_CHARS])
    return {"overclaims": overclaims, "failure_mentions": failures}


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)


def analysis_texts(result: dict):
    for key in ("summary", "key_findings", "assessment_basis"):
        yield from _strings(result.get(key))


def overclaim_check(result: dict, findings: list, aggregate: dict) -> dict:
    """Trả provenance["overclaim_check"]; status: not_applicable | skipped_success_evidence | clean | flagged."""
    out = {"status": "not_applicable", "overclaims": [], "failure_mentions": []}
    findings = findings or []
    if (not any(f.get("branch_id") != "B_unknown" for f in findings)
            or any(f.get("branch_verified") is True for f in findings)):
        return out
    if any(str(g.get("rule_id")) in SUCCESS_EVIDENCE_RULE_IDS for g in aggregate.get("groups", [])):
        out["status"] = "skipped_success_evidence"
        return out
    for text in analysis_texts(result):
        found = find_overclaims(text)
        out["overclaims"].extend(found["overclaims"])
        out["failure_mentions"].extend(found["failure_mentions"])
    out["status"] = "flagged" if out["overclaims"] else "clean"
    return out
