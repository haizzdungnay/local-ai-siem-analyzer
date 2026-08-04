"""Reusable alert/window analysis shared by CLI, eval, worker and web API."""
import hashlib
import json
from collections import Counter

from extractor import _get_nested, extract_fields, format_for_llm
from reader import resolve_config_paths
from llm import analyze_alert, analyze_window
from rag import RuleRAG


ANALYSIS_VERSION = "dashboard-v3"
MAX_ECHO_REDACTION_LOGS = 64
MAX_ECHO_REDACTION_CHARS = 1000
MIN_ECHO_REDACTION_CHARS = 16


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _list_text(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)] if value not in (None, "") else []


def _group_key(source: dict) -> str:
    parts = [
        _text(str(_get_nested(source, "rule.id") or "unknown")),
        _text(str(_get_nested(source, "agent.id") or _get_nested(source, "agent.name") or "unknown")),
        _text(str(_get_nested(source, "data.srcip") or "")),
        _text(str(_get_nested(source, "syscheck.path") or "")),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def aggregate_alerts(hits: list[dict], *, sample_log_chars: int = 1000) -> dict:
    """Group full Indexer hits deterministically without asking the LLM to count."""
    if isinstance(sample_log_chars, bool) or not isinstance(sample_log_chars, int) or sample_log_chars < 1:
        raise ValueError("sample_log_chars phải là số nguyên dương")

    groups: dict[str, dict] = {}
    rule_counts: Counter[str] = Counter()
    agents, source_ips = set(), set()
    alert_rows = []
    for position, hit in enumerate(hits):
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            raise ValueError(f"hits[{position}] phải có _source object")
        source = hit["_source"]
        rule_id = str(_get_nested(source, "rule.id") or "unknown")
        rule_level_value = _get_nested(source, "rule.level")
        rule_level = rule_level_value if isinstance(rule_level_value, (int, float)) else 0
        agent = str(_get_nested(source, "agent.name") or _get_nested(source, "agent.id") or "")
        source_ip = str(_get_nested(source, "data.srcip") or "")
        timestamp = str(source.get("timestamp") or "")
        group_key = _group_key(source)
        rule_counts[rule_id] += 1
        if agent:
            agents.add(agent)
        if source_ip:
            source_ips.add(source_ip)

        group = groups.get(group_key)
        if group is None:
            group = groups[group_key] = {
                "group_key": group_key,
                "count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "max_level": rule_level,
                "rule_id": rule_id,
                "description": str(_get_nested(source, "rule.description") or ""),
                "mitre": _list_text(_get_nested(source, "rule.mitre.id")),
                "agent": agent,
                "source_ip": source_ip,
                "syscheck_path": str(_get_nested(source, "syscheck.path") or ""),
                "sample_log": str(source.get("full_log") or "")[:sample_log_chars],
            }
        group["count"] += 1
        group["first_seen"] = min(filter(None, [group["first_seen"], timestamp]), default="")
        group["last_seen"] = max(group["last_seen"], timestamp)
        group["max_level"] = max(group["max_level"], rule_level)
        alert_rows.append({
            "_index": hit.get("_index", ""),
            "_id": hit.get("_id", ""),
            "timestamp": timestamp,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "description": str(_get_nested(source, "rule.description") or ""),
            "agent": agent,
            "source_ip": source_ip,
            "group_key": group_key,
        })

    ordered_groups = sorted(
        groups.values(),
        key=lambda group: (-group["max_level"], -group["count"], group["last_seen"], group["group_key"]),
    )
    return {
        "total_alerts": len(hits),
        "total_groups": len(ordered_groups),
        "unique_rules": len(rule_counts),
        "unique_agents": len(agents),
        "unique_source_ips": len(source_ips),
        "rule_counts": dict(sorted(rule_counts.items())),
        "groups": ordered_groups,
        "alerts": alert_rows,
        "timeline": [],
        "analysis_mode": "full",
        "source_truncated": False,
    }


def aggregate_rule_buckets(fetched: dict) -> dict:
    """Normalize Indexer rule buckets into the aggregate contract without raw logs."""
    groups = []
    for position, bucket in enumerate(fetched.get("rule_buckets", [])):
        if not isinstance(bucket, dict):
            raise ValueError(f"rule_buckets[{position}] phải là object")
        sample = bucket.get("sample") if isinstance(bucket.get("sample"), dict) else {}
        rule_id = str(bucket.get("rule_id") or "unknown")
        group_key = hashlib.sha256(f"aggregate\x1f{rule_id}".encode("utf-8")).hexdigest()[:24]
        groups.append({
            "group_key": group_key,
            "count": int(bucket.get("count", 0)),
            "first_seen": str(bucket.get("first_seen") or ""),
            "last_seen": str(bucket.get("last_seen") or ""),
            "max_level": bucket.get("max_level", 0),
            "rule_id": rule_id,
            "description": str(_get_nested(sample, "rule.description") or ""),
            "mitre": _list_text(_get_nested(sample, "rule.mitre.id")),
            "agent": str(_get_nested(sample, "agent.name") or _get_nested(sample, "agent.id") or ""),
            "source_ip": str(_get_nested(sample, "data.srcip") or ""),
            "syscheck_path": str(_get_nested(sample, "syscheck.path") or ""),
            "sample_log": "",
        })
    groups.sort(key=lambda group: (-group["max_level"], -group["count"], group["rule_id"]))
    return {
        "total_alerts": int(fetched.get("total", 0)),
        "total_groups": int(fetched.get("unique_rules", len(groups))),
        "unique_rules": int(fetched.get("unique_rules", len(groups))),
        "unique_agents": int(fetched.get("unique_agents", 0)),
        "unique_source_ips": int(fetched.get("unique_source_ips", 0)),
        "rule_counts": {group["rule_id"]: group["count"] for group in groups},
        "groups": groups,
        "alerts": [],
        "timeline": list(fetched.get("timeline", [])),
        "analysis_mode": "aggregate",
        "source_truncated": bool(fetched.get("rules_truncated")),
    }


def format_window_for_llm(
    aggregate: dict,
    *,
    max_groups: int = 20,
    max_chars: int = 24000,
) -> tuple[str, dict]:
    """Build a bounded, auditable prompt and return explicit coverage metadata."""
    if not 1 <= max_groups <= 100:
        raise ValueError("max_groups phải nằm trong khoảng 1..100")
    if max_chars < 1000:
        raise ValueError("max_chars phải từ 1000 trở lên")
    groups = aggregate["groups"]
    lines = [
        f"Analysis mode: {aggregate.get('analysis_mode', 'full')}",
        f"Total alerts: {aggregate['total_alerts']}",
        f"Total groups: {aggregate['total_groups']}",
        f"Unique rules: {aggregate['unique_rules']}",
        f"Unique agents: {aggregate['unique_agents']}",
        f"Unique source IPs: {aggregate['unique_source_ips']}",
    ]
    included = 0
    represented = 0
    current_chars = sum(map(len, lines)) + len(lines) - 1
    for group in groups[:max_groups]:
        block = (
            f"\nGroup {included + 1}: rule={group['rule_id']}; level={group['max_level']}; "
            f"count={group['count']}; first={group['first_seen']}; last={group['last_seen']}; "
            f"agent={group['agent']}; srcip={group['source_ip']}; path={group['syscheck_path']}; "
            f"description={group['description']}; mitre={','.join(group['mitre'])}; "
            f"sample_log={group['sample_log'] or '[not loaded in aggregate mode]'}"
        )
        if current_chars + 1 + len(block) > max_chars:
            break
        lines.append(block)
        current_chars += 1 + len(block)
        included += 1
        represented += group["count"]
    coverage = {
        "included_groups": included,
        "total_groups": aggregate["total_groups"],
        "represented_alerts": represented,
        "total_alerts": aggregate["total_alerts"],
        "truncated": included < aggregate["total_groups"] or bool(aggregate.get("source_truncated")),
    }
    lines.append(f"\nCoverage: {json.dumps(coverage, ensure_ascii=False)}")
    return "\n".join(lines), coverage


def _sample_log_redactors(aggregate: dict) -> list[str]:
    """Collect bounded exact strings that must not be echoed into saved results."""
    samples = set()
    for group in aggregate.get("groups", [])[:MAX_ECHO_REDACTION_LOGS]:
        if not isinstance(group, dict):
            continue
        sample = group.get("sample_log")
        if isinstance(sample, str) and MIN_ECHO_REDACTION_CHARS <= len(sample) <= MAX_ECHO_REDACTION_CHARS:
            samples.add(sample)
    return sorted(samples, key=len, reverse=True)


def _redact_exact_sample_log_echoes(value, samples: list[str]) -> tuple[object, int]:
    """Redact only complete known sample-log substrings, never broad heuristics."""
    if isinstance(value, dict):
        output, count = {}, 0
        for key, item in value.items():
            output[key], item_count = _redact_exact_sample_log_echoes(item, samples)
            count += item_count
        return output, count
    if isinstance(value, list):
        output, count = [], 0
        for item in value:
            redacted, item_count = _redact_exact_sample_log_echoes(item, samples)
            output.append(redacted)
            count += item_count
        return output, count
    if not isinstance(value, str):
        return value, 0
    count = 0
    for sample in samples:
        occurrences = value.count(sample)
        if occurrences:
            value = value.replace(sample, "[REDACTED_ECHOED_SAMPLE_LOG]")
            count += occurrences
    return value, count


class AnalysisService:
    """Own one process-lifetime RAG instance and expose reusable analysis methods."""

    def __init__(self, cfg: dict):
        self.cfg = resolve_config_paths(cfg)
        self.timeout = self.cfg["ollama"].get("timeout", 120)
        self.rag = None

    def _ensure_rag(self):
        if self.rag is not None or not self.cfg.get("rag", {}).get("enabled"):
            return self.rag
        self.rag = RuleRAG(
            data_dir=self.cfg["rag"]["data_dir"],
            embedding_model=self.cfg["rag"]["embedding_model"],
            base_url=self.cfg["ollama"]["base_url"],
            timeout=self.timeout,
        )
        self.rag.ensure_indexed()
        return self.rag

    def analyze_one(self, alert: dict, model: str, language: str = "vi") -> dict:
        extracted = extract_fields(alert, self.cfg["extractor"]["fields"])
        rag_context = ""
        rag_results = []
        rag = self._ensure_rag()
        if rag:
            rag_results = rag.query(
                str(extracted.get("rule.id", "")),
                str(extracted.get("rule.description", "")),
            )
            rag_context = rag.format_context(rag_results)
        result, provenance = analyze_alert(
            alert_text=format_for_llm(extracted),
            rag_context=rag_context,
            model=model,
            base_url=self.cfg["ollama"]["base_url"],
            timeout=self.timeout,
            language=language,
            include_provenance=True,
            allow_remote=self.cfg["ollama"].get("allow_remote", False),
        )
        return {
            "analysis": result,
            "extracted": extracted,
            "rag_results": rag_results,
            "analysis_version": ANALYSIS_VERSION,
            "provenance": provenance,
        }

    def analyze_aggregate(self, aggregate: dict, model: str, language: str = "vi") -> dict:
        dashboard_cfg = self.cfg.get("dashboard", {})
        prompt, coverage = format_window_for_llm(
            aggregate,
            max_groups=dashboard_cfg.get("max_groups_in_prompt", 20),
            max_chars=dashboard_cfg.get("max_window_prompt_chars", 24000),
        )
        result, provenance = analyze_window(
            prompt,
            model=model,
            base_url=self.cfg["ollama"]["base_url"],
            timeout=self.timeout,
            language=language,
            include_provenance=True,
            allow_remote=self.cfg["ollama"].get("allow_remote", False),
        )
        result, echo_redaction_count = _redact_exact_sample_log_echoes(
            result, _sample_log_redactors(aggregate),
        )
        provenance = dict(provenance)
        provenance["redacted_exact_sample_log_echoes"] = echo_redaction_count
        warning = result["severity"] == "unknown" or echo_redaction_count > 0
        return {
            "analysis": result,
            "coverage": coverage,
            "partial": warning or coverage["truncated"],
            "analysis_version": ANALYSIS_VERSION,
            "provenance": provenance,
        }
