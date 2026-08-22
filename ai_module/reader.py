"""reader.py — Đọc alert từ Wazuh Indexer/OpenSearch hoặc alert mẫu."""
import ipaddress
import json
import math
import re
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests
import yaml

from dashboard_time import format_utc, parse_utc


MODULE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = MODULE_DIR.parent / "eval" / "samples"
ALERT_INDEX_PATTERN = "wazuh-alerts-*"
_ALERT_INDEX_RE = re.compile(r"^wazuh-alerts-[A-Za-z0-9._-]+$")
_TIMELINE_INTERVALS = (1, 5, 10, 30, 60, 300, 900, 1800, 3600, 21600, 43200, 86400, 259200, 604800, 2592000)
CARDINALITY_PRECISION_THRESHOLD = 40000
_AGGREGATE_SOURCE_FIELDS = [
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.mitre.id",
    "agent.id",
    "agent.name",
    "data.srcip",
    "syscheck.path",
]


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_ollama_base_url(base_url: str, *, allow_remote: bool = False) -> None:
    """Validate an Ollama URL before any HTTP client is constructed."""
    if not isinstance(allow_remote, bool):
        raise ValueError("allow_remote must be a boolean")
    if not isinstance(base_url, str) or not base_url.strip() or base_url != base_url.strip():
        raise ValueError("ollama.base_url must be a non-empty URL")
    try:
        parsed = urlsplit(base_url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("ollama.base_url has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ollama.base_url must use http(s) with an explicit host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("ollama.base_url must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("ollama.base_url must not contain a query or fragment")
    if _is_loopback_host(parsed.hostname):
        return
    if not allow_remote:
        raise ValueError("ollama.base_url must use a loopback host unless ollama.allow_remote is true")
    if parsed.scheme != "https":
        raise ValueError("remote ollama.base_url must use https")


def _validate_ollama_config(ollama_cfg: dict) -> None:
    """Reject accidental non-local or credential-bearing Ollama endpoints."""
    allow_remote = ollama_cfg.get("allow_remote", False)
    if "base_url" not in ollama_cfg:
        if not isinstance(allow_remote, bool):
            raise ValueError("ollama.allow_remote must be a boolean")
        return
    validate_ollama_base_url(ollama_cfg["base_url"], allow_remote=allow_remote)


def _tls_verify_value(service_cfg: dict, section_name: str):
    """Return Requests' verification value with certificate verification as the default."""
    ca_bundle = service_cfg.get("ca_bundle")
    if ca_bundle is not None:
        if not isinstance(ca_bundle, str) or not ca_bundle.strip():
            raise ValueError(f"{section_name}.ca_bundle must be a non-empty path")
        return ca_bundle

    verify_ssl = service_cfg.get("verify_ssl", True)
    if not isinstance(verify_ssl, bool):
        raise ValueError(f"{section_name}.verify_ssl must be a boolean")
    return verify_ssl


def _validate_tls_config(cfg: dict) -> None:
    """Warn when a configuration deliberately disables TLS certificate checks."""
    for section_name in ("wazuh", "wazuh_indexer"):
        service_cfg = cfg.get(section_name)
        if service_cfg is None:
            continue
        if not isinstance(service_cfg, dict):
            raise ValueError(f"{section_name} config must be an object")
        verify_value = _tls_verify_value(service_cfg, section_name)
        if verify_value is False:
            warnings.warn(
                f"{section_name}.verify_ssl=false disables TLS certificate verification; "
                "use this only for an isolated lab with an explicit risk acceptance.",
                UserWarning,
                stacklevel=3,
            )


def load_config(path: str | Path = MODULE_DIR / "config.yaml") -> dict:
    """Load and minimally validate YAML config."""
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Config YAML phải là object")
    for section in ("ollama", "wazuh_indexer", "extractor"):
        if not isinstance(cfg.get(section), dict):
            raise ValueError(f"Thiếu hoặc sai config section: {section}")
    if not isinstance(cfg["extractor"].get("fields"), list):
        raise ValueError("extractor.fields phải là list")
    _validate_ollama_config(cfg["ollama"])
    _validate_tls_config(cfg)
    return cfg


def resolve_config_paths(cfg: dict) -> dict:
    """Resolve module-relative runtime paths once for CLI, eval and dashboard callers."""
    ollama_cfg = cfg.get("ollama")
    if isinstance(ollama_cfg, dict):
        _validate_ollama_config(ollama_cfg)
    rag_cfg = cfg.get("rag")
    if isinstance(rag_cfg, dict) and "data_dir" in rag_cfg:
        data_dir = Path(rag_cfg["data_dir"])
        rag_cfg["data_dir"] = str(data_dir if data_dir.is_absolute() else MODULE_DIR / data_dir)
    return cfg


def get_wazuh_token(cfg: dict) -> str:
    """Xác thực Wazuh Manager API, trả về JWT token. (Không dùng để lấy alert)"""
    wazuh_cfg = cfg["wazuh"]
    url = f"{wazuh_cfg['protocol']}://{wazuh_cfg['host']}:{wazuh_cfg['port']}/security/user/authenticate"
    r = requests.post(
        url,
        auth=(wazuh_cfg["user"], wazuh_cfg["password"]),
        verify=_tls_verify_value(wazuh_cfg, "wazuh"),
        timeout=wazuh_cfg.get("timeout", 30),
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def _indexer_base_url(cfg: dict) -> str:
    idx_cfg = cfg["wazuh_indexer"]
    protocol = idx_cfg.get("protocol", "https")
    return f"{protocol}://{idx_cfg['host']}:{idx_cfg['port']}"


def _request_kwargs(cfg: dict) -> dict:
    idx_cfg = cfg["wazuh_indexer"]
    return {
        "auth": (idx_cfg["user"], idx_cfg["password"]),
        "verify": _tls_verify_value(idx_cfg, "wazuh_indexer"),
        "timeout": idx_cfg.get("timeout", 30),
    }


def _parse_search_response(body, *, require_identity: bool) -> tuple[list[dict], int | None]:
    if not isinstance(body, dict):
        raise ValueError("Indexer trả JSON không phải object")
    hits_object = body.get("hits")
    if not isinstance(hits_object, dict):
        raise ValueError("Indexer response thiếu hits object")
    hits = hits_object.get("hits")
    if not isinstance(hits, list):
        raise ValueError("Indexer response thiếu hits.hits list")

    total_object = hits_object.get("total")
    total = None
    if total_object is not None:
        total = total_object.get("value") if isinstance(total_object, dict) else total_object
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ValueError("Indexer response có hits.total không hợp lệ")

    parsed = []
    for position, hit in enumerate(hits):
        if not isinstance(hit, dict):
            raise ValueError(f"Indexer hits.hits[{position}] phải là object")
        source = hit.get("_source")
        if not isinstance(source, dict):
            raise ValueError(f"Indexer hits.hits[{position}]._source phải là object")
        if require_identity:
            index_name = hit.get("_index")
            document_id = hit.get("_id")
            if not isinstance(index_name, str) or not _ALERT_INDEX_RE.fullmatch(index_name):
                raise ValueError(f"Indexer hits.hits[{position}]._index không hợp lệ")
            if not isinstance(document_id, str) or not document_id:
                raise ValueError(f"Indexer hits.hits[{position}]._id không hợp lệ")
            parsed.append({"_index": index_name, "_id": document_id, "_source": source})
        else:
            parsed.append(source)
    return parsed, total


def validate_time_range(
    start: str | datetime,
    end: str | datetime,
    *,
    max_span: timedelta = timedelta(days=30),
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Chuẩn hóa cửa sổ UTC nửa mở ``[start, end)`` và chặn range quá lớn."""
    start_utc = parse_utc(start, "start")
    end_utc = parse_utc(end, "end")
    now_utc = parse_utc(now or datetime.now(timezone.utc), "now")
    if start_utc >= end_utc:
        raise ValueError("start phải nhỏ hơn end")
    if end_utc > now_utc:
        raise ValueError("end không được nằm trong tương lai")
    if end_utc - start_utc > max_span:
        raise ValueError(f"Khoảng thời gian không được vượt quá {int(max_span.total_seconds())} giây")
    return start_utc, end_utc


def fetch_alerts_api(cfg: dict, limit: int = 10) -> list[dict]:
    """Lấy N alert mới nhất; giữ contract cũ là trả danh sách ``_source``."""
    if not 1 <= limit <= 50:
        raise ValueError("limit phải nằm trong khoảng 1..50")

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "track_total_hits": False,
    }
    url = f"{_indexer_base_url(cfg)}/{ALERT_INDEX_PATTERN}/_search"
    response = requests.post(url, json=query, **_request_kwargs(cfg))
    response.raise_for_status()
    alerts, _ = _parse_search_response(response.json(), require_identity=False)
    return alerts


def fetch_alerts_range(
    cfg: dict,
    start: str | datetime,
    end: str | datetime,
    *,
    max_alerts: int = 2000,
    max_span: timedelta = timedelta(days=30),
    now: datetime | None = None,
    source_ip: str | None = None,
    agent_ip: str | None = None,
    expected_rule_ids: list[str] | tuple[str, ...] | None = None,
) -> dict:
    """Đọc full alert documents trong cửa sổ UTC nửa mở ``[start, end)``.

    Một request có giới hạn được dùng ở MVP. Nếu số alert vượt ``max_alerts``, hàm
    fail rõ thay vì cắt dữ liệu âm thầm.
    """
    if isinstance(max_alerts, bool) or not isinstance(max_alerts, int) or not 1 <= max_alerts <= 9999:
        raise ValueError("max_alerts phải nằm trong khoảng 1..9999")
    start_utc, end_utc = validate_time_range(start, end, max_span=max_span, now=now)
    filters = _correlation_filters(
        source_ip=source_ip,
        agent_ip=agent_ip,
        expected_rule_ids=expected_rule_ids,
    )
    query = {
        "size": max_alerts + 1,
        "query": _window_query(format_utc(start_utc), format_utc(end_utc), filters),
        "sort": [{"timestamp": {"order": "asc"}}],
        "track_total_hits": False,
    }
    url = f"{_indexer_base_url(cfg)}/{ALERT_INDEX_PATTERN}/_search"
    response = requests.post(url, json=query, **_request_kwargs(cfg))
    response.raise_for_status()
    alerts, _ = _parse_search_response(response.json(), require_identity=True)
    if len(alerts) > max_alerts:
        raise ValueError(f"Cửa sổ có hơn {max_alerts} alert, vượt giới hạn")
    return {
        "start": format_utc(start_utc),
        "end": format_utc(end_utc),
        "total": len(alerts),
        "alerts": alerts,
    }


def _correlation_filters(
    *,
    source_ip: str | None,
    agent_ip: str | None,
    expected_rule_ids: list[str] | tuple[str, ...] | None = None,
) -> list[dict]:
    """Build the only optional server-side correlation filters for a window."""
    values = (("data.srcip", source_ip), ("agent.ip", agent_ip))
    filters = []
    for field, value in values:
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"{field} filter phai la IPv4 address")
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{field} filter phai la IPv4 address") from exc
        if parsed.version != 4:
            raise ValueError(f"{field} filter phai la IPv4 address")
        filters.append({"term": {field: str(parsed)}})
    if expected_rule_ids is not None:
        if (
            not isinstance(expected_rule_ids, (list, tuple))
            or not 1 <= len(expected_rule_ids) <= 16
        ):
            raise ValueError("expected_rule_ids filter is invalid")
        rules = []
        for value in expected_rule_ids:
            if not isinstance(value, str) or not re.fullmatch(r"\d{1,12}", value):
                raise ValueError("expected_rule_ids filter is invalid")
            if value not in rules:
                rules.append(value)
        filters.append({"terms": {"rule.id": rules}})
    return filters


def _window_query(start: str, end: str, filters: list[dict]) -> dict:
    clauses = [{"range": {"timestamp": {"gte": start, "lt": end}}}, *filters]
    return clauses[0] if len(clauses) == 1 else {"bool": {"filter": clauses}}


def _timeline_interval_seconds(start: datetime, end: datetime, max_buckets: int) -> int:
    target = max(1, math.ceil((end - start).total_seconds() / max_buckets))
    for interval in _TIMELINE_INTERVALS:
        if interval >= target:
            return interval
    return math.ceil(target / 86400) * 86400


def _exact_total(body: dict) -> int:
    hits = body.get("hits") if isinstance(body, dict) else None
    total = hits.get("total") if isinstance(hits, dict) else None
    if not isinstance(total, dict) or total.get("relation") != "eq":
        raise ValueError("Indexer không trả exact hits.total")
    value = total.get("value")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Indexer response có hits.total không hợp lệ")
    return value


def _aggregation_value(aggregations: dict, name: str) -> int:
    item = aggregations.get(name)
    value = item.get("value") if isinstance(item, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"Indexer aggregation {name} không hợp lệ")
    return int(value)


def _aggregation_time(item: dict) -> str:
    value = item.get("value") if isinstance(item, dict) else None
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Indexer min/max timestamp không hợp lệ")
    return format_utc(datetime.fromtimestamp(value / 1000, tz=timezone.utc))


def _parse_window_aggregations(
    body: dict,
    *,
    start: datetime,
    end: datetime,
    interval_seconds: int,
) -> dict:
    aggregations = body.get("aggregations") if isinstance(body, dict) else None
    if not isinstance(aggregations, dict):
        raise ValueError("Indexer response thiếu aggregations object")

    timeline_object = aggregations.get("timeline")
    timeline_buckets = timeline_object.get("buckets") if isinstance(timeline_object, dict) else None
    if not isinstance(timeline_buckets, list):
        raise ValueError("Indexer timeline buckets không hợp lệ")
    timeline = []
    for position, bucket in enumerate(timeline_buckets):
        key = bucket.get("key") if isinstance(bucket, dict) else None
        count = bucket.get("doc_count") if isinstance(bucket, dict) else None
        if isinstance(key, bool) or not isinstance(key, (int, float)):
            raise ValueError(f"Indexer timeline bucket {position} thiếu key")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"Indexer timeline bucket {position} có doc_count sai")
        bucket_start = datetime.fromtimestamp(key / 1000, tz=timezone.utc)
        if not start <= bucket_start < end:
            continue
        bucket_end = min(bucket_start + timedelta(seconds=interval_seconds), end)
        timeline.append({
            "start": format_utc(bucket_start),
            "end": format_utc(bucket_end),
            "count": count,
        })

    rules_object = aggregations.get("rules")
    rule_buckets = rules_object.get("buckets") if isinstance(rules_object, dict) else None
    other_count = rules_object.get("sum_other_doc_count") if isinstance(rules_object, dict) else None
    if not isinstance(rule_buckets, list):
        raise ValueError("Indexer rule buckets không hợp lệ")
    if isinstance(other_count, bool) or not isinstance(other_count, int) or other_count < 0:
        raise ValueError("Indexer sum_other_doc_count không hợp lệ")
    rules = []
    for position, bucket in enumerate(rule_buckets):
        if not isinstance(bucket, dict):
            raise ValueError(f"Indexer rule bucket {position} phải là object")
        rule_id = bucket.get("key")
        count = bucket.get("doc_count")
        if rule_id in (None, "") or isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"Indexer rule bucket {position} không hợp lệ")
        sample = bucket.get("sample")
        sample_hits = sample.get("hits") if isinstance(sample, dict) else None
        sample_rows = sample_hits.get("hits") if isinstance(sample_hits, dict) else None
        if not isinstance(sample_rows, list):
            raise ValueError(f"Indexer rule bucket {position} thiếu sample hits")
        source = {}
        if sample_rows:
            row = sample_rows[0]
            source = row.get("_source") if isinstance(row, dict) else None
            if not isinstance(source, dict):
                raise ValueError(f"Indexer rule bucket {position} có sample _source sai")
        max_level = bucket.get("max_level")
        level = max_level.get("value") if isinstance(max_level, dict) else None
        if level is None:
            level = 0
        if isinstance(level, bool) or not isinstance(level, (int, float)):
            raise ValueError(f"Indexer rule bucket {position} có max_level sai")
        rules.append({
            "rule_id": str(rule_id),
            "count": count,
            "max_level": level,
            "first_seen": _aggregation_time(bucket.get("first_seen")),
            "last_seen": _aggregation_time(bucket.get("last_seen")),
            "sample": source,
        })

    return {
        "timeline": timeline,
        "timeline_interval_seconds": interval_seconds,
        "rule_buckets": rules,
        "rules_truncated": other_count > 0,
        "represented_alerts": sum(item["count"] for item in rules),
        "unique_rules": _aggregation_value(aggregations, "unique_rules"),
        "unique_agents": _aggregation_value(aggregations, "unique_agents"),
        "unique_source_ips": _aggregation_value(aggregations, "unique_source_ips"),
        "unique_counts_approximate": True,
        "cardinality_precision_threshold": CARDINALITY_PRECISION_THRESHOLD,
    }


def fetch_alerts_window(
    cfg: dict,
    start: str | datetime,
    end: str | datetime,
    *,
    max_alerts: int = 2000,
    max_rule_buckets: int = 1000,
    max_timeline_buckets: int = 96,
    max_span: timedelta = timedelta(days=30),
    now: datetime | None = None,
    source_ip: str | None = None,
    agent_ip: str | None = None,
    expected_rule_ids: list[str] | tuple[str, ...] | None = None,
    summary_only: bool = False,
) -> dict:
    """Read a window in full-detail or aggregate-only mode based on exact total."""
    if isinstance(max_alerts, bool) or not isinstance(max_alerts, int) or not 1 <= max_alerts <= 9999:
        raise ValueError("max_alerts phải nằm trong khoảng 1..9999")
    if not isinstance(max_rule_buckets, int) or isinstance(max_rule_buckets, bool) or not 1 <= max_rule_buckets <= 5000:
        raise ValueError("max_rule_buckets phải nằm trong khoảng 1..5000")
    if not isinstance(max_timeline_buckets, int) or isinstance(max_timeline_buckets, bool) or not 12 <= max_timeline_buckets <= 288:
        raise ValueError("max_timeline_buckets phải nằm trong khoảng 12..288")
    if not isinstance(summary_only, bool):
        raise ValueError("summary_only phải là boolean")
    start_utc, end_utc = validate_time_range(start, end, max_span=max_span, now=now)
    start_text, end_text = format_utc(start_utc), format_utc(end_utc)
    filters = _correlation_filters(
        source_ip=source_ip,
        agent_ip=agent_ip,
        expected_rule_ids=expected_rule_ids,
    )
    interval_seconds = _timeline_interval_seconds(start_utc, end_utc, max_timeline_buckets)
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": _window_query(start_text, end_text, filters),
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": f"{interval_seconds}s",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_text, "max": end_text},
                }
            },
            "rules": {
                "terms": {"field": "rule.id", "size": max_rule_buckets, "order": {"_count": "desc"}},
                "aggs": {
                    "max_level": {"max": {"field": "rule.level"}},
                    "first_seen": {"min": {"field": "timestamp"}},
                    "last_seen": {"max": {"field": "timestamp"}},
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": {"includes": _AGGREGATE_SOURCE_FIELDS},
                            "sort": [{"timestamp": {"order": "desc"}}],
                        }
                    },
                },
            },
            "unique_rules": {"cardinality": {"field": "rule.id", "precision_threshold": CARDINALITY_PRECISION_THRESHOLD}},
            "unique_agents": {"cardinality": {"field": "agent.id", "precision_threshold": CARDINALITY_PRECISION_THRESHOLD}},
            "unique_source_ips": {"cardinality": {"field": "data.srcip", "precision_threshold": CARDINALITY_PRECISION_THRESHOLD}},
        },
    }
    url = f"{_indexer_base_url(cfg)}/{ALERT_INDEX_PATTERN}/_search"
    response = requests.post(url, json=query, **_request_kwargs(cfg))
    response.raise_for_status()
    body = response.json()
    total = _exact_total(body)
    summary = _parse_window_aggregations(
        body,
        start=start_utc,
        end=end_utc,
        interval_seconds=interval_seconds,
    )
    common = {
        "start": start_text,
        "end": end_text,
        "total": total,
        "detail_limit": max_alerts,
        **summary,
    }
    if summary_only or total > max_alerts:
        return {**common, "analysis_mode": "aggregate", "alerts": []}
    detailed = fetch_alerts_range(
        cfg,
        start_utc,
        end_utc,
        max_alerts=max_alerts,
        max_span=max_span,
        now=now,
        source_ip=source_ip,
        agent_ip=agent_ip,
        expected_rule_ids=expected_rule_ids,
    )
    if detailed["total"] != total:
        raise ValueError("Indexer total thay đổi giữa aggregate và detail query")
    return {**common, "analysis_mode": "full", "alerts": detailed["alerts"]}


def fetch_alert_document(cfg: dict, index_name: str, document_id: str) -> dict:
    """Lấy lại một alert theo identity do server đã lưu, không nhận arbitrary index."""
    if not isinstance(index_name, str) or not _ALERT_INDEX_RE.fullmatch(index_name):
        raise ValueError("index_name không thuộc wazuh-alerts-*")
    if not isinstance(document_id, str) or not document_id:
        raise ValueError("document_id phải là string không rỗng")
    url = f"{_indexer_base_url(cfg)}/{quote(index_name, safe='')}/_doc/{quote(document_id, safe='')}"
    response = requests.get(url, **_request_kwargs(cfg))
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("_source"), dict):
        raise ValueError("Indexer document response thiếu _source object")
    if body.get("found") is False:
        raise ValueError("Alert không còn trong Indexer")
    return {"_index": index_name, "_id": document_id, "_source": body["_source"]}


def fetch_active_source_ips(
    cfg: dict,
    start: str | datetime,
    end: str | datetime,
    *,
    limit: int = 50,
    max_span: timedelta = timedelta(days=30),
    now: datetime | None = None,
) -> list[dict]:
    """Lay danh sach cac IPv4 nguon hoat dong nhieu nhat trong khoang thoi gian."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit phai nam trong khoang 1..500")
    start_utc, end_utc = validate_time_range(start, end, max_span=max_span, now=now)
    query = {
        "size": 0,
        "query": _window_query(format_utc(start_utc), format_utc(end_utc), []),
        "aggs": {
            "top_source_ips": {
                "terms": {"field": "data.srcip", "size": limit, "order": {"_count": "desc"}}
            }
        },
    }
    url = f"{_indexer_base_url(cfg)}/{ALERT_INDEX_PATTERN}/_search"
    response = requests.post(url, json=query, **_request_kwargs(cfg))
    response.raise_for_status()
    buckets = response.json().get("aggregations", {}).get("top_source_ips", {}).get("buckets", [])
    return [
        {"ip": str(b["key"]), "count": int(b["doc_count"])}
        for b in buckets if b.get("key") and isinstance(b.get("doc_count"), int)
    ]


def load_sample_alerts(path: str | Path = SAMPLES_DIR) -> list[dict]:
    """Load alert mẫu từ thư mục eval/samples/ (dùng khi --demo)."""
    alerts = []
    for f in sorted(Path(path).glob("*.json")):
        alerts.append(json.loads(f.read_text(encoding="utf-8")))
    return alerts
