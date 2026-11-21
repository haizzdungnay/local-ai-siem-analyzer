import argparse
import csv
import json
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

AI_MODULE_DIR = Path(__file__).resolve().parents[1] / "ai_module"
sys.path.insert(0, str(AI_MODULE_DIR))

from extractor import extract_fields, format_for_llm, normalize_mitre_ids
from llm import OUTPUT_KEYS, OUTPUT_SEVERITIES, SOC_PROMPT_VERSION, analyze_alert, mitre_grounding
from playbooks import get_playbook
from rag import DEFAULT_RELEVANCE_THRESHOLD, MAX_TOP_K, RuleRAG
from reader import load_config

EVAL_DIR = Path(__file__).resolve().parent
RESULT_FIELDS = [
    "case_id", "model", "rag_enabled", "language", "latency_s", "schema_valid", "error",
    "prompt_version", "system_prompt_sha256", "requested_language",
    "response_language", "language_compliance", "output_origin",
    "provenance_json",
    "summary_score", "root_cause_score", "severity_score", "mitre_score",
    "next_steps_score", "reviewer", "notes", "output_json",
]


def _configure_console_encoding():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def parse_args():
    parser = argparse.ArgumentParser(description="Chạy baseline GĐ4 trên corpus eval")
    parser.add_argument("--config", default=str(AI_MODULE_DIR / "config.yaml"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--playbooks", action="store_true",
                        help="Thêm khối TRUSTED_PLAYBOOK theo rule.id (mặc định tắt để giữ baseline)")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--language", choices=("vi", "en"), default="vi",
        help="Ngon ngu output cua SOC prompt",
    )
    parser.add_argument(
        "--results", default=None,
        help="CSV output rieng; mac dinh la file gan prompt version va language",
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Cho phep ghi de file ket qua da ton tai (khong nen dung voi baseline lich su)",
    )
    return parser.parse_args()


def valid_output(result):
    return (
        isinstance(result, dict)
        and set(result) == OUTPUT_KEYS
        and all(
            isinstance(result[key], str) and bool(result[key].strip())
            for key in ("summary", "root_cause")
        )
        and isinstance(result["mitre"], str)
        and result["severity"] in OUTPUT_SEVERITIES
        and result["severity"] != "unknown"
        and isinstance(result["next_steps"], list)
        and bool(result["next_steps"])
        and all(isinstance(step, str) and step.strip() for step in result["next_steps"])
    )


def load_manifest(limit=None):
    manifest = json.loads((EVAL_DIR / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("eval/manifest.json phải là list không rỗng")
    return manifest[:limit]


def load_case(item):
    case_path = Path(item["case_file"])
    if not case_path.is_absolute():
        case_path = EVAL_DIR.parent / case_path
    return json.loads(case_path.read_text(encoding="utf-8"))


def open_results(path, *, overwrite=False):
    result_path = Path(path)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if overwrite else "x"
    handle = result_path.open(mode, newline="", encoding="utf-8")
    writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS)
    writer.writeheader()
    return handle, writer


def main():
    _configure_console_encoding()
    args = parse_args()
    cfg = load_config(args.config)
    model = args.model or cfg["ollama"]["model"]
    timeout = cfg["ollama"].get("timeout", 120)
    results_path = args.results or str(
        EVAL_DIR / f"results-{SOC_PROMPT_VERSION}{'-playbook' if args.playbooks else ''}-{args.language}.csv"
    )
    rag_enabled = bool(cfg.get("rag", {}).get("enabled")) and not args.no_rag
    with ExitStack() as cleanup:
        rule_rag = None
        if rag_enabled:
            store = cleanup.enter_context(TemporaryDirectory(prefix="siem-alert-eval-"))
            data_dir = Path(cfg["rag"]["data_dir"])
            if not data_dir.is_absolute():
                data_dir = AI_MODULE_DIR / data_dir
            rule_rag = RuleRAG(
                data_dir=str(data_dir),
                embedding_model=cfg["rag"]["embedding_model"],
                base_url=cfg["ollama"]["base_url"],
                timeout=timeout, persist_dir=store, in_memory=True,
                relevance_threshold=cfg["rag"].get("relevance_threshold", DEFAULT_RELEVANCE_THRESHOLD),
            )
            cleanup.callback(rule_rag.close)
            rule_rag.ensure_indexed()

        handle, writer = open_results(results_path, overwrite=args.overwrite)
        cleanup.enter_context(handle)
        manifest = load_manifest(args.limit)
        for index, item in enumerate(manifest, 1):
            alert = load_case(item)
            extracted = extract_fields(alert, cfg["extractor"]["fields"])
            alert_text = format_for_llm(extracted)
            rag_context = ""
            rag_provenance = {"status": "disabled"}
            error = ""
            if rule_rag:
                try:
                    rag_results, rag_provenance = rule_rag.query(
                        str(extracted.get("rule.id", "")), str(extracted.get("rule.description", "")),
                        mitre_ids=normalize_mitre_ids(extracted.get("rule.mitre.id"))[:MAX_TOP_K],
                        include_provenance=True,
                    )
                    rag_context = rule_rag.format_context(rag_results)
                    if rag_provenance.get("status") == "partial":
                        error = "RAG: " + rag_provenance["error_type"]
                except Exception as exc:
                    rag_provenance = {"status": "error", "error_type": type(exc).__name__}
                    error = "RAG: " + type(exc).__name__
            started = time.perf_counter()
            result = None
            provenance = {}
            try:
                result, provenance = analyze_alert(
                    alert_text=alert_text,
                    rag_context=rag_context,
                    model=model,
                    base_url=cfg["ollama"]["base_url"],
                    timeout=timeout,
                    language=args.language,
                    include_provenance=True,
                    allow_remote=cfg["ollama"].get("allow_remote", False),
                    playbook=get_playbook(extracted.get("rule.id", "")) if args.playbooks else None,
                    extracted=extracted,
                )
            except Exception as exc:
                error = ", ".join(filter(None, (error, "analysis: " + type(exc).__name__)))
            latency = time.perf_counter() - started
            provenance["rag"] = rag_provenance
            provenance["mitre_grounding"] = mitre_grounding(
                (result or {}).get("mitre"), extracted.get("rule.mitre.id"), rag_provenance.get("references", []),
            )
            writer.writerow({
                "case_id": item["case_id"], "model": model,
                "rag_enabled": str(rag_enabled).lower(), "language": args.language,
                "latency_s": f"{latency:.3f}",
                "schema_valid": str(valid_output(result)).lower(), "error": error,
                "prompt_version": provenance.get("prompt_version", ""),
                "system_prompt_sha256": provenance.get(
                    "system_prompt_sha256", provenance.get("prompt_sha256", "")
                ),
                "requested_language": provenance.get("requested_language", args.language),
                "response_language": provenance.get("response_language", ""),
                "language_compliance": provenance.get("language_compliance", "unknown"),
                "output_origin": provenance.get("output_origin", ""),
                "provenance_json": json.dumps(provenance, ensure_ascii=False, sort_keys=True),
                "output_json": json.dumps(result, ensure_ascii=False) if result is not None else "",
            })
            handle.flush()
            print(f"[{index}/{len(manifest)}] {item['case_id']}: {latency:.2f}s")


if __name__ == "__main__":
    main()
