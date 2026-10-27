# AI-SIEM Thesis Research Roadmap (2026-10-27)

Status: **APPROVED PLAN / NOT IMPLEMENTED**. Owner: project maintainers. Baseline: `main@70562675114d6cab2ba942a31333a41b4df406ce`. Scope: Wazuh-based analyst-assist, *not* a replacement SIEM, not autonomous response.

## Research question and contributions
Does task-specific QLoRA supervised fine-tuning, separately and in conjunction with local RAG and explainable event correlation, improve evidence-grounded SOC triage over both native Wazuh rules and the same untuned LLM under comparable compute constraints?

Contributions to test (hypotheses, **not findings**):
1. Domain-specific SFT improves correct disposition, high/critical recall, claim grounding and abstention.
2. Versioned rule+ATT&CK RAG improves grounded MITRE mapping without increasing unsupported causal claims.
3. Deterministic correlation adds incident-level context and improves multi-event classification, without pretending an alert proves compromise.
4. Local model deployment on RTX 5070 Ti 16GB is feasible with controlled p95 latency, peak memory and reproducibility.

## Existing assets and cautions
- Preserve Wazuh Indexer :9200 -> extractor -> analysis_service -> llm -> review/export, dashboard SQLite, evidence provenance and local-only default.
- Historical `eval/`: 33 sanitized-live cases, 370 stratified synthetic cases and existing benchmark tools. The 33-case severity adjudication exists in `eval/adjudicated_severity.json` (reported Cohen kappa 0.91); reconcile stale `draft-single-reviewer` metadata and complete semantic human review. Do not claim RAG significant on N=33 (recorded McNemar p~0.58).
- `docs/hybrid-ai-gateway-roadmap.md` G0-G6 is PLANNED; implement, do not duplicate. CI stability and secret audit precede runtime migrations.
- Current model tags and prompts are historical baselines, not a frozen new SFT checkpoint. No fine-tuned weights or live benchmark are provided by this document.

## Sixteen-week phased schedule and hard exit gates

| Phase | Weeks | Deliverables | Exit criterion |
|---|---|---|---|
| P0 Baseline & security | 1-2 | CI fixes, environment lock, dataset audit, evaluation protocol | Clean checkout CI green on all supported matrices; 33-case baseline can be rerun and traced |
| P1 Dataset | 2-6 | Source register, license review, lab captures, schema, de-identification, lineage, 2-reviewer protocol, frozen splits | No group overlap or near-duplicate train/test leakage; evidence and reviewers recorded |
| P2 Fine-tuning | 5-9 | 3B pipeline smoke, primary 7B QLoRA SFT, adapter export, validation | Training config/seed/log/model digest reproducible; holdout never used for tuning |
| P3 Correlation | 6-11 | Event normalizer, rule+time+host/IP grouping, incident evidence trace | Correlation tests include unrelated/benign events; no unsupported claims of successful exploitation |
| P4 Scientific benchmark | 9-13 | B0 Wazuh; B1 base; B2 base+RAG; B3 SFT; B4 SFT+RAG; B5 SFT+RAG+correlation | Paired evaluation and confidence intervals with macro F1, high/critical recall, grounding, abstention and p95 |
| P5 Gateway & UX | 11-15 | G0-G6 in controlled order, local registry, adapter identity, provenance, UI and optional cloud | No change to historical jobs; no cross-boundary fallback, cloud opt-in and redaction enforced |
| P6 Final acceptance | 14-16 | Full defense lab, runbook, research tables, reproducible package, thesis/slides | Independent replay and reviewer sign-off; explicitly report limitations/negative results |

## Evaluation protocol (freeze before SFT)
- Distinguish raw model predictions from deterministic severity floor/post-processing; score both.
- Use **identical base checkpoint**, inference configuration and evaluation splits for B1-B4; B5 must isolate correlation's contribution. Specialized 9B/cloud models are additional external comparators, not SFT ablations.
- Split by scenario/campaign/source session/template, not random individual lines. Existing `eval/cases` and `eval/stratified_370` are evaluation/regression material, **excluded from SFT training** until a formally versioned partition is documented.
- Label separately: observed event, attack attempt, attack success, unknown; severity, disposition, MITRE technique, supporting event IDs, missing evidence and action recommendations.
- Score schema validity; macro/micro F1; per-class recall, especially high/critical; invalid-output count; MITRE evidence precision/recall; unsupported claims; correct abstention; correlation pair/group F1; analyst time-to-triage; throughput, latency p50/p95, VRAM and usage.
- McNemar for paired binary correctness and group-aware bootstrap confidence intervals for F1/other metrics. Do not assume the 370 synthetics guarantee 80% statistical power.
- Blind dual-analyst labeling/adjudication for held-out eval, publish Cohen's kappa and unresolved disagreement; AI judge is secondary only.
- Repeat stochastic experiments across >=3 documented seeds when feasible; report failures and data contamination risks.

## Model training constraints
- RTX 5070 Ti 16GB: QLoRA trial starting at 3B then 7B (4-bit NF4, LoRA rank 16/32, gradient checkpointing, short 1024-2048 context, microbatch 1). Benchmark real VRAM; not a guarantee of fit.
- Use separate train/validation/test pipelines. Human-reviewed `train.jsonl` only; candidate event logs and synthetic scaffolds must **never** silently become labeled SFT examples.
- Preserve SOC output schema and observed facts/inferences/uncertainties; forbid auto-block/auto-command execution.

## Security & operational invariants
- Loopback dashboard default, local-first; cloud egress disabled without owner approval, explicit data minimization and API-key vault.
- No tracked credentials, private keys, unredacted identifiers or customer logs; dataset artifacts stay local until redistribution permission verified.
- Treat source log text and retrieved material as untrusted. Human-in-the-loop response only.
- Each PR: baseline SHA, test command/output, changed files, data/license lineage, regression status, risk, rollback notes, CHANGELOG/HANDOFF updates.

## Next action (P0)
Fix G0 CI/runtime defects from the existing gateway roadmap, reconcile evaluation ground-truth provenance, then build/validate the dataset acquisition and RAG corpus described in `research/README.md`. 
