# Hybrid AI Model Gateway — implementation roadmap

> Status: **PLANNED / DOCUMENTATION ONLY**. Date: 2026-10-23 (Asia/Ho_Chi_Minh).
> Baseline: main @ baa7913 (2026-10-21). This document proposes work; none of the new gateway features are implemented or tested by this document-only change.
> Scope: single-operator, loopback-only SOC analyst assistant. Wazuh remains the alert source; AI output is advisory and never auto-remediates.

## 1. Goal, outcome, and invariants

**Product goal:** manage local and cloud AI providers, model registrations, credential references, defaults, capability limits, and per-job selection in the existing dashboard without editing backend source or YAML each time. Preserve the existing Wazuh/Indexer -> aggregate/RAG -> SOC contract -> validation -> review/report pipeline.

**Desired operator journey:**
1. Open Model Manager; select Ollama, OpenAI-compatible endpoint, OpenRouter, or a supported native cloud adapter.
2. Provide endpoint and (where required) API key through an authenticated local admin operation; key is write-only in the UI.
3. Test reachability, discover models when supported, or explicitly register a model ID and capabilities.
4. Enable one or more models, select an explicit default and optional per-workflow routing policy.
5. Choose a model for manual window, schedule, IP profile, and bounded security-test analysis; observe provider/model/latency/token/cost/provenance without exposing credentials.

**Non-negotiable invariants:**
- Wazuh Indexer (:9200) is the alert data source; Wazuh Manager (:55000) is not.
- Default **local-first**, **cloud disabled**, and **no cross-boundary automatic fallback**. Cloud egress requires explicit owner opt-in per policy; RAG embedding remains local unless independently approved.
- Dashboard remains bound to 127.0.0.1 until a separately reviewed auth/TLS/RBAC release. New admin endpoints require operator authentication and CSRF/Origin checks despite loopback.
- Do not persist raw alert bodies, private model reasoning, system prompts, full RAG text, or API keys in job reports, browser logs, telemetry, and tracked files. Preserve existing evidence provenance, JSON compatibility, and analyst review workflow.
- Runtime cap is **provider/model-specific**, not merely VRAM. Cloud is not constrained by client GPU or Ollama options; cloud still has finite context, output, rate and monetary limits.
- The assistant never executes security response commands automatically.

## 2. Baseline audit at planning time

| Area | Current code | Consequence / proposed seam |
|---|---|---|
| Model discovery | dashboard.py _model_list() calls Ollama /api/tags and filters dashboard.allowed_models | Replace with registry-backed /api/ai/models; preserve old list as migration seed |
| Calling inference | llm.py calls ollama.Client.chat directly | Move transport behind typed ProviderAdapter; keep SOC contracts and validation |
| Hardware policy | analysis_service.py calls adaptive_pacing_options() for aggregate runs | Move to LocalRuntimePolicy; never call GPU detection for cloud |
| Job execution | dashboard_worker.py uses calling_ollama phase | Introduce generic calling_model while accepting historical phases |
| Job persistence | dashboard_store.py SQLite schema v9 and job model string | Add additive registry/provider snapshot and migration; do not break v9 history |
| Web UI | web/index.html, app.js present Ollama dropdowns | Add Models/Providers settings and registry-backed selectors for all entrypoints |
| CI baseline | latest main GitHub Actions is failing on 4 OS/Python combinations | G0 release gate before feature work |

**Known G0 defect evidence:** Actions run 39628600799 reports 13 failed, 301 passed, 2 skipped on Ubuntu Python 3.11; same failure class on Linux/Windows Python 3.11/3.12. Primary cause: missing psutil dependency used in detect_system_hardware() and /api/status. Low-VRAM/CPU pacing may inject low_vram/num_thread keys that normalize_llm_parameters() rejects. Report does not claim these are the only future defects.

## 3. Target component boundaries

~~~text
Dashboard (Model Manager / job forms / schedule / IP / security-test)
      |
      v
AI Gateway API [auth + CSRF + validated requests]
      |
      +-- Model Registry (provider, model ID, aliases, capability and enabled state)
      +-- Credential Vault (OS-protected keys, write-only browser API)
      +-- Router (explicit route, availability, policy + consent; fail closed)
      +-- Provider Adapters
      |     +-- Ollama native
      |     +-- OpenAI-compatible (including OpenRouter or local LM Studio/vLLM)
      |     +-- Optional native adapters when protocol-specific features require them
      +-- Policies
            +-- LocalRuntimePolicy (GPU, available VRAM, memory, batching, context)
            +-- CloudCapabilityPolicy (context/output/structured-output capabilities)
            +-- ContextBudgeter (tokenization, evidence packing, RAG, coverage)
            +-- CloudDataPolicy (classification, redaction, explicit allow)
      |
      v
Existing AnalysisService -> SOC schema/quality gates -> provenance -> SQLite -> reports
~~~

Design the adapter contract around invoke(), list_models() when available, test_connection(), capabilities() and safe provider-specific errors. Use typed request/response objects without leaking provider SDK structures into SOC business logic. Support native Ollama options only in the Ollama adapter; do not send them to cloud APIs.

**Explicit provider identification**: route by internal provider_id + model_id, never by a fragile display label or substring. Separate executable model from its alias, endpoint, model digest/version and configured capabilities. Capabilities must be confirmed by provider documentation/API or operator configuration with a recorded source and verification timestamp; never guess from a model name.

## 4. Durable state and compatibility contract

Additive SQLite migration (target v10 if v9 remains latest at implementation time; recheck schema before writing migration):
- providers: id, display_name, adapter_type, normalized_endpoint, trust_class (local/cloud), enabled, credential_ref, connection status timestamps, configuration revision.
- models: id, provider_id, remote_model_id, alias, enabled, capability_revision, context_limit, output_limit, supports_schema, supports_tools, pricing snapshot/source/time, defaults and explicit warnings.
- routes: workflow name (window, fixed_window, ip_profile, security_test), selected model_id, allowed-fallback model IDs, privacy mode, budget policy version.
- usage_events: job ID, provider_id/model_id, latency, reported/estimated token counts, estimated cost, request status and sanitized error classification. No payloads or secrets.
- credential references only in DB; key material in a local encrypted vault bound to operator account or a protected host secret store.

Every new job stores an **immutable, non-secret** execution snapshot: provider ID, model ID, remote model ID, execution_type, capability revision, routing/policy revision, requested/effective context and output budget, privacy/redaction version and provider response identity. Preserve model digest, language, SOC contract, evidence hashes, RAG provenance, output_origin and explicit fallback reason. Job rerun must never silently switch model/key/profile; allow an explicit 'rerun using current configuration' action as a separate job.

Migration strategy: backup -> expand schema -> seed current Ollama models/aliases from allowed_models -> retain old model string and v9 jobs -> dual-read compatibility -> switch new jobs to registry -> verify rollback/recovery. No rewriting historical jobs, no destructive migration, and do not change default model during migration.

## 5. Security, privacy, and API-key rules

1. **Credential vault**: prefer OS keyring/Windows DPAPI for the Windows host; POSIX must use an equivalent protected store or explicitly configured encrypted-at-rest vault with restrictive permissions. Store references only in SQLite. Write-only create/rotate operations; no GET raw key. A failed vault initialization blocks adding cloud providers rather than downgrading to plaintext.
2. **Local admin authorization**: authentication + CSRF protection on all provider/credential/model/route mutations; secure cookies and Origin/Host enforcement. Browser JavaScript must never receive key material from the server. No secrets in job snapshots, export, traceback, URL, query, prompt or system logs.
3. **SSRF/credential exfiltration protection**: allowlisted provider presets; custom HTTPS endpoints require explicit approval and TLS verification. Reject URL userinfo, unsafe schemes, redirects, local/private/link-local/metadata destinations for cloud connections. Re-validate DNS/IP at connection time; defend against DNS rebinding/redirect pivot and credential forwarding across hosts. Local adapter endpoint is separately allowlisted to loopback/admin-approved hosts.
4. **Cloud egress policy**: default local_only. Allow sanitized_only (deterministic redaction/pseudonymization, bounded evidence and a data-preview test) or approved_full (explicit owner authorization and audit). These are distinct from model selection; choosing cloud does NOT silently authorize sending raw logs or RAG corpus.
5. **Fail closed**: do not automatically fallback from local to cloud, from sanitized to raw, or across providers with different policy/trust class; 401/403 and credential errors are not fallback triggers. Rate limit, retry, timeout and 429/5xx handling must be bounded and idempotency-aware. No silent replay of sensitive prompts.
6. **Quota & costs**: per-provider and per-route request/minute, token/minute, concurrency, per-job estimated maximum and daily/monthly budget caps, with hard-stop when policy requires. Distinguish provider-reported vs estimated usage and price.
7. **Compatibility**: preserve current security-test fixed scenarios and server-owned targets. Dynamic model selection may only use an approved capability list and the existing test's time/token ceiling unless separately reviewed. Keep report-delivery credentials independent from AI keys.
8. Audit the tracked docs/history for potentially live lab credentials before public release; never include example real keys in fixtures or docs.

## 6. Runtime separation: local versus cloud

### Local
- Detect NVIDIA via bounded nvidia-smi call when available; psutil must be declared or handled gracefully; no hard failure of /api/status if hardware detection unavailable.
- Prefer observed available VRAM and model residency, not only total VRAM. Account for GPU sharing and KV cache/context usage; fall back to bounded CPU settings if no GPU.
- Build allowlisted Ollama options (num_ctx, num_batch, num_gpu and num_thread only if actually supported); validate physical/SDK limits, record effective options, never inject unknown keys into generic LLM parameters.
- Test RTX 3050 4 GB, RTX 5070 Ti 16 GB, CPU-only, multiple-GPU and nvidia-smi missing/error. Do not assume 16k context or batch=256 is always optimal; benchmark throughput, p95 latency and peak memory.

### Cloud
- Do NOT call hardware detection to determine cloud request options, and do NOT apply local VRAM/num_batch/num_gpu/num_thread or Ollama-specific ctx settings.
- Determine model context window, maximum output tokens, provider-specific structured-output support and request limits from verified capability profiles; use an adapter that maps generic budgets to the correct provider API. Cloud does not mean unlimited context or unlimited cost.
- Compute input budget in **tokens**, not character count: min(provider/model context - reserved output - safety margin, policy cap). Use the appropriate tokenizer or measured conservative estimate; record confidence/uncertainty of estimate.
- Retain data minimization: choose highest-value Wazuh evidence with transparent coverage/truncation; optionally add hierarchical/map-reduce analysis for long windows instead of dumping raw alerts or exceeding RAG safeguards.
- Structured output: prefer provider schema mode where genuinely supported; otherwise use normal response plus strict existing JSON validation and explicit fallback/repair policy. Do not persist hidden thinking/private reasoning.
- Any context-expansion technique must respect privacy and cloud-cost constraints. Prompt contract, evidence provenance and MITRE hallucination checks must remain enforced.

## 7. UI and API design

**UI pages**
- /ai-models: Providers; Models; Credentials status; Routes; Usage & Health; Admin audit.
- Add provider wizard: preset/adapter -> endpoint -> write-only key -> test -> discover/register -> enable -> default routing. Test operations never return the key.
- Model list: local/cloud badge, provider, alias, availability, context limit, output cap, capability/source, explicit warning if limits unverified, costs if published.
- Job forms (manual, schedule, IP profile, security tests) use consistent registry-backed model selection; show cloud data-policy indicator and estimated request tokens/cost before dispatch. Preserve older results.
- Hardware panel only for local runtime. Cloud details show provider latency, rate-limit and token budget, never client VRAM as a cloud constraint.

**Suggested endpoint contracts** (exact API shape is to be finalized at G1):
- GET/POST /api/ai/providers
- PATCH/DELETE /api/ai/providers/{id}; POST /api/ai/providers/{id}/test
- POST /api/ai/providers/{id}/credentials:rotate (write-only)
- GET /api/ai/providers/{id}/models:discover
- GET/POST /api/ai/models; PATCH /api/ai/models/{id}
- GET/PUT /api/ai/routes/{workflow}
- POST /api/ai/requests:preview (sanitized input metadata, token/cost bound, policy decision; never raw secret)
- GET /api/ai/hardware and GET /api/ai/usage

Each mutation needs schema validation, an authenticated local administrator, a revision check/ETag for concurrent edits, and audit metadata. Model discovery and connection testing have short timeouts and strict URL/redirect constraints. API examples in docs must use placeholders only.

## 8. Delivery phases and acceptance gates

### G0 — Stability gate (P0)
**Change areas**: requirements/lockfile, llm.py, ui.py, analysis_service.py and regression tests.
- [ ] Pin psutil (or remove the hard runtime dependency safely), handle missing nvidia-smi and hardware failure without 500 responses.
- [ ] Make low-VRAM and CPU policy options compatible with their validators; ensure unsupported provider args never pass through.
- [ ] Normalize local thinking/JSON behavior, avoid catch-all TypeError retry and preserve honest fallback metadata.
- [ ] Run pytest, compile, secret scan, pip-audit/SBOM and JS/shell checks.
**Exit:** all four GitHub CI matrix jobs pass; /api/status=200 on systems without GPU; no new security regression. Do not mark complete from an unverified local-only run.

### G1 — Gateway contracts, registry and migrations (P0)
- [ ] Define provider/model IDs, adapter interfaces, capability schema, error taxonomy and versioned provider/request provenance.
- [ ] Write v9+ additive SQLite migration, deterministic migration tests, rollback and backup procedure.
- [ ] Seed current Ollama allowed models; keep old APIs and job exports working via compatibility adapters.
- [ ] Document API threat model, default routes and initial provider preset allowlist.
**Exit:** migration from a copied v9 DB preserves jobs/reviews/schedules; old UI and tests still work; registry supports an offline fake adapter.

### G2 — Credential vault and connection administration (P0)
- [ ] Add encrypted host credential storage, write-only key rotation, reference-only persistence and no-key browser responses.
- [ ] Add authenticated local admin protections, CSRF/Origin/Host checks and audited provider CRUD.
- [ ] Validate endpoints against SSRF/DNS/redirect/TLS/metadata-IP bypasses; bound /test and model discovery.
**Exit:** no secret in DB, browser response, logs or exports; blocked SSRF test matrix; vault failure is fail-closed.

### G3 — Providers and unified inference (P1)
- [ ] Ollama adapter with exact existing behavior and local model discovery.
- [ ] OpenAI-compatible adapter for approved cloud/local endpoints, starting with OpenRouter-style API and explicit model IDs.
- [ ] Add native adapters for non-compatible functionality only when acceptance tests show need; do not claim universal native support.
- [ ] Normalize usage, structured output, timeouts, retries and per-provider errors without weakening SOC schema validation.
**Exit:** mocked end-to-end SOC job succeeds separately on Ollama and OpenAI-compatible adapter; invalid output/failure remains explicit; no cloud calls in offline CI.

### G4 — Context, hardware, routing and privacy policies (P1)
- [ ] Local hardware policy based on available GPU/VRAM and memory; cloud bypasses that policy entirely.
- [ ] Token-aware context budgeting, verified capability limits, output reserves, optional bounded hierarchical analysis.
- [ ] Explicit routing/defaults, bounded rate/cost limits and privacy gates; disable silent local->cloud failover.
- [ ] Record requested/effective model, limits, truncation, token estimates and cost provenance.
**Exit:** CPU/3050/5070 Ti fixtures select valid options; cloud path never uses local GPU options; budget and privacy gate reject over-limit or unauthorized jobs.

### G5 — Dashboard integration and workflow parity (P1)
- [ ] Build Model Manager UI with provider wizard, credential rotation, model capabilities, defaults, routes and usage.
- [ ] Wire all job forms, fixed-window schedules, IP profiling and bounded security-test runner to registry.
- [ ] Make worker phases provider-neutral, keep historical phases readable, and preserve Telegram/Gmail/report behavior.
- [ ] Expose local hardware only when useful; cloud usage/latency/cost shown separately.
**Exit:** operator can add/test/enable/disable/select provider and model without restarting or editing backend; 4 workflow types use registry; historical jobs remain readable.

### G6 — Security, scientific evaluation and release gate (P1)
- [ ] Threat-model review, secret redaction and SSRF/CSRF/fallback/budget tests; run complete cross-platform CI and restore test.
- [ ] Benchmark same frozen, consent-safe evaluation corpus on baseline Qwen 2.5 7B, selected local Pentest model and one approved cloud model.
- [ ] Measure JSON validity, fallback/timeout, latency p50/p95, usage/cost, severity agreement, MITRE grounding and RAG/no-RAG ablation; do not claim superiority without adjudicated human labels.
- [ ] Redact/sanitize docs and review credential history, update README/CHANGELOG/HANDOFF, add operator runbook and explicit rollback.
**Exit:** CI 4/4, cloud opt-in confirmed, no secret leak, migration rollback verified, reproducible non-secret benchmark artifacts, signed-off human-in-the-loop operating instructions.

## 9. Sequence, dependencies and rollbacks

Order: **G0 -> G1 -> G2 -> G3 -> G4 -> G5 -> G6**. Some UI mockups and offline adapter tests can be developed in parallel, but not merged ahead of their security/migration gates. All feature PRs must be small and have test evidence, review, safe migration notes, CHANGELOG then HANDOFF updates.

Feature flags: ai_gateway.enabled=false and ai_gateway.cloud_enabled=false by default; legacy Ollama path remains the rollout fallback until G6 acceptance. Turning gateway off must not delete model/provider state or historical evidence. Provider/model deletion must be soft-disabled if referenced by any job; credential rotations never mutate frozen historical job snapshots. If a phase fails its gate, roll back the feature flag and migrations by the documented backup/restore procedure, not by destructive SQL edits.

Operational exit decision: only enable cloud usage after an owner confirms which data may leave the local lab, accepted providers and their retention terms, request budget, and who holds API keys. Keep deployment localhost-only until separate remote-security acceptance.

## 10. Implementation checklist (code map)

| Proposed new component | Planned responsibility |
|---|---|
| ai_module/ai_gateway/registry.py | provider/model/capability lookups and revisions |
| ai_module/ai_gateway/router.py | workflow route decisions with privacy and budget enforcement |
| ai_module/ai_gateway/credentials.py | encrypted local secret references, key rotation |
| ai_module/ai_gateway/providers/ollama.py | local Ollama-specific calls/discovery |
| ai_module/ai_gateway/providers/openai_compatible.py | standardized compatible HTTP adapter |
| ai_module/ai_gateway/runtime_policy.py | local GPU policy and cloud capability isolation |
| ai_module/ai_gateway/context_budget.py | token budgeting, evidence coverage, long-window strategy |
| ai_module/ai_gateway/privacy_policy.py | explicit local-only/sanitized/approved-full egress gates |
| ai_module/blueprints/ai_models.py | protected admin APIs |
| ai_module/web/models.html + models.js | visual provider/model administration |
| tests/test_ai_gateway_*.py | migration, auth, SSRF, policies, adapters, workflows |

Touch existing llm.py, dashboard.py, analysis_service.py, dashboard_worker.py, dashboard_store.py, reports/export and frontend forms via compatibility-preserving refactors, not parallel alternate SOC implementations.

## 11. Acceptance evidence per phase

Each PR must link its phase and include: changed files; baseline and final commit SHA; concrete automated test results and commands; local/cloud mock evidence; migration/rollback procedure where applicable; risk/limitations; updated CHANGELOG.md and HANDOFF.md. Live cloud keys and live Wazuh data must never be required in CI. Mark an item DONE only if the gate is demonstrably satisfied.

**Current state**: G0–G6 all PLANNED. This roadmap is a planning artifact, not an assertion that any gateway provider, API key vault, cloud routing or UI already exists.
