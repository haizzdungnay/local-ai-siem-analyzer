# AI-SIEM Research Workspace

This directory separates **training candidates**, **frozen evaluation** and **RAG knowledge**. It does not claim a model has been trained or that any external dataset is already ingested.

## Start here
1. Read [research roadmap](../docs/thesis-ai-siem-research-roadmap.md) and [dataset source register](datasets/SOURCES.md).
2. Review terms/license at source and download only the required Splunk Attack Data log via Git LFS (see below). Never add raw logs or credentials to Git.
3. Convert a downloaded JSON-lines Sysmon log into **unreviewed candidates**, not SFT labels:
   `python research/datasets/prepare_log_candidates.py --input /path/to/windows-sysmon.log --out /private/output/candidates.jsonl --source-id splunk-attack-data --scenario-id T1003.001-atomic --max-events 500`
4. Have a domain reviewer add disposition, event outcome, severity, evidence IDs and an analyst-approved response. Lock provenance and leakage-safe splits *before* generating SFT train/val JSONL.
5. Generate a **RAG corpus compatible with ai_module/rag.py**:
   `python research/rag/build_rag_corpus.py --mode starter`
   Or generate a current pinned MITRE Enterprise ATT&CK v20.0 corpus:
   `python research/rag/build_rag_corpus.py --mode mitre-20.0`
6. After inspecting `research/rag/generated/{wazuh_rules,mitre_techniques}.json`, configure `rag.data_dir` as an absolute path to that directory in the **local gitignored** `ai_module/config.yaml`. The existing ChromaDB indexer will build a separate index from the new content on next run. No changes are made to the currently active `ai_module/rag_data/` by this workflow.

### Verified source acquisition (optional, potentially large)
```bash
git lfs install --skip-smudge
git clone https://github.com/splunk/attack_data.git
cd attack_data
git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log"
```
Verify actual downloaded file, its corresponding *.yml metadata, hash, timestamp and content before converting. These Windows/Sysmon logs are **not** Wazuh alerts. They are only inputs for creating training candidates after normalization and human review. For Wazuh-native evidence, prioritize the own controlled Wazuh Indexer lab and correlate with operator-run scenarios; an imported attack log is not proof that Wazuh would have detected it.

### Privacy, licensing and eval separation
- External license/redistribution must be checked at acquisition and documented in a dataset card. Record source URL, repository revision, file hash, capture date and transforms.
- Never automatically assign 'malicious', 'successful' or a specific severity just because the source folder has an ATT&CK technique ID.
- Keep `eval/cases/` (33 live-sanitized), `eval/stratified_370/` and other frozen benchmarks out of training, or redesign splits/version evaluation to remove all overlap.
- `research/rag/seed/` is an authored starter knowledge base for demonstration, NOT a scientific ground-truth label collection.
- `research/rag/generated` is produced locally and intentionally gitignored; index metadata/versions need to be recorded with experiment outputs.

No model parameters, runtime dashboard configuration or production Wazuh data are changed in this PR.
