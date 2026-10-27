# Dataset Source Register — AI-SIEM SOC SFT / Evaluation

Status 2026-10-27. Sources below are **candidates**, not downloaded, quality-assured or approved for training. Prioritize event-native Windows/Linux telemetry; flow-only ML datasets do not teach a language model to explain Wazuh alerts directly.

| Priority | Source | Data | Use | Licenses/caveats |
|---|---|---|---|---|
| A | [Splunk Attack Data](https://github.com/splunk/attack_data) | Raw Windows Security/Sysmon and other attack-event logs, *.yml metadata by ATT&CK technique, Git LFS | Candidate source for SOC SFT with manual annotation and evidence linkage | Apache-2.0 repository; individual samples may contain identifying/demo strings; some downloads large; ATT&CK folder is not success/severity ground truth |
| A | Own Wazuh lab (Index :9200, archives.json when enabled) | Actual Wazuh alerts + benign context and operator-run scenario log | Primary Wazuh-native train/evaluation *after split, annotation and consent* | Never push raw local IPs, secrets or attack outputs; controlled lab evidence required |
| B | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Multi-source malicious/benign security telemetry and replay metadata | Independent scenario diversity and correlation test candidates | License descriptions are inconsistent across some docs: verify actual current LICENSE per artifact before redistribution; no implicit labeling |
| C | [Splunk BOTS v3](https://github.com/splunk/botsv3) | Security challenge data, ~320 MB pre-indexed Splunk | External evaluation/incident investigation; extra conversion required | Splunk-specific format; verify license and data usage restrictions |
| D | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Labeled network flows and PCAP | Optional detection-model baseline, **not** main LLM log-explanation SFT | Academic research dataset, different schema from Wazuh alerts; cite originating paper |

## Recommended selection
**Primary:** Splunk Attack Data and own Wazuh lab. **RAG:** MITRE ATT&CK STIX 2.1 v20.0 (https://github.com/mitre-attack/attack-stix-data, dated 2026-10-13), plus Wazuh rule information checked against installed Wazuh version. **Secondary:** OTRF; monitor licenses/format. Sigma rules are optional retrieval references, NOT automatically training labels: SigmaHQ rules use Detection Rule License 1.1 (https://github.com/SigmaHQ/sigma/blob/master/LICENSE).

## Acquisition manifest per raw source
```json
{
  "source_id": "splunk-attack-data",
  "upstream_repository": "https://github.com/splunk/attack_data",
  "upstream_commit": "RECORD_SHA_ON_DOWNLOAD",
  "dataset_path": "datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log",
  "sha256": "CALCULATE_ON_DOWNLOAD",
  "format": "jsonlines-or-raw-event-log",
  "license": "Apache-2.0 (verify)",
  "capture_metadata_reviewed": false,
  "review_status": "unreviewed",
  "split_group_id": "RECORD_SCENARIO_OR_CAMPAIGN",
  "redistribution_approved": false
}
```

## Minimum release checks for supervised learning
- Raw log -> structured event candidate -> verified incident timeline -> two-reviewer annotation -> reconciled ground truth -> leakage-safe train/val/test splits -> SFT examples.
- Include benign, blocked, attempted, confirmed-successful and insufficient-evidence samples. Avoid unbalanced attacks-only training.
- Keep raw vendor rules/ATT&CK descriptions in versioned **RAG**, not masquerading as observed attack success.
- Reject duplicates across campaigns/templates; never treat event lines from one incident as independent train and test rows.
- No remote cloud model processing of local raw logs without explicit consent and data privacy assessment.
