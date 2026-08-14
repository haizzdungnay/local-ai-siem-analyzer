# Data Export Privacy Contract (template)

This is the implementation contract for the local dashboard exports. It is
deliberately policy-neutral: a privacy/data owner must approve the final data
classification and retention decision before this template becomes a policy.

## Current technical contract

- JSON job exports (`v1` and `v2`) are scoped to the selected job/window.
- History JSON/CSV exports are scoped to the current visible page/filter result.
- Every export carries `export_metadata` with scope, page, redaction version,
  and an included/excluded field inventory.
- Included operational evidence may contain alert/rule IDs, timestamps, and
  source IP values needed for analyst correlation. Credential-shaped values are
  replaced with `[redacted]` and credential/config fields are omitted.
- Raw logs, prompts, model reasoning, passwords, tokens, API keys, cookies,
  credentials, and chat/email delivery configuration are never export fields.
- CSV formula neutralisation remains mandatory. Browser print uses the same
  client redaction boundary and must not be treated as an unrestricted export.

## Versioned privacy defaults (implemented)

The application emits `contract_version: local-ai-export-contract/v1` and
`redaction_version: export-redaction-v1` in JSON job exports. The metadata also
records the field classifications, marker semantics, IP policy, review-note
policy, and export-retention status. These are technical defaults, not a legal
classification:

- **Operational:** job and model audit metadata, timestamps, bounded analysis,
  rule/alert references, metrics, and source IPs needed for SOC correlation.
- **Sensitive/omitted:** raw logs, prompts, model reasoning, credentials,
  cookies/tokens, delivery configuration, and private config fields.
- **Owner-controlled:** `review.note`, `review_history.note`, source-IP masking,
  export-file retention, and any organization-specific secret patterns.

The default `dashboard.export_ip_policy: preserve` keeps source IPs for SOC
correlation. A data owner can set `mask` to emit a network prefix instead. The
default `dashboard.export_review_notes: true` preserves bounded analyst notes
for local case continuity; set it to `false` before sharing exports if notes
are not approved for outbound use. JSON v1/v2 and history CSV/JSON omit raw
logs and credential values; browser print/PDF uses the same DOM text boundary
and must not be treated as a separate unrestricted data path.

Credential-shaped values are replaced with the literal `[redacted]`; fields
classified sensitive are omitted. Unicode is serialized as UTF-8 and retained.
CSV cells beginning with `=`, `+`, `-`, or `@` (including leading whitespace)
are prefixed with an apostrophe to prevent spreadsheet formula execution.
Browser-rendered text uses `textContent`, so analyst text is not interpreted as
HTML/script. `export_retention_days` is optional advisory metadata only: the
dashboard does not store downloaded files or enforce deletion. An owner must
approve storage, sharing, expiry, and deletion controls separately.

## Owner decisions required

The privacy/data owner should complete and approve:

1. Allowed identifiers (for example: rule ID, alert ID, timestamp, IP, agent
   reference) and whether IPs require masking or retention.
2. Forbidden data classes and any organization-specific secret patterns.
3. Export-file retention, storage location, sharing, and deletion controls.
4. Whether review notes and analyst-entered text are exportable.
5. Named owner and review date for this contract.

Until those decisions are approved, the restrictive technical defaults above
remain in force; no custom pattern or additional field is enabled by guesswork.
