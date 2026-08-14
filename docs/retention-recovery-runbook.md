# Retention Recovery Runbook

Retention deletion is opt-in and must be approved by the data-retention owner before an operator runs it. The operator first calls `GET /api/maintenance/preview`, records the policy and confirmation token, then calls `POST /api/maintenance/prune` with `{"confirm":true,"confirmation_token":"..."}`. The service creates an integrity-checked SQLite snapshot and manifest in `dashboard_data/retention_backups/` before deleting eligible terminal jobs. A failed snapshot prevents deletion.

## Restore

An operator lists snapshots with `GET /api/maintenance` and validates the manifest filename, database path, schema version, SHA-256 checksum, and table counts. After approval, call `POST /api/maintenance/restore` with the snapshot filename, `confirm: true`, and a fresh preview token when token enforcement is enabled. Restore rejects traversal, snapshots belonging to another database, altered files, schema mismatches, and count mismatches. The target database is replaced atomically and integrity-checked.

## RPO/RTO and ownership

- RPO: the latest completed pre-prune snapshot; snapshots are local and must be copied to approved backup storage by the storage owner.
- RTO target: restore validation plus atomic replacement within 15 minutes for a normal local SQLite database; operator records actual duration.
- Approver: data-retention owner signs off the preview policy and restore request.
- Operator: storage-maintenance owner performs the calls and records snapshot checksum, outcome, and verification counts.
- Recovery verification: confirm jobs, analyst review events, analysis results, delivery records, and active/non-terminal jobs have the expected counts and statuses.

Authentication/RBAC is intentionally outside this runbook and must be supplied by the product owner before exposing maintenance endpoints beyond the trusted local operator boundary.
