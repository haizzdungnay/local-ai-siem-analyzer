# Security and governance policy

## Repository boundary

Tracked files are sanitized demonstration material. Live credentials, private
keys, tokens, customer data and operational config must never be committed.
Use the ignored `ai_module/config.yaml` or an external secret manager for the
active lab. The dashboard remains loopback-only and single-operator until an
authenticated deployment has its own security review.

Historical references to shared lab credentials have been removed from current
tracked docs. The operator must rotate or revoke any credential that may have
appeared in earlier Git history before distributing the repository. Rewriting
published Git history is an owner-approved operation and is deliberately not
performed by this project automatically.

## Automated controls

- `scripts/check_tracked_secrets.py` scans tracked configuration and
  documentation; the pre-commit hook scans staged blobs and CI scans the full
  checkout.
- `ai_module/requirements.txt` pins direct runtime dependencies. `pylock.toml`
  is a hash-bearing Python 3.12/Windows resolution snapshot; generate a new
  platform-specific lock whenever Python, platform or dependency inputs change.
- `scripts/audit_dependencies.py` runs `pip-audit` and only accepts documented,
  expiring exceptions in `ai_module/pip-audit-allowlist.json`. CI creates a
  CycloneDX SBOM artifact from the same requirements.
- GitHub Actions are pinned by commit SHA and run with read-only repository
  permissions.

## Product claims

Automated tests can prove contract behavior, not SOC semantic quality. Human
two-reviewer scoring, adjudication and analyst-only versus AI-assist timing
remain required before claiming that the model or RAG improves triage. See
`docs/improvement-plan.md` for the remaining evaluation protocol and release
gates.
