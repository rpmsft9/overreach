# Changelog

All notable changes to **overreach** are documented here. The project audits Microsoft
Entra ID for over-permissioned human identities — deterministically, with no LLM in the
verdict path, read-only.

The format follows [Keep a Changelog](https://keepachangelog.com/); this project uses
semantic versioning.

## [0.1.0] — Initial release

### Added
- **Six over-privilege checks (OP1–OP6):** standing privileged role (should be PIM-eligible),
  Global Admin sprawl, dormant privileged account, privileged-without-MFA (labelled an
  amplifier), hidden admin via group nesting, and the privilege→agent (OBO) bridge.
- **Deterministic, explainable engine** — every finding records evidence and a confidence
  level; the methodology triangulates signals rather than claiming a verdict about "need".
- **`scan`** — run the checks over an inventory (Markdown or JSON output).
- **`roles-report`** — the flat "every role → everyone assigned" report, with eligible/active
  and via-group resolved (Markdown, JSON, or CSV).
- **`inventory`** — read-only Microsoft Graph collector (via `az login`): users, active and
  eligible (PIM) directory-role assignments, MFA registration, **group-nesting expansion**
  (role-via-group resolved to transitive members), and **OP6 inputs** (owned OBO-capable apps
  and Agent 365 registrations).
- **`dcspm`** — read-only pull of Microsoft Defender CSPM CIEM recommendations (stale /
  over-permissioned identities) from Azure Resource Graph; `scan --dcspm` merges those
  resource-plane signals with the native directory-role checks.
- **Offline fixtures** so `scan`, `roles-report`, and the DCSPM merge run with no tenant.
- Read-only throughout, with least-privilege Graph scopes documented.
