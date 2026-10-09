"""Render findings as Markdown or JSON."""

import json
from dataclasses import asdict

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_KEYS = ("critical", "high", "medium", "low")


def to_json(tenant, findings):
    payload = {
        "tenant": tenant,
        "summary": _counts(findings),
        "findings": [asdict(f) for f in _sorted(findings)],
    }
    return json.dumps(payload, indent=2)


def to_markdown(tenant, findings):
    findings = _sorted(findings)
    counts = _counts(findings)
    lines = [
        "# overreach - Entra least-privilege audit",
        "",
        f"**Tenant:** {tenant}  ",
        f"**Findings:** {len(findings)}  ",
        "**By severity:** " + ", ".join(f"{k} {counts.get(k, 0)}" for k in SEV_KEYS),
        "",
        "> Findings are candidates for review with evidence and a confidence level, "
        "not absolute verdicts of need. Confirm via an access review.",
        "",
    ]
    for f in findings:
        amp = " - _amplifier_" if f.amplifier else ""
        src = " - _Defender CSPM_" if getattr(f, "source", "native") == "defender-cspm" else ""
        lines += [
            f"## [{f.severity.upper()}] {f.rule} - {f.title}{amp}{src}",
            f"- **Identity:** {f.identity_upn}",
            f"- **Confidence:** {f.confidence}",
            f"- **Evidence:** {f.evidence}",
            f"- **Remediation:** {f.remediation}",
            "",
        ]
    return "\n".join(lines)


def _sorted(findings):
    return sorted(findings, key=lambda f: (-SEV_ORDER[f.severity], f.rule, f.identity_upn))


def _counts(findings):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
