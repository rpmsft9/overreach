"""Load an inventory, run the rules, and aggregate per-identity risk tiers."""

import json

from .models import Identity, OwnedApp, RoleAssignment
from .rules import PER_IDENTITY_RULES, op2_ga_sprawl

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_inventory(path):
    """Read an inventory JSON file into (tenant, list[Identity])."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _parse(data)


def _parse(data):
    identities = []
    for r in data.get("identities", []):
        ras = [RoleAssignment(
                   role=ra["role"],
                   assignment=ra.get("assignment", "active"),
                   scope=ra.get("scope", "/"),
                   via=ra.get("via", "direct"))
               for ra in r.get("role_assignments", [])]
        apps = [OwnedApp(
                    app_id=a.get("app_id", ""),
                    name=a.get("name", ""),
                    obo_capable=a.get("obo_capable", False))
                for a in r.get("owned_apps", [])]
        identities.append(Identity(
            id=r["id"], upn=r.get("upn", ""), display_name=r.get("display_name", ""),
            type=r.get("type", "human"), enabled=r.get("enabled", True),
            last_sign_in_days=r.get("last_sign_in_days"),
            mfa_registered=r.get("mfa_registered", True),
            is_guest=r.get("is_guest", False),
            role_assignments=ras, owned_apps=apps,
            owned_agents=r.get("owned_agents", []),
        ))
    return data.get("tenant", "(unknown)"), identities


def scan(identities, config=None):
    """Run every rule and return a flat list of Findings."""
    config = config or {}
    findings = []
    for identity in identities:
        for rule in PER_IDENTITY_RULES:
            findings.extend(rule(identity))
    findings.extend(op2_ga_sprawl(identities, config.get("ga_max", 5)))
    return findings


def identity_tiers(findings):
    """Map identity_id -> worst severity seen (its aggregate risk tier)."""
    worst = {}
    for f in findings:
        if f.identity_id not in worst or SEV_ORDER[f.severity] > SEV_ORDER[worst[f.identity_id]]:
            worst[f.identity_id] = f.severity
    return worst
