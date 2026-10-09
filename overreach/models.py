"""Data model for an identity inventory and the findings produced from it.

The shapes here mirror the inventory JSON (see fixtures/sample-tenant.json) so
a scan runs the same whether the data came from the Graph collector or a file.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RoleAssignment:
    role: str
    assignment: str = "active"   # "active" (standing) | "eligible" (PIM)
    scope: str = "/"             # "/" = tenant-wide; otherwise an admin-unit / resource scope
    via: str = "direct"          # "direct" | "group:<group name>"


@dataclass
class OwnedApp:
    app_id: str
    name: str = ""
    obo_capable: bool = False    # app can act on-behalf-of the user (OAuth OBO)


@dataclass
class Identity:
    id: str
    upn: str
    display_name: str = ""
    type: str = "human"          # "human" | "agent" (agents are nhi-scan's job; kept for the OP6 bridge)
    enabled: bool = True
    last_sign_in_days: Optional[int] = None  # days since last sign-in; None = never / unknown
    mfa_registered: bool = True
    is_guest: bool = False
    role_assignments: list = field(default_factory=list)  # list[RoleAssignment]
    owned_apps: list = field(default_factory=list)        # list[OwnedApp]
    owned_agents: list = field(default_factory=list)      # list[str] (agent display names / ids)


@dataclass
class Finding:
    rule: str          # "OP1".."OP6", or "DCSPM-*" for Defender CSPM-sourced findings
    title: str
    identity_id: str
    identity_upn: str
    severity: str      # "critical" | "high" | "medium" | "low"
    confidence: str    # "high" | "medium" | "low"
    amplifier: bool    # True = raises the danger of over-privilege, not over-privilege itself
    evidence: str
    remediation: str
    source: str = "native"   # "native" (overreach's own checks on Entra directory roles)
                             # | "defender-cspm" (resource/RBAC-plane CIEM recommendation)
