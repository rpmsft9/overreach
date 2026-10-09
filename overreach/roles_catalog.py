"""Which Entra built-in directory roles count as privileged, and at what tier.

tier0  = identity/security control-plane roles: holding one means you can, directly
         or through a known escalation path (e.g. adding app credentials), take over
         the tenant. These get the highest severity.
privileged = broad administrative roles with real blast radius, below control-plane.

This is a curated starter set, not exhaustive. Entra also exposes an
`isPrivileged` flag on role definitions (roleManagement/directory/roleDefinitions);
the collector can populate from that to stay current - see collect_graph.py.
"""

TIER0_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Hybrid Identity Administrator",
    "Domain Name Administrator",
    "Partner Tier2 Support",
    # Escalation paths: both can add credentials to apps/SPs and act as them.
    "Application Administrator",
    "Cloud Application Administrator",
}

PRIVILEGED_ROLES = {
    "User Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Password Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator",
    "Teams Administrator",
    "Groups Administrator",
    "Billing Administrator",
    "Directory Writers",
    "Identity Governance Administrator",
}


def role_tier(role: str) -> str:
    if role in TIER0_ROLES:
        return "tier0"
    if role in PRIVILEGED_ROLES:
        return "privileged"
    return "standard"


def is_privileged(role: str) -> bool:
    return role_tier(role) in ("tier0", "privileged")
