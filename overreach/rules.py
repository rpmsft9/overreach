"""The over-privilege checks (OP1..OP6).

Design notes (the methodology that matters):
- "Over-privileged" has no ground truth for human "need", so each rule is a
  *signal* with a stated confidence, not an absolute verdict. The tool narrows
  the haystack and shows its work; a human access review confirms "needed or not".
- The backbone is deterministic signals that need NO model of need: standing-when-
  eligible (OP1), hidden/accumulated privilege (OP5), dormancy (OP3), GA sprawl (OP2).
- OP4 is labelled an *amplifier*: it makes over-privilege more dangerous (privileged
  + no MFA), it is not itself "too much access".
- OP6 is the differentiator: a human's privilege flows into agents via OAuth OBO /
  app ownership, so human over-privilege is upstream of agent blast radius.
- Usage-based right-sizing (granted vs. actually-used permissions) is the strongest
  signal of all but needs per-action telemetry; dormancy (OP3) is the MVP proxy.
  See README "Roadmap".
"""

from .models import Finding
from .roles_catalog import role_tier, is_privileged

DORMANT_DAYS = 45
GA_MAX = 5


def _priv_assignments(identity):
    return [ra for ra in identity.role_assignments if is_privileged(ra.role)]


def op1_standing(identity):
    """OP1 - privileged role held as a standing ACTIVE assignment (should be PIM-eligible)."""
    out = []
    for ra in identity.role_assignments:
        if is_privileged(ra.role) and ra.assignment == "active":
            tier = role_tier(ra.role)
            out.append(Finding(
                rule="OP1",
                title="Standing privileged role (should be PIM-eligible)",
                identity_id=identity.id, identity_upn=identity.upn,
                severity="critical" if tier == "tier0" else "high",
                confidence="high", amplifier=False,
                evidence=f"Holds '{ra.role}' as a standing ACTIVE assignment "
                         f"(scope {ra.scope}, via {ra.via}) - available 24/7, not on demand.",
                remediation=f"Convert '{ra.role}' to PIM-eligible (activate just-in-time) or remove if unneeded.",
            ))
    return out


def op3_dormant(identity, dormant_days=DORMANT_DAYS):
    """OP3 - account holds privilege but is dormant (unused privilege = not needed now)."""
    if not identity.enabled:
        return []
    priv = _priv_assignments(identity)
    if not priv:
        return []
    d = identity.last_sign_in_days
    if d is None or d > dormant_days:
        when = "has never signed in" if d is None else f"has not signed in for {d} days"
        roles = ", ".join(sorted({ra.role for ra in priv}))
        tier = "tier0" if any(role_tier(ra.role) == "tier0" for ra in priv) else "privileged"
        return [Finding(
            rule="OP3",
            title="Dormant privileged account",
            identity_id=identity.id, identity_upn=identity.upn,
            severity="critical" if tier == "tier0" else "high",
            confidence="high", amplifier=False,
            evidence=f"Holds privileged role(s) [{roles}] but {when}.",
            remediation="Remove the privileged role(s) from this dormant account, or disable the account.",
        )]
    return []


def op4_weak_auth(identity):
    """OP4 - privileged account without MFA. Amplifier: raises the danger, not the privilege."""
    priv = _priv_assignments(identity)
    if priv and not identity.mfa_registered:
        roles = ", ".join(sorted({ra.role for ra in priv}))
        return [Finding(
            rule="OP4",
            title="Privileged account without MFA (risk amplifier)",
            identity_id=identity.id, identity_upn=identity.upn,
            severity="high", confidence="high", amplifier=True,
            evidence=f"Holds privileged role(s) [{roles}] but has no MFA registered.",
            remediation="Require phishing-resistant MFA for this account via Conditional Access.",
        )]
    return []


def op5_nested(identity):
    """OP5 - privilege inherited indirectly through a group (hidden admin)."""
    out = []
    for ra in identity.role_assignments:
        if is_privileged(ra.role) and ra.via.startswith("group:"):
            out.append(Finding(
                rule="OP5",
                title="Hidden admin via group nesting",
                identity_id=identity.id, identity_upn=identity.upn,
                severity="high" if role_tier(ra.role) == "tier0" else "medium",
                confidence="high", amplifier=False,
                evidence=f"Inherits '{ra.role}' indirectly through {ra.via}, not a direct assignment - "
                         f"easy to miss in a native role view.",
                remediation="Make privileged access direct and reviewable; avoid granting admin roles via nested groups.",
            ))
    return out


def op6_agent_bridge(identity):
    """OP6 - a privileged human whose reach flows into agents via OBO / ownership (the differentiator)."""
    if identity.type != "human":
        return []
    priv = _priv_assignments(identity)
    if not priv:
        return []
    obo_apps = [a for a in identity.owned_apps if getattr(a, "obo_capable", False)]
    agents = list(identity.owned_agents)
    if obo_apps or agents:
        roles = ", ".join(sorted({ra.role for ra in priv}))
        inherited = ", ".join([a.name or a.app_id for a in obo_apps] + agents)
        return [Finding(
            rule="OP6",
            title="Privileged user whose reach flows into agents (OBO / ownership)",
            identity_id=identity.id, identity_upn=identity.upn,
            severity="high", confidence="high", amplifier=False,
            evidence=f"Privileged [{roles}] and owns/sponsors OBO-capable app(s)/agent(s): {inherited}. "
                     f"An agent acting on-behalf-of this user can inherit this entitlement - the user's "
                     f"over-privilege becomes the agent's blast radius.",
            remediation="Right-size the human's privilege first; ensure agents use least-privilege scoped tokens, "
                        "not the full user entitlement. Cross-check the agents with nhi-scan (OWASP NHI5).",
        )]
    return []


# Rules evaluated per identity.
PER_IDENTITY_RULES = [op1_standing, op3_dormant, op4_weak_auth, op5_nested, op6_agent_bridge]


def op2_ga_sprawl(identities, ga_max=GA_MAX):
    """OP2 - tenant-level: too many Global Administrators (recommended max ~5)."""
    gas = [i for i in identities
           if any(ra.role == "Global Administrator" for ra in i.role_assignments)]
    if len(gas) > ga_max:
        names = ", ".join(sorted(i.upn for i in gas))
        return [Finding(
            rule="OP2",
            title="Global Administrator sprawl",
            identity_id="(tenant)", identity_upn="(tenant)",
            severity="high", confidence="high", amplifier=False,
            evidence=f"{len(gas)} identities hold Global Administrator (recommended max ~{ga_max}): {names}.",
            remediation="Reduce Global Admins to the minimum; use least-privileged roles plus a small number "
                        "of PIM-eligible break-glass accounts.",
        )]
    return []
