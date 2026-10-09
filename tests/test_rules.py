import os

from overreach import engine
from overreach.models import Identity, OwnedApp, RoleAssignment
from overreach import rules

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-tenant.json")


def _rules_hit(findings, upn):
    return {f.rule for f in findings if f.identity_upn == upn}


def test_fixture_scan_shapes():
    tenant, identities = engine.load_inventory(FIXTURE)
    findings = engine.scan(identities, {"ga_max": 5})
    # OP2 (tenant): 6 GA holders > 5 -> sprawl fires exactly once.
    assert sum(1 for f in findings if f.rule == "OP2") == 1
    # bob: standing GA + dormant + no MFA
    assert _rules_hit(findings, "bob@contoso.com") == {"OP1", "OP3", "OP4"}
    # carol: standing priv role inherited via a group
    assert _rules_hit(findings, "carol@contoso.com") == {"OP1", "OP5"}
    # dave: standing tier0 role that flows into an agent
    assert _rules_hit(findings, "dave@contoso.com") == {"OP1", "OP6"}
    # heidi: never signed in, holds a privileged role
    assert "OP3" in _rules_hit(findings, "heidi@contoso.com")
    # grace: eligible-only, MFA, recent -> clean
    assert _rules_hit(findings, "grace@contoso.com") == set()


def test_op1_only_fires_on_active():
    eligible = Identity(id="x", upn="x@c", role_assignments=[RoleAssignment("Global Administrator", "eligible")])
    active = Identity(id="y", upn="y@c", role_assignments=[RoleAssignment("Global Administrator", "active")])
    assert rules.op1_standing(eligible) == []
    assert len(rules.op1_standing(active)) == 1
    assert rules.op1_standing(active)[0].severity == "critical"


def test_op4_is_flagged_amplifier():
    ident = Identity(id="z", upn="z@c", mfa_registered=False,
                     role_assignments=[RoleAssignment("User Administrator", "active")])
    out = rules.op4_weak_auth(ident)
    assert out and out[0].amplifier is True


def test_op6_requires_human_and_obo():
    human = Identity(id="h", upn="h@c", type="human",
                     role_assignments=[RoleAssignment("User Administrator", "active")],
                     owned_apps=[OwnedApp("a1", "agent-x", obo_capable=True)])
    assert len(rules.op6_agent_bridge(human)) == 1
    no_obo = Identity(id="h2", upn="h2@c", type="human",
                      role_assignments=[RoleAssignment("User Administrator", "active")],
                      owned_apps=[OwnedApp("a2", "plain-app", obo_capable=False)])
    assert rules.op6_agent_bridge(no_obo) == []
