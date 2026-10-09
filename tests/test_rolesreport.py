import json
import os

from overreach import engine, rolesreport

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample-tenant.json")


def _load():
    _, identities = engine.load_inventory(FIXTURE)
    return identities


def test_build_flattens_every_assignment():
    rows = rolesreport.build(_load())
    # Global Administrator has 6 assignees in the fixture (5 active + 1 eligible).
    ga = [r for r in rows if r["role"] == "Global Administrator"]
    assert len(ga) == 6
    assert {r["assignment"] for r in ga} == {"active", "eligible"}


def test_via_group_is_preserved():
    rows = rolesreport.build(_load())
    carol = [r for r in rows if r["assignee"] == "carol@contoso.com"][0]
    assert carol["role"] == "User Administrator"
    assert carol["via"] == "group:Helpdesk Admins"


def test_json_groups_by_role_with_counts():
    rows = rolesreport.build(_load())
    data = json.loads(rolesreport.to_json("contoso", rows))
    ga = [r for r in data["roles"] if r["role"] == "Global Administrator"][0]
    assert ga["assigned_count"] == 6
    assert ga["privileged"] is True


def test_csv_has_header_and_rows():
    rows = rolesreport.build(_load())
    csv_text = rolesreport.to_csv("contoso", rows)
    lines = csv_text.splitlines()
    assert lines[0] == "role,tier,privileged,assignee,assignee_id,assignment,via,scope,type"
    assert len(lines) - 1 == len(rows)
