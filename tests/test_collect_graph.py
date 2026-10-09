from overreach import collect_graph as cg


def test_group_role_expands_to_transitive_members(monkeypatch):
    # One role assignment whose principal is a group; the group has two user members.
    assignment_rows = [{
        "principal": {"@odata.type": "#microsoft.graph.group", "id": "g-admins", "displayName": "Helpdesk Admins"},
        "roleDefinition": {"displayName": "User Administrator"},
        "directoryScopeId": "/",
    }]

    def fake_get_all(path, token):
        if "transitiveMembers" in path:
            return [{"id": "u1"}, {"id": "u2"}]
        return assignment_rows

    monkeypatch.setattr(cg, "_get_all", fake_get_all)

    by_id = {"u1": {"role_assignments": []}, "u2": {"role_assignments": []}, "u3": {"role_assignments": []}}
    cg._attach_roles("/roleAssignmentScheduleInstances", token="t", by_id=by_id,
                     assignment="active", group_cache={})

    assert by_id["u1"]["role_assignments"] == [
        {"role": "User Administrator", "assignment": "active", "scope": "/", "via": "group:Helpdesk Admins"}]
    assert by_id["u2"]["role_assignments"][0]["via"] == "group:Helpdesk Admins"
    assert by_id["u3"]["role_assignments"] == []   # not a member, untouched


def test_direct_user_assignment_tagged_direct(monkeypatch):
    rows = [{
        "principal": {"@odata.type": "#microsoft.graph.user", "id": "u1"},
        "roleDefinition": {"displayName": "Global Administrator"},
        "directoryScopeId": "/",
    }]
    monkeypatch.setattr(cg, "_get_all", lambda path, token: rows)
    by_id = {"u1": {"role_assignments": []}}
    cg._attach_roles("/x", "t", by_id, "active", {})
    assert by_id["u1"]["role_assignments"][0]["via"] == "direct"


def test_group_member_cache_avoids_refetch(monkeypatch):
    calls = {"n": 0}

    def fake_get_all(path, token):
        if "transitiveMembers" in path:
            calls["n"] += 1
            return [{"id": "u1"}]
        return []

    monkeypatch.setattr(cg, "_get_all", fake_get_all)
    cache = {}
    cg._group_user_members("g1", "t", cache)
    cg._group_user_members("g1", "t", cache)
    assert calls["n"] == 1   # second call served from cache
