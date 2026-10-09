from overreach import collect_graph as cg


def test_obo_capable_heuristic():
    obo_app = {"requiredResourceAccess": [{"resourceAccess": [{"type": "Scope", "id": "x"}]}]}
    app_only = {"requiredResourceAccess": [{"resourceAccess": [{"type": "Role", "id": "y"}]}]}
    none = {}
    assert cg._is_obo_capable(obo_app) is True
    assert cg._is_obo_capable(app_only) is False
    assert cg._is_obo_capable(none) is False


def test_attach_owned_apps_only_to_user_owners(monkeypatch):
    apps = [{
        "appId": "app-1", "displayName": "agent-refunds",
        "requiredResourceAccess": [{"resourceAccess": [{"type": "Scope"}]}],
        "owners": [
            {"@odata.type": "#microsoft.graph.user", "id": "u1"},
            {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1"},
        ],
    }]
    monkeypatch.setattr(cg, "_get_all", lambda path, token: apps)
    by_id = {"u1": {"owned_apps": []}, "sp1": {"owned_apps": []}}
    cg._attach_owned_apps("t", by_id)
    assert by_id["u1"]["owned_apps"] == [{"app_id": "app-1", "name": "agent-refunds", "obo_capable": True}]
    assert by_id["sp1"]["owned_apps"] == []   # service principal owner is not attributed as a human


def test_attach_agents_maps_owner_and_creator(monkeypatch):
    regs = [{"displayName": "agent-refunds-copilot", "ownerIds": ["u1"], "createdBy": "u2"}]
    monkeypatch.setattr(cg, "_get_all", lambda path, token, base=None: regs)
    by_id = {"u1": {"owned_agents": []}, "u2": {"owned_agents": []}, "u3": {"owned_agents": []}}
    cg._attach_agents("t", by_id)
    assert by_id["u1"]["owned_agents"] == ["agent-refunds-copilot"]
    assert by_id["u2"]["owned_agents"] == ["agent-refunds-copilot"]
    assert by_id["u3"]["owned_agents"] == []


def test_attach_agents_skips_when_unavailable(monkeypatch):
    def boom(path, token, base=None):
        raise cg.GraphError("404 preview not enabled")
    monkeypatch.setattr(cg, "_get_all", boom)
    by_id = {"u1": {"owned_agents": []}}
    cg._attach_agents("t", by_id)   # must not raise
    assert by_id["u1"]["owned_agents"] == []
