"""Read-only Microsoft Graph collector (best-effort MVP).

Builds the inventory JSON that `overreach scan` consumes. It is strictly
READ-ONLY and should be run only against a tenant you are authorized to audit.

Auth: reuses an access token from the Azure CLI, so you sign in with your own
account and least-privilege is enforced by what you consent to. Required
delegated scopes (read-only):
    Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All

What it populates today:
    - users (id, upn, display name, enabled, guest, last sign-in)
    - active (standing) directory-role assignments  -> assignment="active"
    - eligible (PIM) directory-role assignments      -> assignment="eligible"
    - MFA registration state (userRegistrationDetails)

Documented TODOs (kept honest):
    - Resolve role assignments whose principal is a GROUP into their transitive
      members, tagging via="group:<name>" so OP5 fires on real tenants.
    - Populate owned_apps / owned_agents for the OP6 bridge (reuse nhi-scan's
      Entra app/owner collector).
Until then OP5/OP6 still demonstrate fully from the fixture.
"""

import json
import subprocess
import urllib.error
import urllib.request

GRAPH = "https://graph.microsoft.com/v1.0"


class GraphError(RuntimeError):
    pass


def _token():
    try:
        out = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com",
             "--query", "accessToken", "-o", "tsv"],
            capture_output=True, text=True, check=True,
        )
        token = out.stdout.strip()
        if not token:
            raise GraphError("empty token from 'az account get-access-token'")
        return token
    except FileNotFoundError:
        raise GraphError("Azure CLI ('az') not found. Install it and run 'az login' first.")
    except subprocess.CalledProcessError as e:
        raise GraphError(f"'az account get-access-token' failed: {e.stderr.strip()}")


def _get_all(path, token):
    """GET a Graph collection, following @odata.nextLink. Returns list of items."""
    url = f"{GRAPH}{path}"
    items = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise GraphError(f"GET {url} -> HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:300]}")
        items.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return items


def gather():
    """Return the inventory as a JSON string."""
    token = _token()

    org = _get_all("/organization", token)
    tenant = (org[0].get("verifiedDomains", [{}])[0].get("name") if org else None) or "(tenant)"

    # Users (least-privilege select). signInActivity needs Entra ID P1 + AuditLog.Read.All.
    users = _get_all(
        "/users?$select=id,userPrincipalName,displayName,accountEnabled,userType,signInActivity&$top=999",
        token,
    )
    by_id = {}
    for u in users:
        by_id[u["id"]] = {
            "id": u["id"],
            "upn": u.get("userPrincipalName", ""),
            "display_name": u.get("displayName", ""),
            "type": "human",
            "enabled": bool(u.get("accountEnabled", True)),
            "is_guest": u.get("userType") == "Guest",
            "last_sign_in_days": _days_since(u.get("signInActivity", {}).get("lastSignInDateTime")),
            "mfa_registered": True,   # overwritten below if we can read it
            "role_assignments": [],
            "owned_apps": [],
            "owned_agents": [],
        }

    # MFA registration state (best-effort; needs the right scope/licence).
    try:
        for d in _get_all("/reports/authenticationMethods/userRegistrationDetails?$top=999", token):
            rec = by_id.get(d.get("id"))
            if rec is not None:
                rec["mfa_registered"] = bool(d.get("isMfaRegistered", False))
    except GraphError:
        pass  # leave default; note in output that MFA was not read

    # Active (standing) role assignments.
    _attach_roles(
        "/roleManagement/directory/roleAssignmentScheduleInstances?$expand=roleDefinition,principal&$top=999",
        token, by_id, assignment="active")
    # Eligible (PIM) role assignments.
    _attach_roles(
        "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition,principal&$top=999",
        token, by_id, assignment="eligible")

    identities = [r for r in by_id.values() if r["role_assignments"]]  # keep it focused on identities that hold roles
    return json.dumps({"tenant": tenant, "identities": identities}, indent=2)


def _attach_roles(path, token, by_id, assignment):
    try:
        rows = _get_all(path, token)
    except GraphError:
        return  # endpoint may be unavailable without PIM; skip
    for row in rows:
        principal = row.get("principal") or {}
        role = (row.get("roleDefinition") or {}).get("displayName", "")
        pid = principal.get("id")
        otype = principal.get("@odata.type", "")
        if pid in by_id and role:
            by_id[pid]["role_assignments"].append({
                "role": role,
                "assignment": assignment,
                "scope": row.get("directoryScopeId", "/"),
                "via": "direct",
            })
        # NOTE: if principal is a group (#microsoft.graph.group), expand transitiveMembers
        # and attach via="group:<name>" so OP5 fires. TODO for M3+.


def _days_since(iso):
    if not iso:
        return None
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None
