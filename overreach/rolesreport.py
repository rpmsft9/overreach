"""roles-report: the flat "every role -> everyone assigned to it" view.

The report Azure makes you assemble yourself. For each role it lists every
assignee with the two things the native portal views blur: whether the
assignment is **active** (standing) or **eligible** (PIM), and whether it is
**direct** or inherited **via a group**. Privileged roles are surfaced first.

It reports whatever the inventory contains: eligible/active is always resolved;
via-group is resolved when the collector populated it (group-nesting expansion in
the live collector is a roadmap item, so today it is fullest from a supplied
inventory).
"""

import csv
import io
import json
from collections import OrderedDict

from .roles_catalog import is_privileged, role_tier

_TIER_ORDER = {"tier0": 0, "privileged": 1, "standard": 2}


def build(identities):
    """Flatten identities into one row per (role, assignee) assignment."""
    rows = []
    for identity in identities:
        for ra in identity.role_assignments:
            rows.append({
                "role": ra.role,
                "tier": role_tier(ra.role),
                "privileged": is_privileged(ra.role),
                "assignee": identity.upn or identity.id,
                "assignee_id": identity.id,
                "assignment": ra.assignment,
                "via": ra.via,
                "scope": ra.scope,
                "type": identity.type,
            })
    return rows


def _sorted(rows):
    return sorted(rows, key=lambda r: (_TIER_ORDER.get(r["tier"], 9), r["role"],
                                       r["assignment"], r["assignee"]))


def _by_role(rows):
    grouped = OrderedDict()
    for r in _sorted(rows):
        grouped.setdefault(r["role"], []).append(r)
    return grouped


def to_markdown(tenant, rows):
    grouped = _by_role(rows)
    lines = [
        "# overreach - role assignment report",
        "",
        f"**Tenant:** {tenant}  ",
        f"**Roles:** {len(grouped)}  ",
        f"**Assignments:** {len(rows)}",
        "",
    ]
    for role, rs in grouped.items():
        tag = " _(privileged)_" if rs[0]["privileged"] else ""
        lines += [f"## {role}{tag} - {len(rs)} assigned", "",
                  "| Assignee | Assignment | Via | Scope | Type |",
                  "|---|---|---|---|---|"]
        for r in rs:
            lines.append(f"| {r['assignee']} | {r['assignment']} | {r['via']} | {r['scope']} | {r['type']} |")
        lines.append("")
    return "\n".join(lines)


def to_json(tenant, rows):
    grouped = _by_role(rows)
    roles = []
    for role, rs in grouped.items():
        roles.append({
            "role": role,
            "tier": rs[0]["tier"],
            "privileged": rs[0]["privileged"],
            "assigned_count": len(rs),
            "assignees": [{k: r[k] for k in ("assignee", "assignee_id", "assignment", "via", "scope", "type")}
                          for r in rs],
        })
    return json.dumps({"tenant": tenant, "roles": roles}, indent=2)


def to_csv(tenant, rows):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["role", "tier", "privileged", "assignee", "assignee_id", "assignment", "via", "scope", "type"])
    for r in _sorted(rows):
        w.writerow([r["role"], r["tier"], r["privileged"], r["assignee"], r["assignee_id"],
                    r["assignment"], r["via"], r["scope"], r["type"]])
    return out.getvalue().rstrip("\n")
