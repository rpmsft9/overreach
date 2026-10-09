"""Defender CSPM (DCSPM) CIEM collector + mapping.

Microsoft retired Entra Permissions Management (ex-CloudKnox) as a standalone
product. Its CIEM analysis now surfaces as **Microsoft Defender CSPM
recommendations** that flag stale/unused and over-permissioned identities across
Azure (and AWS/GCP) *resource* permissions. That analysis is usage-based — it is
the gold-standard signal overreach's native checks only approximate (OP3 dormancy).

This module:
  1. `gather()`  — read-only pull of those recommendations from Azure Resource
     Graph (securityresources / Microsoft.Security assessments), normalized to a
     small JSON shape. Needs Defender CSPM enabled and an ARM token (az login).
  2. `load_findings(path)` — read a normalized DCSPM JSON (from gather() or the
     fixture) and map each recommendation to an overreach Finding, tagged
     source="defender-cspm" so the report keeps it distinct from directory-role
     findings.

Scope note: DCSPM covers resource / RBAC permissions; overreach's native checks
cover Entra directory roles. They are complementary — merge both for the full
picture across the directory plane and the resource plane.
"""

import json
import subprocess
import urllib.error
import urllib.request

from .models import Finding

ARM = "https://management.azure.com"

# The Defender CSPM CIEM recommendations we care about. Match on lowercased display name.
_ARG_QUERY = """
securityresources
| where type == "microsoft.security/assessments"
| extend displayName = tostring(properties.displayName),
         status = tostring(properties.status.code),
         severity = tostring(properties.metadata.severity),
         resourceId = tostring(properties.resourceDetails.Id)
| where status == "Unhealthy"
| where displayName has_any ("permission","permissions","identity","identities",
                             "unused","stale","inactive","overprovisioned",
                             "over-provisioned","super")
| project displayName, status, severity, resourceId,
          additionalData = tostring(properties.additionalData)
"""

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


class DcspmError(RuntimeError):
    pass


# --- gather (live, read-only) ------------------------------------------------

def _arm_token():
    try:
        out = subprocess.run(
            ["az", "account", "get-access-token", "--resource", ARM,
             "--query", "accessToken", "-o", "tsv"],
            capture_output=True, text=True, check=True,
        )
        token = out.stdout.strip()
        if not token:
            raise DcspmError("empty ARM token from 'az account get-access-token'")
        return token
    except FileNotFoundError:
        raise DcspmError("Azure CLI ('az') not found. Install it and run 'az login' first.")
    except subprocess.CalledProcessError as e:
        raise DcspmError(f"'az account get-access-token' failed: {e.stderr.strip()}")


def gather():
    """Return normalized DCSPM CIEM recommendations as a JSON string."""
    token = _arm_token()
    url = f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    assessments = []
    skip_token = None
    while True:
        options = {"resultFormat": "objectArray"}
        if skip_token:
            options["$skipToken"] = skip_token
        body = json.dumps({"query": _ARG_QUERY, "options": options}).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise DcspmError(f"Resource Graph query failed: HTTP {e.code}: "
                             f"{e.read().decode('utf-8', 'ignore')[:300]}")
        for row in payload.get("data", []):
            assessments.append(_normalize_row(row))
        skip_token = payload.get("$skipToken")
        if not skip_token:
            break
    return json.dumps({"source": "defender-cspm", "assessments": assessments}, indent=2)


def _normalize_row(row):
    """Map a raw Resource Graph assessment row to the normalized shape."""
    # The specific over-permissioned principal often lives in additionalData / sub-assessments;
    # we surface the resource and display name, and best-effort an identity if present. TODO: expand.
    return {
        "display_name": row.get("displayName", ""),
        "status": row.get("status", "Unhealthy"),
        "severity": (row.get("severity") or "Medium"),
        "identity": None,
        "identity_type": None,
        "resource_id": row.get("resourceId", ""),
        "remediation": "",
    }


# --- map normalized recommendations to findings (used offline + live) --------

def _classify(display_name):
    d = (display_name or "").lower()
    if "super" in d:
        return "DCSPM-SUPER", "Super identity (excessive resource permissions)"
    if "unused" in d:
        return "DCSPM-UNUSED", "Unused identity (resource permissions)"
    if "stale" in d or "inactive" in d:
        return "DCSPM-STALE", "Stale / inactive identity"
    if "overprovisioned" in d or "over-provisioned" in d or "necessary permissions" in d:
        return "DCSPM-OVERPROV", "Over-provisioned identity (resource permissions)"
    return "DCSPM", "Defender CSPM identity recommendation"


def _to_finding(rec):
    rule, title = _classify(rec.get("display_name", ""))
    sev = _SEV_MAP.get(str(rec.get("severity", "medium")).lower(), "medium")
    who = rec.get("identity") or rec.get("resource_id") or "(resource)"
    where = rec.get("resource_id", "")
    scope = f" on {where}" if where and rec.get("identity") else ""
    return Finding(
        rule=rule, title=title,
        identity_id=rec.get("identity") or rec.get("resource_id") or "(resource)",
        identity_upn=who,
        severity=sev, confidence="high", amplifier=False,
        evidence=f"Defender CSPM (usage-based): '{rec.get('display_name', '')}'{scope}.",
        remediation=rec.get("remediation")
                    or "Right-size the resource role assignments to the permissions actually used "
                       "(per the Defender CSPM recommendation).",
        source="defender-cspm",
    )


def findings_from_normalized(data):
    """Map a normalized DCSPM dict (as produced by gather()) to a list of Findings."""
    return [_to_finding(rec) for rec in data.get("assessments", [])]


def load_findings(path):
    """Read a normalized DCSPM JSON file and return a list of Findings."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return findings_from_normalized(data)
