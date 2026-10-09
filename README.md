# overreach

**Audit Microsoft Entra ID for over-permissioned human identities — deterministic, explainable, read-only.**

`overreach` finds humans who hold more privilege than they need, right-sizes them with
evidence, and flags the ones whose over-privilege flows into **AI agents**. It is the
human-identity companion to [nhi-scan](https://github.com/rpmsft9/nhi-scan) (non-human &
agent identities): nhi-scan owns the machines, `overreach` owns the people, and they
join at the OBO bridge (OP6).

No LLM in the verdict path. Every finding records its evidence and a confidence level.

## Quickstart (30 seconds, no tenant needed)

```bash
python -m overreach.cli scan --input fixtures/sample-tenant.json
```

That runs against a synthetic directory, so you can see the output offline. JSON too:

```bash
python -m overreach.cli scan --input fixtures/sample-tenant.json --format json
```

Against a real tenant (read-only; see **Safety**):

```bash
az login
python -m overreach.cli inventory --out inv.json
python -m overreach.cli scan --input inv.json
```

## The methodology (why this is more than a checkbox)

"Over-privileged" means *holds more than they need* — and **"need" has no ground truth**.
There is no authoritative record of what each person's job requires. So `overreach` does
not pretend to a verdict. It **triangulates over-privilege from signals**, each with a
stated confidence, and presents **candidates for review with evidence**. The tool narrows
the haystack and shows its work; a human access review confirms "needed or not".

The backbone is deterministic signals that need **no model of need**:

| ID | Check | Signal | Confidence |
|----|-------|--------|-----------|
| **OP1** | Standing privileged role | A privileged role held as a permanent **active** assignment that should be **PIM-eligible** (on-demand). Over-privileged *in time*. | high |
| **OP2** | Global Admin sprawl | More Global Administrators than the recommended minimum (~5). | high |
| **OP3** | Dormant privileged account | Holds privilege but hasn't signed in (unused privilege = not needed now). The MVP proxy for usage-based right-sizing. | high |
| **OP4** | Privileged without MFA | **Amplifier** — raises the *danger* of over-privilege, not the privilege itself. | high |
| **OP5** | Hidden admin via nesting | Privilege inherited indirectly through a group, easy to miss in a native role view. | high |
| **OP6** | Privilege → agent bridge | A privileged human who owns/sponsors an **OBO-capable** app or agent: the agent inherits the user's entitlements, so human over-privilege becomes agent blast radius. *The differentiator.* | high |

Design principles:
- **Lean on signals that don't require knowing "need"** (standing, nesting, dormancy, sprawl).
- **Label amplifiers honestly** (OP4) so findings aren't overstated.
- **Never claim a verdict you can't evidence.**

## Roadmap

- **Usage-based right-sizing** — the strongest signal of all: compare *granted* vs.
  *actually-used* permissions from the directory audit log. Needs per-action telemetry;
  strong for Azure RBAC (cf. Entra Permissions Management), weaker-but-usable for
  directory roles. OP3 (dormancy) is the MVP proxy.
- **Group-nesting resolution in the collector** so OP5 fires on real tenants (today it
  resolves fully from a supplied inventory; the live collector marks it as a TODO).
- **Peer baselining** — flag users with far more entitlement than functional peers.
- **Unified report** merging `overreach` (human) and `nhi-scan` (non-human) output.

## Safety

- **Read-only.** `overreach` never writes to your directory.
- **Authorized tenants only.** Run it against your own tenant, or one you have explicit
  written permission to audit. Never point it at someone else's directory.
- **Least-privilege scopes.** The collector needs only `Directory.Read.All`,
  `RoleManagement.Read.Directory`, and `AuditLog.Read.All`, via your own `az login`.

## Status

Alpha (v0.1.0). The offline `scan` path and all six checks are implemented and tested;
the Graph collector is a best-effort MVP (see `collect_graph.py` TODOs).
