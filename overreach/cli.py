"""overreach command-line interface.

    overreach scan --input fixtures/sample-tenant.json        # offline, no tenant needed
    overreach scan --input inv.json --format json
    overreach inventory --out inv.json                         # read-only gather from Graph (needs az login)
"""

import argparse
import sys

from . import engine, report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="overreach",
        description="Audit Microsoft Entra ID for over-permissioned human identities (read-only).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan an inventory JSON and report over-privilege findings.")
    s.add_argument("--input", required=True, help="Path to an inventory JSON (see fixtures/).")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("--ga-max", type=int, default=5, help="Max Global Admins before OP2 fires (default 5).")

    g = sub.add_parser("inventory", help="Gather a read-only inventory from Microsoft Graph.")
    g.add_argument("--out", required=True, help="Where to write the inventory JSON.")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        tenant, identities = engine.load_inventory(args.input)
        findings = engine.scan(identities, {"ga_max": args.ga_max})
        out = report.to_markdown(tenant, findings) if args.format == "md" else report.to_json(tenant, findings)
        print(out)
        return 0

    if args.cmd == "inventory":
        from . import collect_graph
        try:
            data = collect_graph.gather()
        except collect_graph.GraphError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(data)
        print(f"wrote {args.out}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
