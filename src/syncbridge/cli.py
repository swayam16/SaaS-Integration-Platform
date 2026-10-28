"""`syncbridge <command>`

syncbridge chaos [--cases N] [--seed S] [--baseline]   failure test, writes reports/
syncbridge dev [--port 8080]                           local stack: API + console + simulators
syncbridge scim-token                                  new SCIM bearer token and its SHA-256
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from dataclasses import asdict
from pathlib import Path


def cmd_chaos(args) -> None:
    from .sim.harness import ChaosConfig, run_chaos
    from .sim.report import markdown

    cfg = ChaosConfig(cases=args.cases, seed=args.seed)
    if args.cases < 2000:  # keep the activity dense enough for small runs
        cfg.duration = max(300.0, args.cases * 0.18)
        cfg.slack_outage = (cfg.duration * 0.33, cfg.duration * 0.33 + 180)
        cfg.salesforce_outage = (cfg.duration * 0.66, cfg.duration * 0.66 + 90)
    print(f"running failure test: {cfg.cases} cases, seed {cfg.seed}", file=sys.stderr)
    main = run_chaos(cfg)
    naive = None
    if args.baseline:
        print("running naive baseline with the same faults", file=sys.stderr)
        naive = run_chaos(ChaosConfig(**{**asdict(cfg), "naive": True}))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = {"main": asdict(main), "naive": asdict(naive) if naive else None}
    (out / "chaos_report.json").write_text(json.dumps(data, indent=2))
    (out / "chaos_report.md").write_text(markdown(main, naive))
    print(
        json.dumps({"records_synced": main.records["total_records_synced"], **main.audit}, indent=2)
    )
    if args.strict:
        bad = {k: v for k, v in main.audit.items() if v}
        if bad:
            print(f"FAILED: {bad}", file=sys.stderr)
            sys.exit(1)


def cmd_dev(args) -> None:
    from .devserver import serve

    serve(args.port)


def cmd_scim_token(args) -> None:
    from .crypto import sha256_hex

    token = secrets.token_urlsafe(32)
    print(json.dumps({"token": token, "SCIM_TOKEN_SHA256": sha256_hex(token)}, indent=2))


def main() -> None:
    p = argparse.ArgumentParser(prog="syncbridge")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chaos", help="run the failure-injection test")
    c.add_argument("--cases", type=int, default=10_000)
    c.add_argument("--seed", type=int, default=7)
    c.add_argument("--baseline", action="store_true", help="also run the naive baseline")
    c.add_argument("--strict", action="store_true", help="exit 1 on any duplicate or mismatch")
    c.add_argument("--out", default="reports")
    d = sub.add_parser("dev", help="run the local stack")
    d.add_argument("--port", type=int, default=8080)
    sub.add_parser("scim-token", help="generate a SCIM bearer token")
    args = p.parse_args()
    {"chaos": cmd_chaos, "dev": cmd_dev, "scim-token": cmd_scim_token}[args.cmd](args)


if __name__ == "__main__":
    main()
