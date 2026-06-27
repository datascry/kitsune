# fleet/skulk/cli — the `skulk` command: list/describe strategies, run a fleet against an AUTHORIZED target.
# Prints the ethics banner + the fleet shape + Skulk's coordination self-assessment; --dry-run never emits.

from __future__ import annotations

import argparse
import sys

from . import strategies as _strategies  # noqa: F401 - import registers the built-in strategies
from .grade import assess
from .runner import run
from .scope import AuthorizationError, Scope
from .strategy import all_strategies, get

_BANNER = (
    "Skulk — fleet adversary-emulation for testing bot-detection coordination defenses.\n"
    "AUTHORIZED USE ONLY: point it at infrastructure you OWN or have written authorization to test. It emits\n"
    "benign coordination-shaped sessions to a detector's ingest surface — it is not a flood/DoS or credential tool."
)


def _cmd_list(_: argparse.Namespace) -> int:
    print(_BANNER + "\n\nstrategies:")
    for s in all_strategies():
        print(f"  {s.name:14} {s.summary}")
    return 0


def _cmd_describe(args: argparse.Namespace) -> int:
    s = get(args.strategy)
    members = s.members(args.nodes, args.seed)
    print(f"{s.name}: {s.summary}\n\n{args.nodes} members (seed {args.seed}):")
    for m in members:
        print(f"  {m.node_id:10} ip={m.observed_ip:14} fp={m.fp_hash} trace={m.trace_hash} auto={m.automation}")
    a = assess(members)
    verdict = "DETECTABLE" if a.detectable else "EVADES"
    print(f"\ncoordination self-assessment: {verdict} ({a.signal})\n  {a.detail}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scope = Scope(affirmed=args.i_am_authorized)
    for h in args.authorize or []:
        scope.authorize_host(h)
    for c in args.authorize_cidr or []:
        scope.authorize_network(c)
    s = get(args.strategy)
    try:
        result = run(
            target=args.target, strategy=s, nodes=args.nodes, seed=args.seed, scope=scope, dry_run=args.dry_run
        )
    except AuthorizationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    verb = "would emit (dry-run)" if args.dry_run else "emitted"
    print(_BANNER)
    print(f"\n{verb} a `{s.name}` fleet of {args.nodes} → {result.host} (seed {args.seed})")
    for m, sid in zip(result.members, result.session_ids, strict=True):
        print(f"  {sid:28} ip={m.observed_ip:14} fp={m.fp_hash} trace={m.trace_hash}")
    a = assess(result.members)
    print(f"\ncoordination self-assessment: {'DETECTABLE' if a.detectable else 'EVADES'} — {a.detail}")
    if not args.dry_run:
        print("\ngrade it on the target's own coordination view (Kitsune: `task coordination-live`).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skulk", description="Fleet adversary-emulation for coordination-defense testing.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list the fleet strategies").set_defaults(func=_cmd_list)

    d = sub.add_parser("describe", help="show a strategy's generated fleet shape (no emission)")
    d.add_argument("strategy")
    d.add_argument("-n", "--nodes", type=int, default=3)
    d.add_argument("--seed", type=int, default=1)
    d.set_defaults(func=_cmd_describe)

    r = sub.add_parser("run", help="emit a fleet against an AUTHORIZED target detector")
    r.add_argument("strategy")
    r.add_argument("--target", required=True, help="target detector base URL (must be in the authorized scope)")
    r.add_argument("-n", "--nodes", type=int, default=3)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--authorize", action="append", metavar="HOST", help="add an authorized target host (repeatable)")
    r.add_argument("--authorize-cidr", action="append", metavar="CIDR", help="add an authorized target network")
    r.add_argument("--i-am-authorized", action="store_true", help="affirm you are authorized to test the added targets")
    r.add_argument("--dry-run", action="store_true", help="generate + show the fleet but emit nothing")
    r.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
