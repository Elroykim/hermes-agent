#!/usr/bin/env python3
"""Operate the Git-trackable TheWon P0 issue and evidence ledger."""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from hermes_cli.thewon_p0_evidence import EvidenceContractError, IssueLedger


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = ROOT / "docs" / "thewon" / "p0" / "evidence-ledger.json"


def _json(value: str, name: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise EvidenceContractError(f"{name} must be JSON: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show")
    open_issue = commands.add_parser("open")
    open_issue.add_argument("--issue-id", required=True)
    open_issue.add_argument("--owner-bac", required=True)
    open_issue.add_argument("--base-sha", required=True)
    open_issue.add_argument("--boundary", required=True, help="JSON array")
    open_issue.add_argument("--rollback", required=True)
    lease = commands.add_parser("lease")
    lease.add_argument("--issue-id", required=True)
    lease.add_argument("--owner-bac", required=True)
    lease.add_argument("--base-sha", required=True)
    lease.add_argument("--resources", required=True, help="JSON array")
    lease.add_argument("--ttl-seconds", type=int, default=900)
    release = commands.add_parser("release")
    release.add_argument("--issue-id", required=True)
    release.add_argument("--lease-id", required=True)
    renew = commands.add_parser("renew")
    renew.add_argument("--issue-id", required=True)
    renew.add_argument("--lease-id", required=True)
    renew.add_argument("--ttl-seconds", type=int, default=900)
    transition = commands.add_parser("transition")
    transition.add_argument("--issue-id", required=True)
    transition.add_argument("--lease-id", required=True)
    transition.add_argument("--state", required=True)
    transition.add_argument("--pre-state-digest", required=True)
    transition.add_argument("--artifacts", required=True, help="JSON array")
    transition.add_argument("--validation", required=True, help="JSON object")
    args = parser.parse_args()
    ledger = IssueLedger(args.ledger)
    try:
        if args.command == "show":
            result = ledger.read()
        elif args.command == "open":
            ledger.open_issue(
                issue_id=args.issue_id,
                owner_bac=args.owner_bac,
                base_sha=args.base_sha,
                mutation_boundary=_json(args.boundary, "boundary"),
                rollback=args.rollback,
            )
            result = ledger.read()
        elif args.command == "lease":
            result = ledger.acquire_lease(
                issue_id=args.issue_id,
                owner_bac=args.owner_bac,
                base_sha=args.base_sha,
                resources=_json(args.resources, "resources"),
                ttl=timedelta(seconds=args.ttl_seconds),
            ).__dict__
        elif args.command == "release":
            result = {"released_resources": ledger.release_lease(issue_id=args.issue_id, lease_id=args.lease_id)}
        elif args.command == "renew":
            result = ledger.renew_lease(
                issue_id=args.issue_id,
                lease_id=args.lease_id,
                ttl=timedelta(seconds=args.ttl_seconds),
            ).__dict__
        else:
            result = ledger.record_transition(
                issue_id=args.issue_id,
                lease_id=args.lease_id,
                state=args.state,
                pre_state_digest=args.pre_state_digest,
                artifacts=_json(args.artifacts, "artifacts"),
                validation=_json(args.validation, "validation"),
            )
    except EvidenceContractError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
