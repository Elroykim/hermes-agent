#!/usr/bin/env python3
"""Verify captured P0 Slack, workflow, and Blackbox evidence offline."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from hermes_cli.thewon_p0_evidence import EvidenceContractError, RoundtripContract, verify_roundtrip


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"cannot read {path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--thread", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = _load(args.contract)
        thread = _load(args.thread)
        evidence = _load(args.evidence)
        if not isinstance(contract, dict) or not isinstance(thread, list) or not isinstance(evidence, dict):
            raise EvidenceContractError("contract, thread, and evidence must have exact top-level shapes")
        print(json.dumps(asdict(verify_roundtrip(RoundtripContract(**contract), thread, evidence)), sort_keys=True))
    except (EvidenceContractError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
