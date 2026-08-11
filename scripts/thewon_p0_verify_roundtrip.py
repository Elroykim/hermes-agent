#!/usr/bin/env python3
"""Verify offline P0 captured evidence with strict duplicate-key parsing."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from hermes_cli.thewon_p0_evidence import EvidenceContractError, RoundtripContract, load_strict_json_document, verify_roundtrip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--thread", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = load_strict_json_document(args.contract)
        thread = load_strict_json_document(args.thread)
        evidence = load_strict_json_document(args.evidence)
        if not isinstance(contract, dict) or not isinstance(thread, list) or not isinstance(evidence, dict):
            raise EvidenceContractError("contract, thread, and evidence have invalid top-level shapes")
        print(json.dumps(asdict(verify_roundtrip(RoundtripContract(**contract), thread, evidence)), sort_keys=True))
    except (EvidenceContractError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
