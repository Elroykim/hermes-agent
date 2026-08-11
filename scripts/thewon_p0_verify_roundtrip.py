#!/usr/bin/env python3
"""Verify a captured TheWon agent roundtrip without accessing Slack secrets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from hermes_cli.thewon_p0_evidence import (
    EvidenceContractError,
    RoundtripContract,
    canonical_sha256,
    verify_roundtrip,
)


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"cannot load {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--thread", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        contract_value = _load(args.contract)
        thread = _load(args.thread)
        evidence = _load(args.evidence)
        if not isinstance(contract_value, dict) or not isinstance(thread, list) or not isinstance(evidence, dict):
            raise EvidenceContractError("contract/thread/evidence shapes are invalid")
        result = verify_roundtrip(RoundtripContract(**contract_value), thread, evidence)
        payload = {
            "schema_version": "thewon-p0-roundtrip-result/v1",
            "result": result.__dict__,
            "result_sha256": canonical_sha256(result.__dict__),
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        if args.output is None:
            print(encoded, end="")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
    except (EvidenceContractError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
