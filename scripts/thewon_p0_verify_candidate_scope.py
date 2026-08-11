#!/usr/bin/env python3
"""Compare a committed candidate diff with its manifest and ledger leases."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from hermes_cli.thewon_p0_candidate_scope import CandidateScopeError, verify_candidate_scope


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateScopeError(f"cannot load {path}") from exc


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    try:
        actual = [line for line in _git(args.repo, "diff", "--name-only", args.base, "HEAD").splitlines() if line]
        manifest = _load(args.manifest)
        ledger = _load(args.ledger)
        if not isinstance(manifest, dict) or not isinstance(ledger, dict):
            raise CandidateScopeError("manifest and ledger must be objects")
        paths = verify_candidate_scope(actual_paths=actual, candidate={"declared_paths": manifest.get("declared_paths"), "ledger": ledger.get("lease_scope")})
        body = {"schema_version": "thewon-p0-r6-scope-report/v1", "base_commit": _git(args.repo, "rev-parse", args.base), "base_tree": _git(args.repo, "rev-parse", f"{args.base}^{{tree}}"), "candidate_commit": _git(args.repo, "rev-parse", "HEAD"), "candidate_tree": _git(args.repo, "rev-parse", "HEAD^{tree}"), "diff_paths": sorted(paths)}
        body["report_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        print(json.dumps(body, sort_keys=True, separators=(",", ":")))
    except (CandidateScopeError, OSError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
