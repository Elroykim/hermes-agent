#!/usr/bin/env python3
"""Capture immutable Git candidate provenance without touching runtime state."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    payload = {
        "schema_version": "thewon-p0-r6-prestate/v1",
        "base_commit": _git(repo, "rev-parse", args.base),
        "base_tree": _git(repo, "rev-parse", f"{args.base}^{{tree}}"),
        "head_commit": _git(repo, "rev-parse", "HEAD"),
        "head_tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "worktree_clean": not bool(_git(repo, "status", "--porcelain=v1")),
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
