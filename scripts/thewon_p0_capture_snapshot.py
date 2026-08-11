#!/usr/bin/env python3
"""Read-only Git pre-state snapshot for an external P0 packet."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({"captured_at": datetime.now(timezone.utc).isoformat(), "head": _git(args.repo, "rev-parse", "HEAD"), "tree": _git(args.repo, "rev-parse", "HEAD^{tree}"), "status_porcelain": _git(args.repo, "status", "--porcelain=v1")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
