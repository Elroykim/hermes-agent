#!/usr/bin/env python3
"""Capture a read-only, hash-bound P0 pre-state snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hermes_cli.thewon_p0_evidence import canonical_sha256


def _run(*args: str) -> dict[str, object]:
    completed = subprocess.run(args, capture_output=True, check=False, text=True)
    return {
        "argv": list(args),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _file(path: Path) -> dict[str, object]:
    row: dict[str, object] = {"path": str(path)}
    try:
        stat = path.lstat()
        row.update({"exists": True, "mode": oct(stat.st_mode & 0o777), "size": stat.st_size})
        if path.is_file() and not path.is_symlink():
            row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            row["sha256"] = None
    except OSError as exc:
        row.update({"exists": False, "error": str(exc), "sha256": None})
    return row


def _docker() -> list[dict[str, object]]:
    result = _run("docker", "ps", "-a", "--format", "{{json .}}")
    if result["returncode"] != 0:
        return [{"error": result["stderr"]}]
    rows: list[dict[str, object]] = []
    for line in str(result["stdout"]).splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"unparsed": line})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--external-path", action="append", type=Path, default=[])
    parser.add_argument("--launchd-label", action="append", default=[])
    args = parser.parse_args()
    repo = args.repo.resolve()
    files = [repo / "scripts" / "thewon_p0_verify_roundtrip.py", *args.external_path]
    launchd = {label: _run("launchctl", "print", f"gui/{os.getuid()}/{label}") for label in args.launchd_label}
    snapshot: dict[str, Any] = {
        "schema_version": "thewon-p0-prestate-snapshot/v1",
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": {
            "path": str(repo),
            "head": _run("git", "-C", str(repo), "rev-parse", "HEAD"),
            "status": _run("git", "-C", str(repo), "status", "--porcelain=v1", "-b"),
            "remotes": _run("git", "-C", str(repo), "remote", "-v"),
        },
        "tracked_and_external_files": [_file(path) for path in files],
        "launchd": launchd,
        "processes": _run("pgrep", "-fl", "mina_review_hook|thewon_slack_named_agent_loop"),
        "containers": _docker(),
    }
    snapshot["snapshot_sha256"] = canonical_sha256(snapshot)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(args.output), "snapshot_sha256": snapshot["snapshot_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
