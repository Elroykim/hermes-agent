#!/usr/bin/env python3
"""Fail closed unless one candidate lease covers its exact committed Git diff."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from hermes_cli.thewon_p0_evidence import EvidenceContractError, canonical_sha256, validate_candidate_provenance


ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise EvidenceContractError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def _git_bytes(repo: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceContractError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _relative_path(repo: Path, path: Path) -> str:
    try:
        relative_path = path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceContractError(f"{path} is outside the candidate repository") from exc
    if not relative_path or relative_path.startswith("../") or "/../" in relative_path:
        raise EvidenceContractError(f"{path} is not a repository-relative path")
    return relative_path


def _json_file(repo: Path, revision: str, path: Path) -> tuple[str, dict[str, object], bytes]:
    relative_path = _relative_path(repo, path)
    raw = _git_bytes(repo, "show", f"{revision}:{relative_path}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"{relative_path} is not valid JSON at {revision}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceContractError(f"{relative_path} is not a JSON object at {revision}")
    return relative_path, value, raw


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise EvidenceContractError(f"{name} is not a lowercase SHA-256")
    return value


def _verify_artifacts(repo: Path, revision: str, manifest: dict[str, object]) -> list[dict[str, str]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise EvidenceContractError("candidate manifest artifacts are missing")
    verified: list[dict[str, str]] = []
    paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise EvidenceContractError("candidate artifact is malformed")
        path = artifact.get("path")
        if not isinstance(path, str):
            raise EvidenceContractError("candidate artifact path is malformed")
        relative_path = _relative_path(repo, repo / path)
        if relative_path != path or path in paths:
            raise EvidenceContractError("candidate artifact path is not canonical")
        paths.add(path)
        expected = _sha256(artifact.get("sha256"), "candidate artifact sha256")
        actual = hashlib.sha256(_git_bytes(repo, "show", f"{revision}:{path}")).hexdigest()
        if actual != expected:
            raise EvidenceContractError(f"candidate artifact hash mismatch: {path}")
        verified.append({"path": path, "sha256": actual})
    return verified


def _verify_transition_manifest_hashes(
    ledger: dict[str, object],
    *,
    issue_id: str,
    lease_id: str,
    manifest_path: str,
    manifest_sha256: str,
) -> None:
    issues = ledger.get("issues")
    if not isinstance(issues, dict) or not isinstance(issues.get(issue_id), dict):
        raise EvidenceContractError("candidate ledger issue is missing")
    transitions = issues[issue_id].get("transitions")
    if not isinstance(transitions, list):
        raise EvidenceContractError("candidate ledger transitions are malformed")
    required_states = {"candidate_bound", "audit_ready"}
    found_states: set[str] = set()
    for transition in transitions:
        if not isinstance(transition, dict) or transition.get("lease_id") != lease_id:
            continue
        state = transition.get("state")
        if state not in required_states:
            continue
        artifacts = transition.get("artifacts")
        if not isinstance(artifacts, list):
            raise EvidenceContractError("candidate ledger transition artifacts are malformed")
        matches = [
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("path") == manifest_path
        ]
        if len(matches) != 1 or matches[0].get("sha256") != manifest_sha256:
            raise EvidenceContractError("candidate ledger transition does not bind the final manifest hash")
        found_states.add(state)
    if found_states != required_states:
        raise EvidenceContractError("candidate ledger lacks terminal candidate-bound and audit-ready manifest receipts")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--issue-id", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    try:
        repo = args.repo.resolve()
        base_sha = _git(repo, "rev-parse", "--verify", f"{args.base_sha}^{{commit}}")
        head_sha = _git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}")
        changed_paths = tuple(
            line
            for line in _git(repo, "diff", "--name-only", "--no-renames", base_sha, head_sha).splitlines()
            if line
        )
        manifest_path, manifest, manifest_bytes = _json_file(repo, head_sha, args.manifest)
        _, ledger, _ = _json_file(repo, head_sha, args.ledger)
        validated = validate_candidate_provenance(
            manifest,
            ledger,
            issue_id=args.issue_id,
            changed_paths=changed_paths,
        )
        artifacts = _verify_artifacts(repo, head_sha, manifest)
        lease = manifest.get("candidate_lease")
        if not isinstance(lease, dict):
            raise EvidenceContractError("candidate lease is malformed")
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        _verify_transition_manifest_hashes(
            ledger,
            issue_id=args.issue_id,
            lease_id=str(lease.get("lease_id", "")),
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
        )
    except EvidenceContractError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "base_sha": base_sha,
                "candidate_commit": head_sha,
                "changed_paths": list(validated),
                "manifest_sha256": manifest_sha256,
                "artifacts": artifacts,
                "issue_id": args.issue_id,
                "provenance_sha256": canonical_sha256(
                    {
                        "artifacts": artifacts,
                        "base_sha": base_sha,
                        "candidate_commit": head_sha,
                        "changed_paths": list(validated),
                        "issue_id": args.issue_id,
                        "manifest_sha256": manifest_sha256,
                    }
                ),
                "status": "PASS",
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
