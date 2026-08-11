"""Exact path-set checks for a candidate's declared mutation lease."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence


class CandidateScopeError(ValueError):
    """Candidate paths and resource leases do not describe the actual diff."""


@dataclass(frozen=True)
class LeaseClaim:
    """A Git-ledger lease claim supplied by the candidate issuer."""

    lease_id: str
    base_sha: str
    resources: tuple[str, ...]
    expires_at: str


def _utc_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateScopeError("lease expiry is malformed") from exc
    if parsed.tzinfo is None:
        raise CandidateScopeError("lease expiry must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _paths(value: object, name: str) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CandidateScopeError(f"{name} must be a path list")
    result: set[str] = set()
    for path in value:
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/") or any(token in path for token in ("*", "?", "[", "]")):
            raise CandidateScopeError(f"{name} has an invalid exact repository path")
        result.add(path)
    if len(result) != len(value) or not result:
        raise CandidateScopeError(f"{name} must be non-empty and unique")
    return result


def verify_candidate_scope(*, actual_paths: Sequence[str], candidate: Mapping[str, object]) -> set[str]:
    actual = _paths(actual_paths, "actual_paths")
    declared = _paths(candidate.get("declared_paths"), "declared_paths")
    ledger = candidate.get("ledger")
    if not isinstance(ledger, Mapping) or set(ledger) != {"mutation_boundary", "acquired_resources", "released_resources"}:
        raise CandidateScopeError("candidate ledger scope has an invalid exact schema")
    scopes = [
        _paths(ledger["mutation_boundary"], "mutation_boundary"),
        _paths(ledger["acquired_resources"], "acquired_resources"),
        _paths(ledger["released_resources"], "released_resources"),
    ]
    if any(paths != actual for paths in [declared, *scopes]):
        raise CandidateScopeError("actual diff, manifest, and every lease scope must be exactly equal")
    if "docs/thewon/p0/evidence-ledger.json" not in actual:
        raise CandidateScopeError("ledger mutation must itself be leased")
    return actual


def validate_lease_claim(*, expected_base_sha: str, requested: LeaseClaim, active: Sequence[LeaseClaim], now: datetime) -> None:
    """Reject base drift and overlap with unexpired claims before any mutation."""

    if requested.base_sha != expected_base_sha:
        raise CandidateScopeError("lease base SHA drift")
    requested_resources = _paths(requested.resources, "requested resources")
    if not requested.lease_id or _utc_time(requested.expires_at) <= now.astimezone(timezone.utc):
        raise CandidateScopeError("requested lease is invalid or expired")
    for claim in active:
        if claim.lease_id == requested.lease_id:
            raise CandidateScopeError("lease id must be unique")
        if _utc_time(claim.expires_at) <= now.astimezone(timezone.utc):
            continue
        if requested_resources & _paths(claim.resources, "active resources"):
            raise CandidateScopeError("resource is already held by an active lease")
