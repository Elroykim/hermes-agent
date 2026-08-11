"""Exact diff-to-lease path-set verification for P0 candidates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence


class CandidateScopeError(ValueError):
    pass


@dataclass(frozen=True)
class LeaseClaim:
    lease_id: str
    base_sha: str
    resources: tuple[str, ...]
    expires_at: str


def _paths(value: object, name: str) -> set[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CandidateScopeError(f"{name} must be a list")
    result = set(value)
    if not result or len(result) != len(value) or any(not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/") or any(c in path for c in "*?[]") for path in result):
        raise CandidateScopeError(f"{name} must contain unique exact repository paths")
    return result


def verify_candidate_scope(*, actual_paths: Sequence[str], candidate: Mapping[str, object]) -> set[str]:
    actual = _paths(actual_paths, "actual paths")
    ledger = candidate.get("ledger")
    if not isinstance(ledger, Mapping) or set(ledger) != {"mutation_boundary", "acquired_resources", "released_resources"}:
        raise CandidateScopeError("ledger scope schema is invalid")
    scopes = [_paths(candidate.get("declared_paths"), "manifest paths"), *[_paths(ledger[key], key) for key in ledger]]
    if any(scope != actual for scope in scopes) or "docs/thewon/p0/evidence-ledger.json" not in actual:
        raise CandidateScopeError("actual diff and every lease scope must exactly match including ledger")
    return actual


def validate_lease_claim(*, expected_base_sha: str, requested: LeaseClaim, active: Sequence[LeaseClaim], now: datetime) -> None:
    if requested.base_sha != expected_base_sha or not requested.lease_id:
        raise CandidateScopeError("lease base or identifier is invalid")
    requested_paths = _paths(requested.resources, "requested resources")
    try:
        expiry = datetime.fromisoformat(requested.expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateScopeError("lease expiry is invalid") from exc
    if expiry.tzinfo is None or expiry <= now.astimezone(timezone.utc):
        raise CandidateScopeError("lease is expired")
    for claim in active:
        if claim.lease_id == requested.lease_id:
            raise CandidateScopeError("lease identifier is already used")
        try:
            active_expiry = datetime.fromisoformat(claim.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CandidateScopeError("active lease expiry is invalid") from exc
        if active_expiry.tzinfo is not None and active_expiry > now.astimezone(timezone.utc) and requested_paths & _paths(claim.resources, "active resources"):
            raise CandidateScopeError("resource is already leased")
