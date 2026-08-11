"""Evidence contracts and leased state for the TheWon P0 control plane.

This module deliberately evaluates already-captured Slack and runtime evidence.
It does not call Slack, read credentials, or mutate a live runtime.  That keeps
the policy testable and prevents a reply count from becoming a PASS signal.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping


LEDGER_SCHEMA = "thewon-p0-evidence-ledger/v1"
_SHA256_LENGTH = 64
_GIT_SHA_LENGTHS = {40, 64}


class EvidenceContractError(ValueError):
    """Evidence does not satisfy the P0 fail-closed contract."""


class LeaseConflict(EvidenceContractError):
    """Another valid lease owns a requested mutable resource."""


@dataclass(frozen=True)
class RoundtripContract:
    run_id: str
    parent_ts: str
    owner_user_id: str
    expected_agent_user_id: str
    workflow_run_id: str
    blackbox_run_id: str


@dataclass(frozen=True)
class VerifiedRoundtrip:
    run_id: str
    agent_response_ts: str
    agent_user_id: str
    tool_result_sha256: str
    workflow_sha256: str
    blackbox_sha256: str


@dataclass(frozen=True)
class Lease:
    lease_id: str
    issue_id: str
    resources: tuple[str, ...]
    owner_bac: str
    base_sha: str
    issued_at: str
    expires_at: str


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvidenceContractError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceContractError(f"{name} must be a non-empty string")
    return value


def _require_sha(value: object, name: str, lengths: set[int] = {_SHA256_LENGTH}) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in lengths
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceContractError(f"{name} must be a lowercase SHA digest")
    return value


def _timestamp(value: object, name: str) -> Decimal:
    raw = _require_text(value, name)
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise EvidenceContractError(f"{name} must be a Slack timestamp") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise EvidenceContractError(f"{name} must be a positive Slack timestamp")
    return parsed


def _artifact(evidence: Mapping[str, object], key: str, expected_run_id: str) -> str:
    value = evidence.get(key)
    if not isinstance(value, Mapping):
        raise EvidenceContractError(f"missing {key} evidence")
    if value.get("run_id") != expected_run_id:
        raise EvidenceContractError(f"{key} run_id does not match the contract")
    return canonical_sha256(dict(value))


def verify_roundtrip(
    contract: RoundtripContract,
    messages: Iterable[Mapping[str, object]],
    evidence: Mapping[str, object],
) -> VerifiedRoundtrip:
    """Verify one user-origin agent roundtrip and its durable outputs.

    The caller must pass the full thread page(s), not a pre-filtered reply list.
    This makes the parent identity and exact responding Slack user auditable.
    """

    for value, name in (
        (contract.run_id, "run_id"),
        (contract.owner_user_id, "owner_user_id"),
        (contract.expected_agent_user_id, "expected_agent_user_id"),
        (contract.workflow_run_id, "workflow_run_id"),
        (contract.blackbox_run_id, "blackbox_run_id"),
    ):
        _require_text(value, name)
    parent_time = _timestamp(contract.parent_ts, "parent_ts")
    rows = [dict(row) for row in messages if isinstance(row, Mapping)]
    parent_rows = [row for row in rows if row.get("ts") == contract.parent_ts]
    if len(parent_rows) != 1 or parent_rows[0].get("user") != contract.owner_user_id:
        raise EvidenceContractError("thread parent is not the expected user-origin message")

    candidates: list[dict[str, object]] = []
    for row in rows:
        if row.get("user") != contract.expected_agent_user_id:
            continue
        if _timestamp(row.get("ts"), "agent response ts") <= parent_time:
            continue
        metadata = row.get("metadata")
        if not isinstance(metadata, Mapping):
            continue
        if metadata.get("p0_run_id") != contract.run_id or metadata.get("terminal") is not True:
            continue
        if not isinstance(row.get("text"), str) or not row["text"].strip():
            continue
        candidates.append(row)
    if len(candidates) != 1:
        raise EvidenceContractError("expected exactly one non-empty terminal response from the assigned agent")

    tool = evidence.get("tool_result")
    if not isinstance(tool, Mapping) or tool.get("message_ts") != candidates[0].get("ts"):
        raise EvidenceContractError("tool result is not bound to the terminal Slack response")
    tool_sha = _artifact(evidence, "tool_result", contract.run_id)
    workflow_sha = _artifact(evidence, "workflow", contract.workflow_run_id)
    blackbox_sha = _artifact(evidence, "blackbox", contract.blackbox_run_id)
    return VerifiedRoundtrip(
        run_id=contract.run_id,
        agent_response_ts=str(candidates[0]["ts"]),
        agent_user_id=contract.expected_agent_user_id,
        tool_result_sha256=tool_sha,
        workflow_sha256=workflow_sha,
        blackbox_sha256=blackbox_sha,
    )


class IssueLedger:
    """A small atomic Git-trackable ledger with per-resource leases."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    @staticmethod
    def _now(value: datetime | None = None) -> datetime:
        now = value or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise EvidenceContractError("ledger time must be timezone-aware")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_iso(value: object, name: str) -> datetime:
        if not isinstance(value, str):
            raise EvidenceContractError(f"{name} must be an ISO timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceContractError(f"{name} is malformed") from exc
        if parsed.tzinfo is None:
            raise EvidenceContractError(f"{name} must be timezone-aware")
        return parsed.astimezone(timezone.utc)

    def _empty(self) -> dict[str, object]:
        return {"schema_version": LEDGER_SCHEMA, "issues": {}, "resource_leases": {}}

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_unlocked(self) -> dict[str, object]:
        if not self.path.exists():
            return self._empty()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceContractError(f"ledger cannot be read: {exc}") from exc
        if not isinstance(value, dict) or value.get("schema_version") != LEDGER_SCHEMA:
            raise EvidenceContractError("ledger schema is not authoritative")
        if not isinstance(value.get("issues"), dict) or not isinstance(value.get("resource_leases"), dict):
            raise EvidenceContractError("ledger structure is malformed")
        return value

    def _write_unlocked(self, value: Mapping[str, object]) -> None:
        payload = _canonical_json(dict(value)) + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(prefix=".p0-ledger-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def read(self) -> dict[str, object]:
        with self._locked():
            return json.loads(_canonical_json(self._load_unlocked()))

    def open_issue(
        self,
        *,
        issue_id: str,
        owner_bac: str,
        base_sha: str,
        mutation_boundary: Iterable[str],
        rollback: str,
    ) -> None:
        _require_text(issue_id, "issue_id")
        _require_text(owner_bac, "owner_bac")
        _require_sha(base_sha, "base_sha", _GIT_SHA_LENGTHS)
        boundary = sorted({_require_text(value, "mutation_boundary") for value in mutation_boundary})
        if not boundary:
            raise EvidenceContractError("mutation_boundary must not be empty")
        _require_text(rollback, "rollback")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            assert isinstance(issues, dict)
            existing = issues.get(issue_id)
            row = {
                "owner_bac": owner_bac,
                "base_sha": base_sha,
                "mutation_boundary": boundary,
                "rollback": rollback,
                "state": "OPEN",
                "transitions": [],
            }
            if existing is not None and existing != row:
                raise EvidenceContractError("issue already exists with different authority")
            issues[issue_id] = row
            self._write_unlocked(value)

    def acquire_lease(
        self,
        *,
        issue_id: str,
        resources: Iterable[str],
        owner_bac: str,
        base_sha: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> Lease:
        timestamp = self._now(now)
        if ttl < timedelta(seconds=60) or ttl > timedelta(hours=24):
            raise EvidenceContractError("lease ttl must be between one minute and 24 hours")
        _require_text(owner_bac, "owner_bac")
        _require_sha(base_sha, "base_sha", _GIT_SHA_LENGTHS)
        requested = tuple(sorted({_require_text(resource, "resource") for resource in resources}))
        if not requested:
            raise EvidenceContractError("at least one resource is required")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            leases = value["resource_leases"]
            assert isinstance(issues, dict) and isinstance(leases, dict)
            issue = issues.get(issue_id)
            if not isinstance(issue, dict) or issue.get("base_sha") != base_sha:
                raise EvidenceContractError("issue is missing or base SHA drifted")
            for resource in requested:
                held = leases.get(resource)
                if not isinstance(held, dict):
                    continue
                expires_at = self._parse_iso(held.get("expires_at"), "lease expires_at")
                if expires_at > timestamp:
                    raise LeaseConflict(f"resource is already leased by {held.get('owner_bac')}: {resource}")
            lease = Lease(
                lease_id=f"lease-{uuid.uuid4().hex}",
                issue_id=issue_id,
                resources=requested,
                owner_bac=owner_bac,
                base_sha=base_sha,
                issued_at=self._iso(timestamp),
                expires_at=self._iso(timestamp + ttl),
            )
            for resource in requested:
                leases[resource] = asdict(lease)
            self._write_unlocked(value)
            return lease

    def record_transition(
        self,
        *,
        issue_id: str,
        lease_id: str,
        state: str,
        pre_state_digest: str,
        artifacts: Iterable[Mapping[str, object]],
        validation: Mapping[str, object],
        now: datetime | None = None,
    ) -> dict[str, object]:
        timestamp = self._now(now)
        _require_text(state, "state")
        _require_sha(pre_state_digest, "pre_state_digest")
        _require_text(lease_id, "lease_id")
        normalized_artifacts: list[dict[str, str]] = []
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                raise EvidenceContractError("artifact must be an object")
            normalized_artifacts.append(
                {
                    "path": _require_text(artifact.get("path"), "artifact path"),
                    "sha256": _require_sha(artifact.get("sha256"), "artifact sha256"),
                }
            )
        if not normalized_artifacts or not isinstance(validation, Mapping):
            raise EvidenceContractError("transition requires artifacts and validation")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            leases = value["resource_leases"]
            assert isinstance(issues, dict) and isinstance(leases, dict)
            issue = issues.get(issue_id)
            if not isinstance(issue, dict):
                raise EvidenceContractError("issue does not exist")
            issue_resources = [
                row for row in leases.values() if isinstance(row, dict) and row.get("lease_id") == lease_id
            ]
            if not issue_resources:
                raise EvidenceContractError("lease is absent")
            if any(
                row.get("issue_id") != issue_id
                or self._parse_iso(row.get("expires_at"), "lease expires_at") <= timestamp
                for row in issue_resources
            ):
                raise EvidenceContractError("lease is not valid for this transition")
            event = {
                "state": state,
                "lease_id": lease_id,
                "recorded_at": self._iso(timestamp),
                "pre_state_digest": pre_state_digest,
                "artifacts": normalized_artifacts,
                "validation": json.loads(_canonical_json(dict(validation))),
            }
            transitions = issue["transitions"]
            assert isinstance(transitions, list)
            transitions.append(event)
            issue["state"] = state
            self._write_unlocked(value)
            return event

    def renew_lease(
        self,
        *,
        issue_id: str,
        lease_id: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> Lease:
        """Extend one still-valid lease without changing its resource ownership."""
        timestamp = self._now(now)
        _require_text(issue_id, "issue_id")
        _require_text(lease_id, "lease_id")
        if ttl < timedelta(seconds=60) or ttl > timedelta(hours=24):
            raise EvidenceContractError("lease ttl must be between one minute and 24 hours")
        with self._locked():
            value = self._load_unlocked()
            leases = value["resource_leases"]
            assert isinstance(leases, dict)
            rows = [
                row
                for row in leases.values()
                if isinstance(row, dict) and row.get("lease_id") == lease_id
            ]
            if not rows:
                raise EvidenceContractError("lease is absent")
            first = rows[0]
            expected = {
                "lease_id": lease_id,
                "issue_id": issue_id,
                "resources": first.get("resources"),
                "owner_bac": first.get("owner_bac"),
                "base_sha": first.get("base_sha"),
                "issued_at": first.get("issued_at"),
                "expires_at": first.get("expires_at"),
            }
            if any(
                {key: row.get(key) for key in expected} != expected
                for row in rows
            ):
                raise EvidenceContractError("lease rows are inconsistent")
            if self._parse_iso(first.get("expires_at"), "lease expires_at") <= timestamp:
                raise EvidenceContractError("lease is expired")
            resources = first.get("resources")
            if not isinstance(resources, list) or not resources:
                raise EvidenceContractError("lease resources are malformed")
            new_expiry = self._iso(timestamp + ttl)
            for resource in resources:
                row = leases.get(resource)
                if not isinstance(row, dict) or row.get("lease_id") != lease_id:
                    raise EvidenceContractError("lease resource ownership changed")
                row["expires_at"] = new_expiry
            self._write_unlocked(value)
            return Lease(
                lease_id=lease_id,
                issue_id=issue_id,
                resources=tuple(resources),
                owner_bac=_require_text(first.get("owner_bac"), "lease owner_bac"),
                base_sha=_require_sha(first.get("base_sha"), "lease base_sha", _GIT_SHA_LENGTHS),
                issued_at=_require_text(first.get("issued_at"), "lease issued_at"),
                expires_at=new_expiry,
            )

    def release_lease(self, *, issue_id: str, lease_id: str) -> tuple[str, ...]:
        """Release all resources owned by a completed or blocked mutation lease."""
        _require_text(issue_id, "issue_id")
        _require_text(lease_id, "lease_id")
        with self._locked():
            value = self._load_unlocked()
            leases = value["resource_leases"]
            assert isinstance(leases, dict)
            resources = tuple(
                sorted(
                    resource
                    for resource, row in leases.items()
                    if isinstance(row, dict) and row.get("lease_id") == lease_id
                )
            )
            if not resources:
                raise EvidenceContractError("lease is absent")
            if any(
                not isinstance(leases[resource], dict) or leases[resource].get("issue_id") != issue_id
                for resource in resources
            ):
                raise EvidenceContractError("lease does not belong to this issue")
            for resource in resources:
                del leases[resource]
            self._write_unlocked(value)
            return resources
