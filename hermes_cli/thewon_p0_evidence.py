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
_SUCCESS_STATUSES = frozenset({"success", "succeeded", "completed"})
_LEGAL_PREDECESSORS = {
    "candidate_bound": frozenset({"OPEN"}),
    "containment_applied": frozenset({"candidate_bound"}),
    "audit_ready": frozenset({"candidate_bound", "containment_applied"}),
    "blocked": frozenset({"OPEN", "candidate_bound", "containment_applied", "audit_ready"}),
}
_TERMINAL_STATES = frozenset({"audit_ready", "blocked"})
_LEASE_HISTORY_EVENTS = frozenset({"acquired", "renewed", "released"})
_LEASE_HISTORY_KEYS = frozenset(
    {
        "event",
        "lease_id",
        "issue_id",
        "resources",
        "owner_bac",
        "base_sha",
        "issued_at",
        "expires_at",
        "recorded_at",
    }
)


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
    channel_id: str


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


def _candidate_paths(values: object, name: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise EvidenceContractError(f"{name} must be a path list")
    paths = tuple(sorted({_require_text(value, name) for value in values}))
    if not paths or len(paths) != len(values):
        raise EvidenceContractError(f"{name} must be a non-empty unique path list")
    if any(path.startswith("/") or path.startswith("../") or "/../" in path for path in paths):
        raise EvidenceContractError(f"{name} contains a non-repository path")
    return paths


def validate_candidate_provenance(
    manifest: Mapping[str, object],
    ledger: Mapping[str, object],
    *,
    issue_id: str,
    changed_paths: Iterable[str],
) -> tuple[str, ...]:
    """Bind a committed candidate's exact diff to its issue and terminal lease.

    The candidate manifest is intentionally not its own hash authority.  Instead,
    this function compares an externally derived Git diff with all three mutable
    declarations: the manifest scope, the issue mutation boundary, and the
    acquire/release rows of one terminal lease.
    """

    expected_issue = _require_text(issue_id, "issue_id")
    if not isinstance(manifest, Mapping) or not isinstance(ledger, Mapping):
        raise EvidenceContractError("candidate provenance inputs must be mappings")
    if manifest.get("issue_id") != expected_issue:
        raise EvidenceContractError("candidate manifest issue does not match")
    changed = _candidate_paths(tuple(changed_paths), "changed_paths")
    declared = _candidate_paths(manifest.get("changed_paths"), "manifest changed_paths")
    if declared != changed:
        raise EvidenceContractError("candidate manifest does not cover the exact Git diff")

    lease = manifest.get("candidate_lease")
    issues = ledger.get("issues")
    history = ledger.get("lease_history")
    if not isinstance(lease, Mapping) or not isinstance(issues, Mapping) or not isinstance(history, list):
        raise EvidenceContractError("candidate provenance structure is malformed")
    lease_id = _require_text(lease.get("lease_id"), "candidate lease_id")
    owner_bac = _require_text(lease.get("owner_bac"), "candidate owner_bac")
    base_sha = _require_sha(lease.get("base_sha"), "candidate base_sha", _GIT_SHA_LENGTHS)
    issue = issues.get(expected_issue)
    if not isinstance(issue, Mapping):
        raise EvidenceContractError("candidate issue is missing from the ledger")
    if issue.get("owner_bac") != owner_bac:
        raise EvidenceContractError("candidate lease owner does not match the issue owner")
    if _require_sha(issue.get("base_sha"), "issue base_sha", _GIT_SHA_LENGTHS) != base_sha:
        raise EvidenceContractError("candidate lease base SHA does not match the issue")
    boundary = _candidate_paths(issue.get("mutation_boundary"), "issue mutation_boundary")
    if boundary != changed:
        raise EvidenceContractError("issue mutation boundary does not cover the exact Git diff")

    rows = [
        row
        for row in history
        if isinstance(row, Mapping) and row.get("issue_id") == expected_issue and row.get("lease_id") == lease_id
    ]
    if len(rows) != 2 or [row.get("event") for row in rows] != ["acquired", "released"]:
        raise EvidenceContractError("candidate lease must have one acquired and one released history row")
    for row in rows:
        if row.get("owner_bac") != owner_bac:
            raise EvidenceContractError("candidate lease history owner drifted")
        if _require_sha(row.get("base_sha"), "candidate lease history base_sha", _GIT_SHA_LENGTHS) != base_sha:
            raise EvidenceContractError("candidate lease history base SHA drifted")
        if _candidate_paths(row.get("resources"), "candidate lease resources") != changed:
            raise EvidenceContractError("candidate lease history does not cover the exact Git diff")
    resource_leases = ledger.get("resource_leases")
    if not isinstance(resource_leases, Mapping) or any(
        path in resource_leases
        or isinstance(row, Mapping) and row.get("lease_id") == lease_id
        for path, row in resource_leases.items()
    ):
        raise EvidenceContractError("candidate lease is not terminally released")
    return changed


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
    if value.get("status") not in _SUCCESS_STATUSES:
        raise EvidenceContractError(f"{key} did not succeed")
    result = value.get("result")
    if not isinstance(result, Mapping) or not result:
        raise EvidenceContractError(f"{key} has no successful non-empty result")
    if result.get("ok") is False or (
        result.get("ok") is not True
        and result.get("status") not in _SUCCESS_STATUSES
        and result.get("state") not in _SUCCESS_STATUSES
    ):
        raise EvidenceContractError(f"{key} has no successful non-empty result")
    durable_artifact = value.get("artifact")
    if not isinstance(durable_artifact, Mapping):
        raise EvidenceContractError(f"{key} has no durable artifact")
    _require_text(durable_artifact.get("path"), f"{key} artifact path")
    _require_sha(durable_artifact.get("sha256"), f"{key} artifact sha256")
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
        (contract.channel_id, "channel_id"),
    ):
        _require_text(value, name)
    if contract.workflow_run_id != contract.run_id or contract.blackbox_run_id != contract.run_id:
        raise EvidenceContractError("all durable artifacts must share the requested run_id")
    parent_time = _timestamp(contract.parent_ts, "parent_ts")
    rows = [dict(row) for row in messages if isinstance(row, Mapping)]
    parent_rows = [row for row in rows if row.get("ts") == contract.parent_ts]
    if (
        len(parent_rows) != 1
        or parent_rows[0].get("user") != contract.owner_user_id
        or parent_rows[0].get("channel") != contract.channel_id
        or parent_rows[0].get("thread_ts") not in (None, contract.parent_ts)
    ):
        raise EvidenceContractError("thread parent is not the expected user-origin message")

    candidates: list[dict[str, object]] = []
    for row in rows:
        metadata = row.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("p0_run_id") != contract.run_id:
            continue
        if row.get("user") != contract.expected_agent_user_id:
            raise EvidenceContractError("roundtrip reply is not from the assigned agent")
        if _timestamp(row.get("ts"), "agent response ts") <= parent_time:
            raise EvidenceContractError("roundtrip reply precedes its parent")
        if row.get("channel") != contract.channel_id or row.get("thread_ts") != contract.parent_ts:
            raise EvidenceContractError("roundtrip reply is outside the requested channel or thread")
        if metadata.get("terminal") is not True:
            continue
        if not isinstance(row.get("text"), str) or not row["text"].strip():
            raise EvidenceContractError("terminal roundtrip reply has no result text")
        candidates.append(row)
    if len(candidates) != 1:
        raise EvidenceContractError("expected exactly one non-empty terminal response from the assigned agent")

    tool = evidence.get("tool_result")
    if (
        not isinstance(tool, Mapping)
        or tool.get("message_ts") != candidates[0].get("ts")
        or tool.get("channel") != contract.channel_id
        or tool.get("thread_ts") != contract.parent_ts
    ):
        raise EvidenceContractError("tool result is not bound to the terminal Slack response")
    tool_sha = _artifact(evidence, "tool_result", contract.run_id)
    workflow_sha = _artifact(evidence, "workflow", contract.run_id)
    blackbox_sha = _artifact(evidence, "blackbox", contract.run_id)
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
        return {"schema_version": LEDGER_SCHEMA, "issues": {}, "resource_leases": {}, "lease_history": []}

    @staticmethod
    def _resource_within_boundary(resource: str, boundary: Iterable[str]) -> bool:
        return any(
            resource == allowed
            or resource.startswith(f"{allowed}/")
            or resource.startswith(f"{allowed}:")
            for allowed in boundary
        )

    @staticmethod
    def _lease_ttl_is_valid(ttl: object) -> bool:
        return isinstance(ttl, timedelta) and timedelta(seconds=60) <= ttl <= timedelta(hours=24)

    @staticmethod
    def _state_digest(issue: Mapping[str, object]) -> str:
        return canonical_sha256(
            {
                "owner_bac": issue.get("owner_bac"),
                "base_sha": issue.get("base_sha"),
                "mutation_boundary": issue.get("mutation_boundary"),
                "rollback": issue.get("rollback"),
                "state": issue.get("state"),
                "transitions": issue.get("transitions"),
            }
        )

    def _validated_issue(self, issues: Mapping[str, object], issue_id: str) -> dict[str, object]:
        issue = issues.get(issue_id)
        if not isinstance(issue, dict):
            raise EvidenceContractError("issue does not exist")
        _require_text(issue.get("owner_bac"), "issue owner_bac")
        _require_sha(issue.get("base_sha"), "issue base_sha", _GIT_SHA_LENGTHS)
        boundary = issue.get("mutation_boundary")
        if not isinstance(boundary, list) or not boundary:
            raise EvidenceContractError("issue mutation_boundary is malformed")
        if any(not isinstance(value, str) or not value.strip() for value in boundary):
            raise EvidenceContractError("issue mutation_boundary is malformed")
        if boundary != sorted(set(boundary)):
            raise EvidenceContractError("issue mutation_boundary is malformed")
        _require_text(issue.get("rollback"), "issue rollback")
        state = issue.get("state")
        if state != "OPEN" and state not in _LEGAL_PREDECESSORS:
            raise EvidenceContractError("issue state is not recognized")
        if not isinstance(issue.get("transitions"), list):
            raise EvidenceContractError("issue transitions are malformed")
        return issue

    @staticmethod
    def _history_event(event: str, lease: Lease, recorded_at: datetime) -> dict[str, object]:
        return {
            "event": event,
            "lease_id": lease.lease_id,
            "issue_id": lease.issue_id,
            "resources": list(lease.resources),
            "owner_bac": lease.owner_bac,
            "base_sha": lease.base_sha,
            "issued_at": lease.issued_at,
            "expires_at": lease.expires_at,
            "recorded_at": IssueLedger._iso(recorded_at),
        }

    def _normalized_history_entry(self, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != _LEASE_HISTORY_KEYS:
            raise EvidenceContractError("lease history entry is malformed")
        event = value.get("event")
        if event not in _LEASE_HISTORY_EVENTS:
            raise EvidenceContractError("lease history event is not recognized")
        resources = value.get("resources")
        if (
            not isinstance(resources, list)
            or not resources
            or any(not isinstance(resource, str) or not resource.strip() for resource in resources)
            or resources != sorted(set(resources))
        ):
            raise EvidenceContractError("lease history resources are malformed")
        issued_at = self._parse_iso(value.get("issued_at"), "lease history issued_at")
        expires_at = self._parse_iso(value.get("expires_at"), "lease history expires_at")
        recorded_at = self._parse_iso(value.get("recorded_at"), "lease history recorded_at")
        if expires_at <= issued_at or recorded_at < issued_at:
            raise EvidenceContractError("lease history timestamps are inconsistent")
        normalized = {
            "event": event,
            "lease_id": _require_text(value.get("lease_id"), "lease history lease_id"),
            "issue_id": _require_text(value.get("issue_id"), "lease history issue_id"),
            "resources": list(resources),
            "owner_bac": _require_text(value.get("owner_bac"), "lease history owner_bac"),
            "base_sha": _require_sha(value.get("base_sha"), "lease history base_sha", _GIT_SHA_LENGTHS),
            "issued_at": self._iso(issued_at),
            "expires_at": self._iso(expires_at),
            "recorded_at": self._iso(recorded_at),
        }
        if dict(value) != normalized:
            raise EvidenceContractError("lease history entry is not canonical")
        return normalized

    @staticmethod
    def _history_matches_lease(entry: Mapping[str, object], lease: Lease) -> bool:
        return (
            entry.get("lease_id") == lease.lease_id
            and entry.get("issue_id") == lease.issue_id
            and entry.get("resources") == list(lease.resources)
            and entry.get("owner_bac") == lease.owner_bac
            and entry.get("base_sha") == lease.base_sha
            and entry.get("issued_at") == lease.issued_at
            and entry.get("expires_at") == lease.expires_at
        )

    def _validate_lease_history(
        self,
        issues: Mapping[str, object],
        leases: Mapping[str, object],
        history: object,
    ) -> None:
        if not isinstance(history, list):
            raise EvidenceContractError("lease_history must be a list")
        entries_by_lease: dict[str, list[dict[str, object]]] = {}
        for raw_entry in history:
            entry = self._normalized_history_entry(raw_entry)
            issue = self._validated_issue(issues, str(entry["issue_id"]))
            if entry["owner_bac"] != issue.get("owner_bac") or entry["base_sha"] != issue.get("base_sha"):
                raise EvidenceContractError("lease history does not match issue authority")
            boundary = issue.get("mutation_boundary")
            assert isinstance(boundary, list)
            if any(not self._resource_within_boundary(resource, boundary) for resource in entry["resources"]):
                raise EvidenceContractError("lease history resource is outside the mutation boundary")
            lease_id = str(entry["lease_id"])
            previous = entries_by_lease.setdefault(lease_id, [])
            if not previous:
                if entry["event"] != "acquired":
                    raise EvidenceContractError("lease history must begin with acquisition")
            else:
                prior = previous[-1]
                if prior["event"] == "released" or entry["event"] == "acquired":
                    raise EvidenceContractError("lease history lifecycle is invalid")
                if any(
                    entry[field] != prior[field]
                    for field in ("issue_id", "resources", "owner_bac", "base_sha", "issued_at")
                ):
                    raise EvidenceContractError("lease history identity drifted")
                if self._parse_iso(entry["recorded_at"], "lease history recorded_at") < self._parse_iso(
                    prior["recorded_at"], "lease history recorded_at"
                ):
                    raise EvidenceContractError("lease history is not chronological")
                prior_expiry = self._parse_iso(prior["expires_at"], "lease history expires_at")
                expiry = self._parse_iso(entry["expires_at"], "lease history expires_at")
                if entry["event"] == "renewed" and expiry <= prior_expiry:
                    raise EvidenceContractError("lease history renewal did not extend the lease")
                if entry["event"] == "released" and expiry != prior_expiry:
                    raise EvidenceContractError("lease release does not match its final expiry")
            previous.append(entry)

        active_lease_ids: set[str] = set()
        for row in leases.values():
            if not isinstance(row, Mapping):
                raise EvidenceContractError("lease row is malformed")
            active_lease_ids.add(_require_text(row.get("lease_id"), "lease lease_id"))
        for lease_id in active_lease_ids:
            rows = [row for row in leases.values() if isinstance(row, Mapping) and row.get("lease_id") == lease_id]
            assert rows
            issue_id = _require_text(rows[0].get("issue_id"), "lease issue_id")
            issue = self._validated_issue(issues, issue_id)
            lease = self._lease_for_issue(leases, issue, issue_id=issue_id, lease_id=lease_id)
            entries = entries_by_lease.get(lease_id)
            if not entries or entries[-1]["event"] == "released" or not self._history_matches_lease(entries[-1], lease):
                raise EvidenceContractError("active lease does not match its history")
        for lease_id, entries in entries_by_lease.items():
            if lease_id not in active_lease_ids and entries[-1]["event"] != "released":
                raise EvidenceContractError("lease history has no final release record")

    def _lease_for_issue(
        self,
        leases: Mapping[str, object],
        issue: Mapping[str, object],
        *,
        issue_id: str,
        lease_id: str,
        timestamp: datetime | None = None,
    ) -> Lease:
        rows = {
            resource: row
            for resource, row in leases.items()
            if isinstance(row, dict) and row.get("lease_id") == lease_id
        }
        if not rows:
            raise EvidenceContractError("lease is absent")
        if any(not isinstance(resource, str) for resource in rows):
            raise EvidenceContractError("lease resources are malformed")
        resources = tuple(sorted(rows))
        first = next(iter(rows.values()))
        assert isinstance(first, dict)
        owner_bac = _require_text(first.get("owner_bac"), "lease owner_bac")
        base_sha = _require_sha(first.get("base_sha"), "lease base_sha", _GIT_SHA_LENGTHS)
        issued_at = self._parse_iso(first.get("issued_at"), "lease issued_at")
        expires_at = self._parse_iso(first.get("expires_at"), "lease expires_at")
        if expires_at <= issued_at:
            raise EvidenceContractError("lease expiry must follow issuance")
        expected = {
            "lease_id": lease_id,
            "issue_id": issue_id,
            "resources": list(resources),
            "owner_bac": owner_bac,
            "base_sha": base_sha,
            "issued_at": self._iso(issued_at),
            "expires_at": self._iso(expires_at),
        }
        if any(row != expected for row in rows.values()):
            raise EvidenceContractError("lease rows are inconsistent")
        if owner_bac != issue.get("owner_bac"):
            raise EvidenceContractError("lease owner does not match the issue owner")
        if base_sha != issue.get("base_sha"):
            raise EvidenceContractError("lease base SHA does not match the issue base")
        boundary = issue.get("mutation_boundary")
        assert isinstance(boundary, list)
        if any(not self._resource_within_boundary(resource, boundary) for resource in resources):
            raise EvidenceContractError("lease resource is outside the mutation boundary")
        if timestamp is not None and (issued_at > timestamp or expires_at <= timestamp):
            raise EvidenceContractError("lease is not active")
        return Lease(
            lease_id=lease_id,
            issue_id=issue_id,
            resources=resources,
            owner_bac=owner_bac,
            base_sha=base_sha,
            issued_at=self._iso(issued_at),
            expires_at=self._iso(expires_at),
        )

    @staticmethod
    def _validation_evidence(validation: object) -> dict[str, object]:
        if not isinstance(validation, Mapping) or validation.get("passed") is not True:
            raise EvidenceContractError("transition requires passing validation evidence")
        return json.loads(_canonical_json(dict(validation)))

    def _normalized_artifacts(
        self,
        artifacts: Iterable[Mapping[str, object]],
        boundary: Iterable[str],
    ) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        paths: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                raise EvidenceContractError("artifact must be an object")
            path = _require_text(artifact.get("path"), "artifact path")
            if path in paths:
                raise EvidenceContractError("transition artifacts must have unique paths")
            if not self._resource_within_boundary(path, boundary):
                raise EvidenceContractError("artifact is outside the mutation boundary")
            paths.add(path)
            normalized.append({"path": path, "sha256": _require_sha(artifact.get("sha256"), "artifact sha256")})
        if not normalized:
            raise EvidenceContractError("transition requires artifacts")
        return normalized

    def _require_legal_predecessor(self, issue: Mapping[str, object], state: str) -> None:
        predecessors = _LEGAL_PREDECESSORS.get(state)
        if predecessors is None:
            raise EvidenceContractError("transition state is not recognized")
        current_state = issue.get("state")
        if current_state not in predecessors:
            raise EvidenceContractError("transition does not follow a legal predecessor state")
        if current_state == "OPEN":
            return
        transitions = issue.get("transitions")
        assert isinstance(transitions, list)
        if not transitions or not isinstance(transitions[-1], Mapping):
            raise EvidenceContractError("transition has no recorded prerequisite evidence")
        prerequisite = transitions[-1]
        if (
            prerequisite.get("state") != current_state
            or not isinstance(prerequisite.get("artifacts"), list)
            or not prerequisite["artifacts"]
            or not isinstance(prerequisite.get("validation"), Mapping)
            or prerequisite["validation"].get("passed") is not True
        ):
            raise EvidenceContractError("transition has no legal prerequisite evidence")

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
        if "lease_history" not in value:
            value["lease_history"] = []
        self._validate_lease_history(value["issues"], value["resource_leases"], value["lease_history"])
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

    def state_digest(self, *, issue_id: str) -> str:
        """Return the authoritative digest required for the next transition."""
        _require_text(issue_id, "issue_id")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            assert isinstance(issues, dict)
            issue = self._validated_issue(issues, issue_id)
            return self._state_digest(issue)

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
        if not self._lease_ttl_is_valid(ttl):
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
            history = value["lease_history"]
            assert isinstance(issues, dict) and isinstance(leases, dict) and isinstance(history, list)
            issue = self._validated_issue(issues, issue_id)
            if issue.get("state") != "OPEN":
                raise EvidenceContractError("issue is no longer eligible for a new lease")
            if issue.get("owner_bac") != owner_bac:
                raise EvidenceContractError("lease owner does not match the issue owner")
            if issue.get("base_sha") != base_sha:
                raise EvidenceContractError("issue base SHA drifted")
            boundary = issue.get("mutation_boundary")
            assert isinstance(boundary, list)
            if any(not self._resource_within_boundary(resource, boundary) for resource in requested):
                raise EvidenceContractError("lease resource is outside the mutation boundary")
            for row in leases.values():
                if not isinstance(row, dict) or row.get("issue_id") != issue_id:
                    continue
                if self._parse_iso(row.get("expires_at"), "lease expires_at") > timestamp:
                    raise LeaseConflict("issue already has an active lease")
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
                lease_row = asdict(lease)
                lease_row["resources"] = list(lease.resources)
                leases[resource] = lease_row
            history.append(self._history_event("acquired", lease, timestamp))
            self._validate_lease_history(issues, leases, history)
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
        _require_text(issue_id, "issue_id")
        _require_text(state, "state")
        _require_sha(pre_state_digest, "pre_state_digest")
        _require_text(lease_id, "lease_id")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            leases = value["resource_leases"]
            assert isinstance(issues, dict) and isinstance(leases, dict)
            issue = self._validated_issue(issues, issue_id)
            if pre_state_digest != self._state_digest(issue):
                raise EvidenceContractError("pre_state_digest does not match the authoritative issue state")
            self._require_legal_predecessor(issue, state)
            self._lease_for_issue(
                leases,
                issue,
                issue_id=issue_id,
                lease_id=lease_id,
                timestamp=timestamp,
            )
            boundary = issue.get("mutation_boundary")
            assert isinstance(boundary, list)
            normalized_artifacts = self._normalized_artifacts(artifacts, boundary)
            normalized_validation = self._validation_evidence(validation)
            event = {
                "state": state,
                "lease_id": lease_id,
                "recorded_at": self._iso(timestamp),
                "pre_state_digest": pre_state_digest,
                "artifacts": normalized_artifacts,
                "validation": normalized_validation,
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
        if not self._lease_ttl_is_valid(ttl):
            raise EvidenceContractError("lease ttl must be between one minute and 24 hours")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            leases = value["resource_leases"]
            history = value["lease_history"]
            assert isinstance(issues, dict) and isinstance(leases, dict) and isinstance(history, list)
            issue = self._validated_issue(issues, issue_id)
            if issue.get("state") in _TERMINAL_STATES:
                raise EvidenceContractError("terminal issues cannot renew leases")
            lease = self._lease_for_issue(
                leases,
                issue,
                issue_id=issue_id,
                lease_id=lease_id,
                timestamp=timestamp,
            )
            new_expiry_at = timestamp + ttl
            if new_expiry_at <= self._parse_iso(lease.expires_at, "lease expires_at"):
                raise EvidenceContractError("lease renewal must extend its expiry")
            new_expiry = self._iso(new_expiry_at)
            for resource in lease.resources:
                row = leases.get(resource)
                if not isinstance(row, dict) or row.get("lease_id") != lease_id:
                    raise EvidenceContractError("lease resource ownership changed")
                row["expires_at"] = new_expiry
            renewed = Lease(
                lease_id=lease_id,
                issue_id=issue_id,
                resources=lease.resources,
                owner_bac=lease.owner_bac,
                base_sha=lease.base_sha,
                issued_at=lease.issued_at,
                expires_at=new_expiry,
            )
            history.append(self._history_event("renewed", renewed, timestamp))
            self._validate_lease_history(issues, leases, history)
            self._write_unlocked(value)
            return renewed

    def release_lease(
        self,
        *,
        issue_id: str,
        lease_id: str,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        """Release all resources owned by a completed or blocked mutation lease."""
        timestamp = self._now(now)
        _require_text(issue_id, "issue_id")
        _require_text(lease_id, "lease_id")
        with self._locked():
            value = self._load_unlocked()
            issues = value["issues"]
            leases = value["resource_leases"]
            history = value["lease_history"]
            assert isinstance(issues, dict) and isinstance(leases, dict) and isinstance(history, list)
            issue = self._validated_issue(issues, issue_id)
            if issue.get("state") not in _TERMINAL_STATES:
                raise EvidenceContractError("lease can be released only after a terminal transition")
            lease = self._lease_for_issue(leases, issue, issue_id=issue_id, lease_id=lease_id)
            history.append(self._history_event("released", lease, timestamp))
            for resource in lease.resources:
                del leases[resource]
            self._validate_lease_history(issues, leases, history)
            self._write_unlocked(value)
            return lease.resources
