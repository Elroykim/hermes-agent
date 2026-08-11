"""Fail-closed P0 evidence contracts.

This module evaluates captured evidence only. It performs no Slack, runtime,
or ledger mutation, so a spinner, reply count, or health check cannot become a
PASS signal by itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping, Sequence


class EvidenceContractError(ValueError):
    """Captured P0 evidence is incomplete, stale, or not exactly bound."""


@dataclass(frozen=True)
class RoundtripContract:
    run_id: str
    channel_id: str
    parent_ts: str
    requester_user_id: str
    expected_agent_user_id: str


@dataclass(frozen=True)
class VerifiedRoundtrip:
    run_id: str
    agent_response_ts: str
    tool_artifact_sha256: str
    workflow_artifact_sha256: str
    blackbox_artifact_sha256: str


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceContractError(f"{name} must be non-empty")
    return value


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise EvidenceContractError(f"{name} must be a lowercase SHA-256")
    return value


def _ts(value: object, name: str) -> Decimal:
    raw = _text(value, name)
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise EvidenceContractError(f"{name} must be a Slack timestamp") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise EvidenceContractError(f"{name} must be a positive Slack timestamp")
    return parsed


def _artifact(value: object, name: str) -> str:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "size"}:
        raise EvidenceContractError(f"{name} artifact must have exact path/sha256/size fields")
    path = Path(_text(value.get("path"), f"{name} artifact path"))
    expected = _sha(value.get("sha256"), f"{name} artifact sha256")
    size = value.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise EvidenceContractError(f"{name} artifact size is invalid")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise EvidenceContractError(f"{name} artifact cannot be read") from exc
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != expected:
        raise EvidenceContractError(f"{name} artifact bytes do not match attestation")
    return expected


def _exact(value: object, keys: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EvidenceContractError(f"{name} has an invalid exact schema")
    return value


def _utc_iso(value: object, name: str) -> None:
    raw = _text(value, name)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceContractError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceContractError(f"{name} must be timezone-aware")


def verify_roundtrip(
    contract: RoundtripContract,
    messages: Sequence[Mapping[str, object]],
    evidence: Mapping[str, object],
) -> VerifiedRoundtrip:
    """Require one human-origin MINA terminal response and durable producer proof."""

    run_id = _text(contract.run_id, "run_id")
    channel_id = _text(contract.channel_id, "channel_id")
    parent_ts = _text(contract.parent_ts, "parent_ts")
    parent_time = _ts(parent_ts, "parent_ts")
    requester = _text(contract.requester_user_id, "requester_user_id")
    agent = _text(contract.expected_agent_user_id, "expected_agent_user_id")
    parents = [row for row in messages if row.get("ts") == parent_ts]
    if len(parents) != 1:
        raise EvidenceContractError("expected exactly one parent")
    parent = parents[0]
    if parent.get("user") != requester or parent.get("channel_id") != channel_id or parent.get("thread_ts") not in (None, parent_ts):
        raise EvidenceContractError("parent is not the expected human-origin message")

    terminals: list[Mapping[str, object]] = []
    for row in messages:
        metadata = row.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("p0_run_id") != run_id:
            continue
        if row.get("user") != agent:
            raise EvidenceContractError("run response is not from expected MINA")
        if row.get("channel_id") != channel_id or row.get("thread_ts") != parent_ts:
            raise EvidenceContractError("run response is outside canonical parent")
        if _ts(row.get("ts"), "response ts") <= parent_time:
            raise EvidenceContractError("run response predates parent")
        if metadata.get("terminal") is True:
            if not isinstance(row.get("text"), str) or not row["text"].strip():
                raise EvidenceContractError("terminal response is empty")
            terminals.append(row)
    if len(terminals) != 1:
        raise EvidenceContractError("expected exactly one terminal response")
    response_ts = _text(terminals[0].get("ts"), "response ts")

    tool = _exact(evidence.get("tool_result"), {"run_id", "message_ts", "channel_id", "thread_ts", "artifact"}, "tool_result")
    if (tool["run_id"], tool["message_ts"], tool["channel_id"], tool["thread_ts"]) != (run_id, response_ts, channel_id, parent_ts):
        raise EvidenceContractError("tool result is not exactly bound to terminal response")
    tool_sha = _artifact(tool["artifact"], "tool_result")

    workflow = _exact(evidence.get("workflow"), {"run_id", "execution_id", "engine_id", "captured_at", "parent_ts", "response_ts", "channel_id", "artifact"}, "workflow")
    if (workflow["run_id"], workflow["parent_ts"], workflow["response_ts"], workflow["channel_id"]) != (run_id, parent_ts, response_ts, channel_id):
        raise EvidenceContractError("workflow is not directly bound to Slack evidence")
    for field in ("execution_id", "engine_id"):
        _text(workflow[field], f"workflow {field}")
    _utc_iso(workflow["captured_at"], "workflow captured_at")
    workflow_sha = _artifact(workflow["artifact"], "workflow")

    blackbox = _exact(evidence.get("blackbox"), {"run_id", "event_id", "durable_payload_sha256", "durable_sqlite_receipt", "agent_id", "session_id", "runtime_source_or_image_digest", "parent_ts", "response_ts", "channel_id", "artifact"}, "blackbox")
    if (blackbox["run_id"], blackbox["agent_id"], blackbox["parent_ts"], blackbox["response_ts"], blackbox["channel_id"]) != (run_id, agent, parent_ts, response_ts, channel_id):
        raise EvidenceContractError("blackbox is not directly bound to Slack evidence")
    for field in ("event_id", "session_id"):
        _text(blackbox[field], f"blackbox {field}")
    receipt = _text(blackbox["durable_sqlite_receipt"], "blackbox durable_sqlite_receipt")
    if not receipt.startswith("sqlite:"):
        raise EvidenceContractError("blackbox durable receipt must name a SQLite receipt")
    _sha(blackbox["durable_payload_sha256"], "blackbox durable_payload_sha256")
    _sha(blackbox["runtime_source_or_image_digest"], "blackbox runtime source/image digest")
    blackbox_sha = _artifact(blackbox["artifact"], "blackbox")
    return VerifiedRoundtrip(run_id, response_ts, tool_sha, workflow_sha, blackbox_sha)
