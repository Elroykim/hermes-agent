"""Fail-closed offline contracts for TheWon P0 evidence.

This module validates captured bytes only. It does not contact Slack, start a
workflow, append Blackbox events, or mutate a ledger.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping, Sequence


class EvidenceContractError(ValueError):
    """P0 evidence is absent, malformed, stale, or not exactly bound."""


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


_DURABLE_COLUMNS = {
    "event_id": ("TEXT", 1),
    "agent_id": ("TEXT", 0),
    "payload_sha256": ("TEXT", 0),
    "row_json": ("TEXT", 0),
    "state": ("TEXT", 0),
    "attempt_count": ("INTEGER", 0),
    "created_at": ("TEXT", 0),
    "last_attempt_at": ("TEXT", 0),
    "delivered_at": ("TEXT", 0),
    "agent_path": ("TEXT", 0),
    "central_path": ("TEXT", 0),
}


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceContractError(f"{name} must be non-empty")
    return value


def _sha(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise EvidenceContractError(f"{name} must be a lowercase SHA-256")
    return value


def _ts(value: object, name: str) -> Decimal:
    try:
        result = Decimal(_text(value, name))
    except InvalidOperation as exc:
        raise EvidenceContractError(f"{name} must be a Slack timestamp") from exc
    if not result.is_finite() or result <= 0:
        raise EvidenceContractError(f"{name} must be a positive Slack timestamp")
    return result


def _iso(value: object, name: str) -> str:
    raw = _text(value, name)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceContractError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise EvidenceContractError(f"{name} must be timezone-aware")
    return raw


def _exact(value: object, keys: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EvidenceContractError(f"{name} has an invalid exact schema")
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceContractError("artifact JSON contains duplicate keys")
        result[key] = value
    return result


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceContractError("evidence JSON is not canonical") from exc


def _strict_json(raw: str, name: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicates)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceContractError(f"{name} is not strict JSON") from exc


def parse_terminal_metadata_json(raw: str) -> Mapping[str, object]:
    """Parse raw terminal metadata without allowing duplicate JSON keys."""

    return _exact(
        _strict_json(raw, "terminal metadata JSON"),
        {
            "p0_run_id",
            "terminal",
            "channel_id",
            "thread_ts",
            "response_ts",
            "tool_artifact_id",
        },
        "terminal metadata",
    )


def load_strict_json_document(path: Path) -> object:
    """Load an offline evidence input while rejecting duplicate object keys."""

    try:
        return _strict_json(path.read_text(encoding="utf-8"), "evidence document")
    except (OSError, UnicodeDecodeError) as exc:
        raise EvidenceContractError(f"cannot read strict JSON document: {path}") from exc


def _read_artifact(value: object, name: str) -> tuple[Mapping[str, object], str]:
    proof = _exact(value, {"path", "sha256", "size"}, f"{name} artifact proof")
    path = Path(_text(proof["path"], f"{name} artifact path"))
    expected_sha = _sha(proof["sha256"], f"{name} artifact sha256")
    size = proof["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise EvidenceContractError(f"{name} artifact size is invalid")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise EvidenceContractError(f"{name} artifact cannot be read") from exc
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != expected_sha:
        raise EvidenceContractError(f"{name} artifact bytes do not match proof")
    try:
        parsed = _strict_json(payload.decode("utf-8"), f"{name} artifact")
    except UnicodeDecodeError as exc:
        raise EvidenceContractError(f"{name} artifact is not UTF-8") from exc
    if not isinstance(parsed, Mapping):
        raise EvidenceContractError(f"{name} artifact must be a JSON object")
    return parsed, expected_sha


def _verify_tool(
    value: object,
    *,
    run_id: str,
    response_ts: str,
    channel_id: str,
    parent_ts: str,
) -> str:
    proof = _exact(
        value,
        {"run_id", "message_ts", "channel_id", "thread_ts", "artifact"},
        "tool_result",
    )
    if (
        proof["run_id"],
        proof["message_ts"],
        proof["channel_id"],
        proof["thread_ts"],
    ) != (run_id, response_ts, channel_id, parent_ts):
        raise EvidenceContractError("tool result is not bound to the terminal response")
    artifact, digest = _read_artifact(proof["artifact"], "tool_result")
    parsed = _exact(
        artifact,
        {"artifact_id", "run_id", "response_ts"},
        "tool result artifact",
    )
    if parsed["run_id"] != run_id or parsed["response_ts"] != response_ts:
        raise EvidenceContractError("tool artifact is not bound to the terminal response")
    _text(parsed["artifact_id"], "tool artifact id")
    return digest


def _verify_workflow(
    value: object,
    *,
    run_id: str,
    response_ts: str,
    channel_id: str,
    parent_ts: str,
) -> str:
    proof = _exact(
        value,
        {
            "run_id",
            "execution_id",
            "engine_id",
            "captured_at",
            "parent_ts",
            "response_ts",
            "channel_id",
            "artifact",
        },
        "workflow",
    )
    artifact, digest = _read_artifact(proof["artifact"], "workflow")
    record = _exact(
        artifact,
        {
            "schema_version",
            "run_id",
            "execution_id",
            "engine_id",
            "captured_at",
            "slack",
        },
        "workflow artifact",
    )
    slack = _exact(
        record["slack"],
        {"channel_id", "parent_ts", "response_ts"},
        "workflow artifact Slack binding",
    )
    if record["schema_version"] != "thewon-p0-workflow-artifact/v1":
        raise EvidenceContractError("workflow artifact schema version is invalid")
    expected = (
        run_id,
        proof["execution_id"],
        proof["engine_id"],
        proof["captured_at"],
        parent_ts,
        response_ts,
        channel_id,
    )
    actual = (
        proof["run_id"],
        record["execution_id"],
        record["engine_id"],
        record["captured_at"],
        proof["parent_ts"],
        proof["response_ts"],
        proof["channel_id"],
    )
    internal = (
        record["run_id"],
        record["execution_id"],
        record["engine_id"],
        record["captured_at"],
        slack["parent_ts"],
        slack["response_ts"],
        slack["channel_id"],
    )
    if actual != expected or internal != expected:
        raise EvidenceContractError(
            "workflow proof and immutable artifact are not exactly bound"
        )
    _text(proof["execution_id"], "workflow execution id")
    _text(proof["engine_id"], "workflow engine id")
    _iso(proof["captured_at"], "workflow capture time")
    return digest


def _verify_durable_schema(connection: sqlite3.Connection) -> None:
    try:
        rows = connection.execute("PRAGMA table_info(durable_receipts)").fetchall()
    except sqlite3.Error as exc:
        raise EvidenceContractError("blackbox durable SQLite schema is unqueryable") from exc
    observed = {
        str(row[1]): (str(row[2]).upper(), int(row[5]))
        for row in rows
    }
    if observed != _DURABLE_COLUMNS:
        raise EvidenceContractError("blackbox durable SQLite schema is incompatible")


def _projection_identity(
    path: Path,
    *,
    event_id: str,
    payload_sha256: str,
    durable_row_json: str,
    name: str,
) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise EvidenceContractError(f"blackbox {name} projection cannot be read") from exc
    matches = 0
    for line in lines:
        value = _strict_json(line, f"blackbox {name} projection row")
        if not isinstance(value, Mapping):
            raise EvidenceContractError(f"blackbox {name} projection row is not an object")
        if value.get("id") != event_id:
            continue
        if value.get("durable_payload_sha256") != payload_sha256:
            raise EvidenceContractError(f"blackbox {name} projection event is mismatched")
        if _canonical(value) != durable_row_json:
            raise EvidenceContractError(f"blackbox {name} projection row_json is mismatched")
        matches += 1
    if matches != 1:
        raise EvidenceContractError(f"blackbox {name} projection event identity is not unique")


def _verify_blackbox(
    value: object,
    *,
    run_id: str,
    response_ts: str,
    channel_id: str,
    parent_ts: str,
    agent: str,
) -> str:
    keys = {
        "event_id",
        "run_id",
        "agent_id",
        "session_id",
        "runtime_source_or_image_digest",
        "durable_payload_sha256",
        "parent_ts",
        "response_ts",
        "channel_id",
        "artifact",
        "durable_sqlite",
    }
    proof = _exact(value, keys, "blackbox")
    artifact, digest = _read_artifact(proof["artifact"], "blackbox")
    record = _exact(
        artifact,
        {
            "schema_version",
            "event_id",
            "run_id",
            "agent_id",
            "session_id",
            "runtime_source_or_image_digest",
            "durable_payload_sha256",
            "slack",
            "projection",
        },
        "blackbox event artifact",
    )
    slack = _exact(
        record["slack"],
        {"channel_id", "parent_ts", "response_ts"},
        "blackbox artifact Slack binding",
    )
    projection = _exact(
        record["projection"],
        {"agent_path", "central_path", "row"},
        "blackbox artifact projection",
    )
    if record["schema_version"] != "thewon-p0-blackbox-event/v2":
        raise EvidenceContractError("blackbox artifact schema version is invalid")
    expected = (run_id, agent, parent_ts, response_ts, channel_id)
    if (
        proof["run_id"],
        proof["agent_id"],
        proof["parent_ts"],
        proof["response_ts"],
        proof["channel_id"],
    ) != expected:
        raise EvidenceContractError("blackbox proof is not bound to the terminal response")
    if (
        record["run_id"],
        record["agent_id"],
        slack["parent_ts"],
        slack["response_ts"],
        slack["channel_id"],
    ) != expected:
        raise EvidenceContractError("blackbox event is not bound to the terminal response")
    for key in (
        "event_id",
        "session_id",
        "runtime_source_or_image_digest",
        "durable_payload_sha256",
    ):
        if proof[key] != record[key]:
            raise EvidenceContractError(f"blackbox {key} differs from immutable event")
    event_id = _text(proof["event_id"], "blackbox event id")
    _text(proof["session_id"], "blackbox session id")
    _sha(proof["runtime_source_or_image_digest"], "blackbox runtime digest")
    payload_sha = _sha(proof["durable_payload_sha256"], "blackbox payload digest")
    projection_row = projection["row"]
    if not isinstance(projection_row, Mapping):
        raise EvidenceContractError("blackbox artifact projection row is invalid")
    if (
        projection_row.get("id"),
        projection_row.get("agent_id"),
        projection_row.get("durable_payload_sha256"),
    ) != (event_id, agent, payload_sha):
        raise EvidenceContractError("blackbox artifact projection row is not bound")
    durable = _exact(proof["durable_sqlite"], {"path"}, "blackbox durable SQLite proof")
    db_path = Path(_text(durable["path"], "blackbox SQLite path"))
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        _verify_durable_schema(connection)
        rows = connection.execute(
            "SELECT event_id, agent_id, payload_sha256, row_json, state, "
            "agent_path, central_path FROM durable_receipts WHERE event_id = ?",
            (event_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise EvidenceContractError("blackbox durable SQLite receipt is unqueryable") from exc
    finally:
        if "connection" in locals():
            connection.close()
    if len(rows) != 1:
        raise EvidenceContractError("blackbox durable SQLite event is missing or ambiguous")
    row = rows[0]
    if tuple(row[:3]) != (event_id, agent, payload_sha) or row[4] != "delivered":
        raise EvidenceContractError("blackbox durable SQLite event fields are not bound")
    row_json = _text(row[3], "blackbox durable SQLite row_json")
    parsed_row = _strict_json(row_json, "blackbox durable SQLite row_json")
    if not isinstance(parsed_row, Mapping) or _canonical(parsed_row) != row_json:
        raise EvidenceContractError("blackbox durable SQLite row_json is not canonical")
    if _canonical(projection_row) != row_json:
        raise EvidenceContractError("blackbox durable SQLite row_json differs from artifact")
    agent_path = _text(row[5], "blackbox durable SQLite agent path")
    central_path = _text(row[6], "blackbox durable SQLite central path")
    if (projection["agent_path"], projection["central_path"]) != (agent_path, central_path):
        raise EvidenceContractError("blackbox projection paths differ from durable receipt")
    _projection_identity(
        Path(agent_path),
        event_id=event_id,
        payload_sha256=payload_sha,
        durable_row_json=row_json,
        name="agent",
    )
    _projection_identity(
        Path(central_path),
        event_id=event_id,
        payload_sha256=payload_sha,
        durable_row_json=row_json,
        name="central",
    )
    return digest


def verify_roundtrip(
    contract: RoundtripContract,
    messages: Sequence[Mapping[str, object]],
    evidence: Mapping[str, object],
) -> VerifiedRoundtrip:
    """Validate one human-origin MINA terminal result with producer evidence."""

    run_id = _text(contract.run_id, "run_id")
    channel_id = _text(contract.channel_id, "channel_id")
    parent_ts = _text(contract.parent_ts, "parent ts")
    parent_time = _ts(parent_ts, "parent ts")
    requester = _text(contract.requester_user_id, "requester")
    agent = _text(contract.expected_agent_user_id, "expected MINA")
    parents = [row for row in messages if row.get("ts") == parent_ts]
    if len(parents) != 1 or (
        parents[0].get("user"),
        parents[0].get("channel_id"),
        parents[0].get("thread_ts"),
    ) != (requester, channel_id, parent_ts):
        raise EvidenceContractError("expected exactly one human-origin parent")
    terminals: list[tuple[Mapping[str, object], Mapping[str, object]]] = []
    for row in messages:
        metadata = row.get("metadata")
        if not isinstance(metadata, Mapping) or metadata.get("p0_run_id") != run_id:
            continue
        metadata = _exact(
            metadata,
            {
                "p0_run_id",
                "terminal",
                "channel_id",
                "thread_ts",
                "response_ts",
                "tool_artifact_id",
            },
            "terminal metadata",
        )
        if (
            row.get("user") != agent
            or row.get("channel_id") != channel_id
            or row.get("thread_ts") != parent_ts
        ):
            raise EvidenceContractError("terminal belongs to another agent or thread")
        if _ts(row.get("ts"), "terminal ts") <= parent_time or row.get("ts") != metadata["response_ts"]:
            raise EvidenceContractError("terminal response timestamp is invalid")
        if metadata["terminal"] is not True or not isinstance(row.get("text"), str) or not row["text"].strip():
            raise EvidenceContractError("terminal response is empty or non-terminal")
        terminals.append((row, metadata))
    if len(terminals) != 1:
        raise EvidenceContractError("expected exactly one terminal response")
    terminal, metadata = terminals[0]
    response_ts = _text(terminal["ts"], "terminal response ts")
    tool_sha = _verify_tool(
        evidence.get("tool_result"),
        run_id=run_id,
        response_ts=response_ts,
        channel_id=channel_id,
        parent_ts=parent_ts,
    )
    tool_proof = _exact(
        evidence["tool_result"],
        {"run_id", "message_ts", "channel_id", "thread_ts", "artifact"},
        "tool_result",
    )
    tool_artifact, _ = _read_artifact(tool_proof["artifact"], "tool_result")
    if tool_artifact["artifact_id"] != metadata["tool_artifact_id"]:
        raise EvidenceContractError("terminal does not bind the tool artifact")
    workflow_sha = _verify_workflow(
        evidence.get("workflow"),
        run_id=run_id,
        response_ts=response_ts,
        channel_id=channel_id,
        parent_ts=parent_ts,
    )
    blackbox_sha = _verify_blackbox(
        evidence.get("blackbox"),
        run_id=run_id,
        response_ts=response_ts,
        channel_id=channel_id,
        parent_ts=parent_ts,
        agent=agent,
    )
    return VerifiedRoundtrip(
        run_id,
        response_ts,
        tool_sha,
        workflow_sha,
        blackbox_sha,
    )
