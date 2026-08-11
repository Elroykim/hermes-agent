from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from hermes_cli.thewon_p0_evidence import (
    EvidenceContractError,
    RoundtripContract,
    parse_terminal_metadata_json,
    verify_roundtrip,
)


RUN_ID = "p0-r7-run-001"
CHANNEL = "C0BLPP2N6BX"
PARENT = "1780000000.000001"
RESPONSE = "1780000001.000001"
MINA = "U0BFXDNTS2D"
RUNTIME = "b" * 64


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _artifact(tmp_path: Path, name: str, value: dict[str, object]) -> dict[str, object]:
    path = tmp_path / name
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(payload)
    return {"path": str(path), "sha256": _sha(payload), "size": len(payload)}


def _durable_db(tmp_path: Path, event: dict[str, object]) -> dict[str, object]:
    path = tmp_path / "durable.sqlite3"
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE durable_receipts (receipt_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO durable_receipts VALUES (?, ?, ?)",
        ("receipt-1", event["event_id"], event["durable_payload_sha256"]),
    )
    connection.commit()
    connection.close()
    return {"path": str(path), "receipt_id": "receipt-1"}


def _contract() -> RoundtripContract:
    return RoundtripContract(RUN_ID, CHANNEL, PARENT, "U0APE8BDM0W", MINA)


def _messages(metadata: dict[str, object] | None = None, *, agent: str = MINA, text: str = "done"):
    return [
        {"ts": PARENT, "channel_id": CHANNEL, "thread_ts": PARENT, "user": "U0APE8BDM0W", "text": "run"},
        {
            "ts": RESPONSE,
            "channel_id": CHANNEL,
            "thread_ts": PARENT,
            "user": agent,
            "text": text,
            "metadata": metadata or {
                "p0_run_id": RUN_ID,
                "terminal": True,
                "channel_id": CHANNEL,
                "thread_ts": PARENT,
                "response_ts": RESPONSE,
                "tool_artifact_id": "tool-1",
            },
        },
    ]


def _evidence(tmp_path: Path):
    tool = _artifact(tmp_path, "tool.json", {"artifact_id": "tool-1", "run_id": RUN_ID, "response_ts": RESPONSE})
    workflow_record = {
        "schema_version": "thewon-p0-workflow-artifact/v1",
        "run_id": RUN_ID,
        "execution_id": "wf-1",
        "engine_id": "workflow-controller/v1",
        "captured_at": "2026-08-11T00:00:00Z",
        "slack": {"channel_id": CHANNEL, "parent_ts": PARENT, "response_ts": RESPONSE},
    }
    workflow = _artifact(tmp_path, "workflow.json", workflow_record)
    payload_sha = _sha(b"blackbox payload")
    blackbox_record = {
        "schema_version": "thewon-p0-blackbox-event/v1",
        "event_id": "bb-1",
        "run_id": RUN_ID,
        "agent_id": MINA,
        "session_id": "session-1",
        "runtime_source_or_image_digest": RUNTIME,
        "durable_payload_sha256": payload_sha,
        "slack": {"channel_id": CHANNEL, "parent_ts": PARENT, "response_ts": RESPONSE},
    }
    blackbox = _artifact(tmp_path, "blackbox.json", blackbox_record)
    return {
        "tool_result": {"run_id": RUN_ID, "message_ts": RESPONSE, "channel_id": CHANNEL, "thread_ts": PARENT, "artifact": tool},
        "workflow": {**{key: workflow_record[key] for key in ("run_id", "execution_id", "engine_id", "captured_at")}, "parent_ts": PARENT, "response_ts": RESPONSE, "channel_id": CHANNEL, "artifact": workflow},
        "blackbox": {**{key: blackbox_record[key] for key in ("event_id", "run_id", "agent_id", "session_id", "runtime_source_or_image_digest", "durable_payload_sha256")}, "parent_ts": PARENT, "response_ts": RESPONSE, "channel_id": CHANNEL, "artifact": blackbox, "durable_sqlite": _durable_db(tmp_path, blackbox_record)},
    }


def test_roundtrip_requires_real_workflow_blackbox_and_terminal_contract(tmp_path: Path):
    result = verify_roundtrip(_contract(), _messages(), _evidence(tmp_path))
    assert result.run_id == RUN_ID
    assert result.agent_response_ts == RESPONSE


@pytest.mark.parametrize("mutate", [
    lambda messages, evidence: messages[1]["metadata"].__setitem__("unknown", True),
    lambda messages, evidence: messages[1].__setitem__("user", "U_OTHER"),
    lambda messages, evidence: messages[1].__setitem__("text", ""),
    lambda messages, evidence: messages[1]["metadata"].__setitem__("response_ts", PARENT),
    lambda messages, evidence: evidence["workflow"].__setitem__("execution_id", "other"),
    lambda messages, evidence: evidence["workflow"].__setitem__("response_ts", "1780000999.000001"),
    lambda messages, evidence: evidence["blackbox"].__setitem__("event_id", "other"),
    lambda messages, evidence: evidence["blackbox"]["durable_sqlite"].__setitem__("receipt_id", "other"),
    lambda messages, evidence: evidence["tool_result"]["artifact"].__setitem__("sha256", "0" * 64),
])
def test_roundtrip_rejects_terminal_schema_and_cross_producer_mismatches(tmp_path: Path, mutate):
    messages = _messages()
    evidence = _evidence(tmp_path)
    mutate(messages, evidence)
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, evidence)


def test_roundtrip_rejects_altered_artifact_and_sql_payload_mismatch(tmp_path: Path):
    evidence = _evidence(tmp_path)
    Path(evidence["workflow"]["artifact"]["path"]).write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)

    evidence = _evidence(tmp_path)
    db = sqlite3.connect(evidence["blackbox"]["durable_sqlite"]["path"])
    db.execute("UPDATE durable_receipts SET event_id = ?", ("other-event",))
    db.commit()
    db.close()
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)


@pytest.mark.parametrize("raw", [
    '{"p0_run_id":"x","p0_run_id":"x"}',
    '{"p0_run_id":"x","terminal":true}',
    '{"p0_run_id":"x","terminal":true,"channel_id":"c","thread_ts":"t","response_ts":"r","tool_artifact_id":"a","extra":1}',
])
def test_terminal_metadata_rejects_duplicate_missing_and_unknown_fields(raw: str):
    with pytest.raises(EvidenceContractError):
        parse_terminal_metadata_json(raw)


@pytest.mark.parametrize("section,field,value", [
    ("workflow", "run_id", "other-run"),
    ("workflow", "captured_at", "2026-08-11T00:00:00"),
    ("blackbox", "runtime_source_or_image_digest", "0" * 64),
    ("blackbox", "durable_payload_sha256", "0" * 64),
])
def test_roundtrip_rejects_cross_run_and_internal_artifact_mismatch(tmp_path: Path, section: str, field: str, value: object):
    evidence = _evidence(tmp_path)
    path = Path(evidence[section]["artifact"]["path"])
    record = json.loads(path.read_text(encoding="utf-8"))
    record[field] = value
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(payload)
    evidence[section]["artifact"].update({"sha256": _sha(payload), "size": len(payload)})
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)


@pytest.mark.parametrize("section,change", [
    ("workflow", lambda record: record.__setitem__("unknown", True)),
    ("workflow", lambda record: record.pop("engine_id")),
    ("blackbox", lambda record: record["slack"].__setitem__("wrong", "value")),
])
def test_roundtrip_rejects_unknown_or_missing_immutable_artifact_fields(tmp_path: Path, section: str, change):
    evidence = _evidence(tmp_path)
    path = Path(evidence[section]["artifact"]["path"])
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(payload)
    evidence[section]["artifact"].update({"sha256": _sha(payload), "size": len(payload)})
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)

    evidence = _evidence(tmp_path)
    db = sqlite3.connect(evidence["blackbox"]["durable_sqlite"]["path"])
    db.execute("UPDATE durable_receipts SET payload_sha256 = ?", ("0" * 64,))
    db.commit()
    db.close()
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)
