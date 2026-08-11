from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hermes_cli.thewon_p0_evidence import (
    EvidenceContractError,
    RoundtripContract,
    verify_roundtrip,
)


RUN_ID = "p0-r6-run-001"
CHANNEL = "C0BLPP2N6BX"
PARENT = "1780000000.000001"
RESPONSE = "1780000001.000001"
MINA = "U0BFXDNTS2D"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact(tmp_path: Path, name: str, payload: bytes) -> dict[str, object]:
    path = tmp_path / name
    path.write_bytes(payload)
    return {"path": str(path), "sha256": _sha(path), "size": len(payload)}


def _contract() -> RoundtripContract:
    return RoundtripContract(
        run_id=RUN_ID,
        channel_id=CHANNEL,
        parent_ts=PARENT,
        requester_user_id="U0APE8BDM0W",
        expected_agent_user_id=MINA,
    )


def _messages(*, agent: str = MINA, text: str = "done", terminal: bool = True):
    return [
        {"ts": PARENT, "channel_id": CHANNEL, "thread_ts": PARENT, "user": "U0APE8BDM0W", "text": "run"},
        {
            "ts": RESPONSE,
            "channel_id": CHANNEL,
            "thread_ts": PARENT,
            "user": agent,
            "text": text,
            "metadata": {"p0_run_id": RUN_ID, "terminal": terminal},
        },
    ]


def _evidence(tmp_path: Path):
    tool = _artifact(tmp_path, "tool.json", b'{"ok":true}')
    workflow = _artifact(tmp_path, "workflow.json", b'{"execution":"wf-1"}')
    blackbox = _artifact(tmp_path, "blackbox.json", b'{"event":"bb-1"}')
    return {
        "tool_result": {"run_id": RUN_ID, "message_ts": RESPONSE, "channel_id": CHANNEL, "thread_ts": PARENT, "artifact": tool},
        "workflow": {"run_id": RUN_ID, "execution_id": "wf-1", "engine_id": "workflow-controller/v1", "captured_at": "2026-08-11T00:00:00Z", "parent_ts": PARENT, "response_ts": RESPONSE, "channel_id": CHANNEL, "artifact": workflow},
        "blackbox": {"run_id": RUN_ID, "event_id": "bb-1", "durable_payload_sha256": "a" * 64, "durable_sqlite_receipt": "sqlite:receipt-1", "agent_id": MINA, "session_id": "session-1", "runtime_source_or_image_digest": "b" * 64, "parent_ts": PARENT, "response_ts": RESPONSE, "channel_id": CHANNEL, "artifact": blackbox},
    }


def test_roundtrip_requires_bound_human_mina_terminal_and_real_artifact_bytes(tmp_path: Path):
    result = verify_roundtrip(_contract(), _messages(), _evidence(tmp_path))
    assert result.run_id == RUN_ID
    assert result.agent_response_ts == RESPONSE


@pytest.mark.parametrize("mutator", [
    lambda messages, evidence: messages.__setitem__(1, {**messages[1], "user": "U_OTHER"}),
    lambda messages, evidence: messages.__setitem__(1, {**messages[1], "text": ""}),
    lambda messages, evidence: evidence["workflow"].__setitem__("execution_id", ""),
    lambda messages, evidence: evidence["blackbox"].__setitem__("durable_sqlite_receipt", ""),
    lambda messages, evidence: evidence["workflow"].__setitem__("response_ts", "1780000999.000001"),
    lambda messages, evidence: evidence["tool_result"]["artifact"].__setitem__("sha256", "0" * 64),
])
def test_roundtrip_rejects_wrong_agent_empty_reply_missing_producer_binding_or_tampered_bytes(tmp_path: Path, mutator):
    messages = _messages()
    evidence = _evidence(tmp_path)
    mutator(messages, evidence)
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, evidence)


def test_roundtrip_rejects_loose_success_status_aliases(tmp_path: Path):
    evidence = _evidence(tmp_path)
    evidence["workflow"]["status"] = "completed"
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)
