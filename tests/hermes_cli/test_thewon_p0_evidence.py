from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from hermes_cli.thewon_p0_evidence import (
    EvidenceContractError,
    IssueLedger,
    LeaseConflict,
    RoundtripContract,
    canonical_sha256,
    verify_roundtrip,
)


_CHANNEL = "C_P0"
_PARENT_TS = "1780000000.000001"
_REPLY_TS = "1780000001.000001"
_RUN_ID = "p0-run-001"
_BASE_SHA = "a" * 40
_RESOURCES = (
    "runtime:mina-review-hook",
    "slack:C_P0:1780000000.000001",
)
_BOUNDARY = (
    "hermes_cli/thewon_p0_review.py",
    "runtime:mina-review-hook",
    "slack:C_P0",
)


def _sha(value: object) -> str:
    return canonical_sha256(value)


def _contract(**overrides: str) -> RoundtripContract:
    values = {
        "run_id": _RUN_ID,
        "parent_ts": _PARENT_TS,
        "owner_user_id": "U_OWNER",
        "expected_agent_user_id": "U_CK",
        "workflow_run_id": _RUN_ID,
        "blackbox_run_id": _RUN_ID,
        "channel_id": _CHANNEL,
    }
    values.update(overrides)
    return RoundtripContract(**values)


def _durable_artifact(name: str, digest_character: str) -> dict[str, str]:
    return {"path": f"evidence/{name}.json", "sha256": digest_character * 64}


def _evidence() -> dict[str, object]:
    return {
        "tool_result": {
            "run_id": _RUN_ID,
            "status": "succeeded",
            "message_ts": _REPLY_TS,
            "channel": _CHANNEL,
            "thread_ts": _PARENT_TS,
            "result": {"ok": True, "summary": "tool completed"},
            "artifact": _durable_artifact("tool-result", "a"),
        },
        "workflow": {
            "run_id": _RUN_ID,
            "status": "completed",
            "result": {"state": "completed"},
            "artifact": _durable_artifact("workflow", "b"),
        },
        "blackbox": {
            "run_id": _RUN_ID,
            "status": "succeeded",
            "result": {"state": "completed"},
            "artifact": _durable_artifact("blackbox", "c"),
        },
    }


def _messages(
    *,
    agent_user: str = "U_CK",
    text: str = "completed",
    terminal: bool = True,
    parent_channel: str = _CHANNEL,
    reply_channel: str = _CHANNEL,
    reply_thread_ts: str = _PARENT_TS,
) -> list[dict[str, object]]:
    return [
        {
            "ts": _PARENT_TS,
            "thread_ts": _PARENT_TS,
            "channel": parent_channel,
            "user": "U_OWNER",
            "text": f"run {_RUN_ID}",
        },
        {
            "ts": _REPLY_TS,
            "thread_ts": reply_thread_ts,
            "channel": reply_channel,
            "user": agent_user,
            "text": text,
            "metadata": {"p0_run_id": _RUN_ID, "terminal": terminal},
        },
    ]


def _open_ledger(tmp_path, *, issue_id: str = "P0-HOOK-001", owner_bac: str = "CK") -> IssueLedger:
    ledger = IssueLedger(tmp_path / "ledger.json")
    ledger.open_issue(
        issue_id=issue_id,
        owner_bac=owner_bac,
        base_sha=_BASE_SHA,
        mutation_boundary=_BOUNDARY,
        rollback="git revert <commit>",
    )
    return ledger


def _acquire(ledger: IssueLedger, *, issue_id: str = "P0-HOOK-001", now: datetime):
    return ledger.acquire_lease(
        issue_id=issue_id,
        resources=_RESOURCES,
        owner_bac="CK",
        base_sha=_BASE_SHA,
        ttl=timedelta(minutes=10),
        now=now,
    )


def _transition(
    ledger: IssueLedger,
    lease_id: str,
    *,
    state: str,
    now: datetime,
    validation: dict[str, object] | None = None,
    artifacts: list[dict[str, str]] | None = None,
    pre_state_digest: str | None = None,
) -> dict[str, object]:
    return ledger.record_transition(
        issue_id="P0-HOOK-001",
        lease_id=lease_id,
        state=state,
        pre_state_digest=pre_state_digest or ledger.state_digest(issue_id="P0-HOOK-001"),
        artifacts=artifacts or [{"path": "hermes_cli/thewon_p0_review.py", "sha256": "d" * 64}],
        validation=validation or {"passed": True, "command": "pytest tests/hermes_cli/test_thewon_p0_evidence.py"},
        now=now,
    )


def test_roundtrip_requires_thread_bound_nonempty_terminal_and_shared_durable_artifacts():
    result = verify_roundtrip(_contract(), _messages(), _evidence())

    assert result.agent_response_ts == _REPLY_TS
    assert result.tool_result_sha256 == _sha(_evidence()["tool_result"])
    assert result.workflow_sha256 == _sha(_evidence()["workflow"])
    assert result.blackbox_sha256 == _sha(_evidence()["blackbox"])


def test_roundtrip_accepts_a_root_parent_without_thread_ts():
    messages = _messages()
    messages[0].pop("thread_ts")

    result = verify_roundtrip(_contract(), messages, _evidence())

    assert result.agent_response_ts == _REPLY_TS


def test_roundtrip_rejects_a_root_parent_with_a_different_thread_ts():
    messages = _messages()
    messages[0]["thread_ts"] = "1780000999.000001"

    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, _evidence())


@pytest.mark.parametrize(
    "messages",
    [
        _messages(agent_user="U_OTHER"),
        _messages(text=""),
        _messages(terminal=False),
        _messages(parent_channel="C_OTHER"),
        _messages(reply_channel="C_OTHER"),
        _messages(reply_thread_ts="1780000999.000001"),
    ],
)
def test_roundtrip_rejects_unrelated_or_nonterminal_replies(messages):
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, _evidence())


def test_roundtrip_rejects_a_claimed_run_reply_from_another_thread_even_with_a_valid_reply():
    messages = _messages()
    unrelated = dict(messages[1])
    unrelated["ts"] = "1780000002.000001"
    unrelated["thread_ts"] = "1780000999.000001"
    messages.append(unrelated)

    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, _evidence())


def test_roundtrip_rejects_an_empty_claimed_terminal_reply_even_with_a_valid_reply():
    messages = _messages()
    empty = dict(messages[1])
    empty["ts"] = "1780000002.000001"
    empty["text"] = ""
    messages.append(empty)

    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, _evidence())


@pytest.mark.parametrize("artifact_key", ["tool_result", "workflow", "blackbox"])
def test_roundtrip_rejects_failed_or_non_durable_artifacts(artifact_key):
    evidence = _evidence()
    artifact = evidence[artifact_key]
    assert isinstance(artifact, dict)
    artifact["status"] = "failed"

    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)

    evidence = _evidence()
    artifact = evidence[artifact_key]
    assert isinstance(artifact, dict)
    artifact.pop("artifact")
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)


def test_roundtrip_rejects_mixed_run_ids_and_empty_terminal_result():
    evidence = _evidence()
    workflow = evidence["workflow"]
    assert isinstance(workflow, dict)
    workflow["run_id"] = "other-run"
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)

    evidence = _evidence()
    tool = evidence["tool_result"]
    assert isinstance(tool, dict)
    tool["result"] = {}
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)

    evidence = _evidence()
    workflow = evidence["workflow"]
    assert isinstance(workflow, dict)
    workflow["result"] = {"state": "failed"}
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), _messages(), evidence)


def test_issue_ledger_serializes_leases_and_requires_terminal_lifecycle(tmp_path):
    ledger = _open_ledger(tmp_path)
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    lease = _acquire(ledger, now=now)

    with pytest.raises(LeaseConflict):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:mina-review-hook"],
            owner_bac="CK",
            base_sha=_BASE_SHA,
            ttl=timedelta(minutes=10),
            now=now + timedelta(minutes=1),
        )
    with pytest.raises(EvidenceContractError):
        ledger.release_lease(issue_id="P0-HOOK-001", lease_id=lease.lease_id)

    event = _transition(ledger, lease.lease_id, state="candidate_bound", now=now + timedelta(minutes=2))
    assert event["lease_id"] == lease.lease_id
    assert ledger.read()["issues"]["P0-HOOK-001"]["transitions"][0]["state"] == "candidate_bound"

    renewed = ledger.renew_lease(
        issue_id="P0-HOOK-001",
        lease_id=lease.lease_id,
        ttl=timedelta(minutes=10),
        now=now + timedelta(minutes=2),
    )
    assert renewed.expires_at == "2026-08-11T00:12:00Z"

    _transition(ledger, lease.lease_id, state="audit_ready", now=now + timedelta(minutes=3))
    with pytest.raises(EvidenceContractError):
        ledger.renew_lease(
            issue_id="P0-HOOK-001",
            lease_id=lease.lease_id,
            ttl=timedelta(minutes=10),
            now=now + timedelta(minutes=3),
        )
    assert ledger.release_lease(
        issue_id="P0-HOOK-001",
        lease_id=lease.lease_id,
        now=now + timedelta(minutes=3),
    ) == _RESOURCES
    released_ledger = ledger.read()
    assert released_ledger["resource_leases"] == {}
    history = released_ledger["lease_history"]
    assert [entry["event"] for entry in history] == ["acquired", "renewed", "released"]
    assert history[-1] == {
        "event": "released",
        "lease_id": lease.lease_id,
        "issue_id": "P0-HOOK-001",
        "resources": list(_RESOURCES),
        "owner_bac": "CK",
        "base_sha": _BASE_SHA,
        "issued_at": "2026-08-11T00:00:00Z",
        "expires_at": "2026-08-11T00:12:00Z",
        "recorded_at": "2026-08-11T00:03:00Z",
    }

    replacement = _open_ledger(tmp_path, issue_id="P0-HOOK-002", owner_bac="EV")
    next_lease = replacement.acquire_lease(
        issue_id="P0-HOOK-002",
        resources=["runtime:mina-review-hook"],
        owner_bac="EV",
        base_sha=_BASE_SHA,
        ttl=timedelta(minutes=10),
        now=now + timedelta(minutes=3),
    )
    assert next_lease.owner_bac == "EV"


def test_issue_ledger_migrates_absent_lease_history_to_an_empty_canonical_list(tmp_path):
    ledger = _open_ledger(tmp_path)
    legacy_ledger = ledger.read()
    legacy_ledger.pop("lease_history")
    ledger.path.write_text(json.dumps(legacy_ledger), encoding="utf-8")

    assert ledger.read()["lease_history"] == []


def test_issue_ledger_rejects_a_tampered_final_release_history_record(tmp_path):
    ledger = _open_ledger(tmp_path)
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    lease = _acquire(ledger, now=now)
    _transition(ledger, lease.lease_id, state="candidate_bound", now=now + timedelta(minutes=1))
    _transition(ledger, lease.lease_id, state="audit_ready", now=now + timedelta(minutes=2))
    ledger.release_lease(issue_id="P0-HOOK-001", lease_id=lease.lease_id, now=now + timedelta(minutes=3))

    stored = ledger.read()
    history = stored["lease_history"]
    assert isinstance(history, list)
    history[-1]["resources"] = ["runtime:mina-review-hook"]
    ledger.path.write_text(json.dumps(stored), encoding="utf-8")

    with pytest.raises(EvidenceContractError):
        ledger.read()


def test_issue_ledger_rejects_owner_resource_and_base_drift(tmp_path):
    ledger = _open_ledger(tmp_path)
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)

    with pytest.raises(EvidenceContractError):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:mina-review-hook"],
            owner_bac="EV",
            base_sha=_BASE_SHA,
            ttl=timedelta(minutes=10),
            now=now,
        )
    with pytest.raises(EvidenceContractError):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:outside-boundary"],
            owner_bac="CK",
            base_sha=_BASE_SHA,
            ttl=timedelta(minutes=10),
            now=now,
        )
    with pytest.raises(EvidenceContractError):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:mina-review-hook"],
            owner_bac="CK",
            base_sha="b" * 40,
            ttl=timedelta(minutes=10),
            now=now,
        )


@pytest.mark.parametrize(("field", "replacement"), [("owner_bac", "EV"), ("base_sha", "b" * 40)])
def test_transition_rejects_tampered_lease_authority(tmp_path, field, replacement):
    ledger = _open_ledger(tmp_path)
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    lease = _acquire(ledger, now=now)
    stored = ledger.read()
    for row in stored["resource_leases"].values():
        assert isinstance(row, dict)
        row[field] = replacement
    ledger.path.write_text(json.dumps(stored), encoding="utf-8")

    with pytest.raises(EvidenceContractError):
        _transition(ledger, lease.lease_id, state="candidate_bound", now=now + timedelta(minutes=1))


def test_transition_requires_legal_state_digest_and_prerequisite_evidence(tmp_path):
    ledger = _open_ledger(tmp_path)
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    lease = _acquire(ledger, now=now)

    with pytest.raises(EvidenceContractError):
        _transition(ledger, lease.lease_id, state="arbitrary", now=now + timedelta(minutes=1))
    with pytest.raises(EvidenceContractError):
        _transition(ledger, lease.lease_id, state="audit_ready", now=now + timedelta(minutes=1))
    with pytest.raises(EvidenceContractError):
        _transition(
            ledger,
            lease.lease_id,
            state="candidate_bound",
            validation={"passed": False},
            now=now + timedelta(minutes=1),
        )
    with pytest.raises(EvidenceContractError):
        _transition(
            ledger,
            lease.lease_id,
            state="candidate_bound",
            artifacts=[{"path": "docs/outside-boundary.json", "sha256": "d" * 64}],
            now=now + timedelta(minutes=1),
        )
    with pytest.raises(EvidenceContractError):
        _transition(
            ledger,
            lease.lease_id,
            state="candidate_bound",
            pre_state_digest="e" * 64,
            now=now + timedelta(minutes=1),
        )

    _transition(ledger, lease.lease_id, state="candidate_bound", now=now + timedelta(minutes=1))
    stored = ledger.read()
    prerequisite = stored["issues"]["P0-HOOK-001"]["transitions"][-1]
    assert isinstance(prerequisite, dict)
    prerequisite["validation"] = {"passed": False}
    ledger.path.write_text(json.dumps(stored), encoding="utf-8")

    with pytest.raises(EvidenceContractError):
        _transition(ledger, lease.lease_id, state="audit_ready", now=now + timedelta(minutes=2))
