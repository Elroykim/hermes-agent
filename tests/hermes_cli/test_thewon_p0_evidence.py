from __future__ import annotations

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


def _sha(value: object) -> str:
    return canonical_sha256(value)


def _contract() -> RoundtripContract:
    return RoundtripContract(
        run_id="p0-run-001",
        parent_ts="1780000000.000001",
        owner_user_id="U_OWNER",
        expected_agent_user_id="U_CK",
        workflow_run_id="workflow-001",
        blackbox_run_id="blackbox-001",
    )


def _evidence() -> dict[str, object]:
    return {
        "tool_result": {"run_id": "p0-run-001", "message_ts": "1780000001.000001", "result": {"ok": True}},
        "workflow": {"run_id": "workflow-001", "result": {"state": "completed"}},
        "blackbox": {"run_id": "blackbox-001", "events": ["input", "output"]},
    }


def _messages(*, agent_user: str = "U_CK", text: str = "completed", terminal: bool = True) -> list[dict[str, object]]:
    return [
        {"ts": "1780000000.000001", "user": "U_OWNER", "text": "run p0-run-001"},
        {
            "ts": "1780000001.000001",
            "user": agent_user,
            "text": text,
            "metadata": {"p0_run_id": "p0-run-001", "terminal": terminal},
        },
    ]


def test_roundtrip_requires_exact_agent_nonempty_terminal_and_bound_artifacts():
    result = verify_roundtrip(_contract(), _messages(), _evidence())

    assert result.agent_response_ts == "1780000001.000001"
    assert result.tool_result_sha256 == _sha(_evidence()["tool_result"])
    assert result.workflow_sha256 == _sha(_evidence()["workflow"])
    assert result.blackbox_sha256 == _sha(_evidence()["blackbox"])


@pytest.mark.parametrize(
    ("messages", "evidence"),
    [
        (_messages(agent_user="U_OTHER"), _evidence()),
        (_messages(text=""), _evidence()),
        (_messages(terminal=False), _evidence()),
        (_messages(), {"tool_result": _evidence()["tool_result"], "workflow": _evidence()["workflow"]}),
    ],
)
def test_roundtrip_rejects_reply_count_false_positives(messages, evidence):
    with pytest.raises(EvidenceContractError):
        verify_roundtrip(_contract(), messages, evidence)


def test_issue_ledger_serializes_resource_leases_and_binds_transitions(tmp_path):
    ledger = IssueLedger(tmp_path / "ledger.json")
    ledger.open_issue(
        issue_id="P0-HOOK-001",
        owner_bac="CK",
        base_sha="a" * 40,
        mutation_boundary=["hermes_cli/thewon_p0_review.py"],
        rollback="git revert <commit>",
    )
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    lease = ledger.acquire_lease(
        issue_id="P0-HOOK-001",
        resources=["runtime:mina-review-hook", "slack:C0BLPP2N6BX:1785382723.729409"],
        owner_bac="CK",
        base_sha="a" * 40,
        ttl=timedelta(minutes=10),
        now=now,
    )

    with pytest.raises(LeaseConflict):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:mina-review-hook"],
            owner_bac="EV",
            base_sha="a" * 40,
            ttl=timedelta(minutes=10),
            now=now + timedelta(minutes=1),
        )

    with pytest.raises(LeaseConflict):
        ledger.acquire_lease(
            issue_id="P0-HOOK-001",
            resources=["runtime:mina-review-hook"],
            owner_bac="CK",
            base_sha="a" * 40,
            ttl=timedelta(minutes=10),
            now=now + timedelta(minutes=1),
        )

    event = ledger.record_transition(
        issue_id="P0-HOOK-001",
        lease_id=lease.lease_id,
        state="candidate_bound",
        pre_state_digest="b" * 64,
        artifacts=[{"path": "hermes_cli/thewon_p0_review.py", "sha256": "c" * 64}],
        validation={"command": "pytest tests/hermes_cli/test_thewon_p0_evidence.py", "passed": 5},
        now=now + timedelta(minutes=2),
    )

    assert event["lease_id"] == lease.lease_id
    assert ledger.read()["issues"]["P0-HOOK-001"]["transitions"][0]["state"] == "candidate_bound"
    renewed = ledger.renew_lease(
        issue_id="P0-HOOK-001",
        lease_id=lease.lease_id,
        ttl=timedelta(minutes=10),
        now=now + timedelta(minutes=2),
    )
    assert renewed.lease_id == lease.lease_id
    assert renewed.expires_at == "2026-08-11T00:12:00Z"
    assert ledger.release_lease(issue_id="P0-HOOK-001", lease_id=lease.lease_id) == (
        "runtime:mina-review-hook",
        "slack:C0BLPP2N6BX:1785382723.729409",
    )
    replacement = ledger.acquire_lease(
        issue_id="P0-HOOK-001",
        resources=["runtime:mina-review-hook"],
        owner_bac="EV",
        base_sha="a" * 40,
        ttl=timedelta(minutes=10),
        now=now + timedelta(minutes=2),
    )
    assert replacement.owner_bac == "EV"


def test_issue_ledger_rejects_base_sha_drift(tmp_path):
    ledger = IssueLedger(tmp_path / "ledger.json")
    ledger.open_issue(
        issue_id="P0-LEDGER-001",
        owner_bac="NV",
        base_sha="a" * 40,
        mutation_boundary=["docs/thewon/p0/evidence-ledger.json"],
        rollback="git revert <commit>",
    )

    with pytest.raises(EvidenceContractError):
        ledger.acquire_lease(
            issue_id="P0-LEDGER-001",
            resources=["ledger:p0"],
            owner_bac="NV",
            base_sha="b" * 40,
            ttl=timedelta(minutes=10),
        )
