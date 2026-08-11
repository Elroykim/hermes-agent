from __future__ import annotations

import pytest

from hermes_cli.thewon_p0_review import (
    ReviewBinding,
    ReviewBindingError,
    build_gv_receipt,
    select_gv_verdict,
)


def _binding() -> ReviewBinding:
    return ReviewBinding(
        channel_id="C0BLPP2N6BX",
        thread_ts="1785382723.729409",
        request_ts="1780000001.000001",
        run_id="p0-run-001",
        completion_key="completion-001",
        expected_gv_user_id="U_GV",
        expected_artifact_sha256="a" * 64,
    )


def _message(**overrides: object) -> dict[str, object]:
    message: dict[str, object] = {
        "ts": "1780000002.000001",
        "user": "U_GV",
        "text": (
            "[P0-GV] run_id=p0-run-001 completion_key=completion-001 "
            f"verdict=REWORK artifact_sha256={'a' * 64}\n"
            "GV independently reproduced the result."
        ),
    }
    message.update(overrides)
    return message


def test_select_gv_verdict_requires_identity_request_time_and_exact_binding():
    verdict = select_gv_verdict(_binding(), [_message()])

    assert verdict.user_id == "U_GV"
    assert verdict.message_ts == "1780000002.000001"
    assert verdict.verdict == "REWORK"
    receipt = build_gv_receipt(_binding(), verdict)
    assert receipt["evaluated_user_id"] == "U_GV"
    assert receipt["completion_key"] == "completion-001"


@pytest.mark.parametrize(
    "message",
    [
        _message(user="U_OTHER"),
        _message(ts="1780000000.000001"),
        _message(text=""),
        _message(
            text=(
                "[P0-GV] run_id=p0-run-001 completion_key=wrong "
                f"verdict=PASS artifact_sha256={'a' * 64}\n"
                "This must not bind."
            )
        ),
        _message(text="[P0-GV] run_id=p0-run-001 completion_key=completion-001 verdict=PASS artifact_sha256=" + "a" * 64),
    ],
)
def test_select_gv_verdict_rejects_unbound_or_empty_messages(message):
    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), [message])


def test_select_gv_verdict_rejects_duplicate_bound_verdicts():
    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), [_message(), _message(ts="1780000003.000001")])


def test_select_gv_verdict_rejects_a_well_formed_but_wrong_artifact_hash():
    wrong_hash = "b" * 64
    message = _message(
        text=(
            "[P0-GV] run_id=p0-run-001 completion_key=completion-001 "
            f"verdict=REWORK artifact_sha256={wrong_hash}\\n"
            "GV independently reproduced the result."
        )
    )

    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), [message])
