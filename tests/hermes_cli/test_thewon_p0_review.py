from __future__ import annotations

import pytest

from hermes_cli.thewon_p0_review import ReviewBinding, ReviewBindingError, select_gv_verdict


def _binding() -> ReviewBinding:
    return ReviewBinding(
        channel_id="C0BLPP2N6BX",
        thread_ts="1785382723.729409",
        request_ts="1780000001.000001",
        run_id="p0-r6-run-001",
        completion_key="key-001",
        expected_gv_user_id="U0BJDSJP734",
        expected_artifact_sha256="a" * 64,
    )


def _message(**overrides):
    value = {
        "ts": "1780000002.000001", "channel_id": "C0BLPP2N6BX", "thread_ts": "1785382723.729409", "user": "U0BJDSJP734",
        "text": "[P0-GV] run_id=p0-r6-run-001 completion_key=key-001 verdict=REWORK artifact_sha256=" + "a" * 64 + "\nindependent reproduction",
    }
    value.update(overrides)
    return value


def test_gv_requires_exact_identity_thread_request_time_and_single_receipt():
    assert select_gv_verdict(_binding(), [_message()]).verdict == "REWORK"


@pytest.mark.parametrize("messages", [
    [_message(user="U0BFXDNTS2D")],
    [_message(ts="1780000000.000001")],
    [_message(), _message(ts="1780000003.000001")],
    [_message(text="[P0-GV] run_id=p0-r6-run-001 completion_key=wrong verdict=PASS artifact_sha256=" + "a" * 64 + "\ntext")],
])
def test_gv_rejects_mina_stale_duplicate_or_wrong_completion_key(messages):
    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), messages)
