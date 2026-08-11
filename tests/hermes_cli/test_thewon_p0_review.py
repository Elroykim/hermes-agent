from __future__ import annotations

import pytest

from hermes_cli.thewon_p0_review import ReviewBinding, ReviewBindingError, select_gv_verdict


def _binding() -> ReviewBinding:
    return ReviewBinding("C0BLPP2N6BX", "1785382723.729409", "1780000001.000001", "p0-r7-run-001", "key-r7", "U0BJDSJP734", "a" * 64)


def _receipt(**changes):
    row = {"ts": "1780000002.000001", "channel_id": "C0BLPP2N6BX", "thread_ts": "1785382723.729409", "user": "U0BJDSJP734", "text": "[P0-GV] run_id=p0-r7-run-001 completion_key=key-r7 verdict=REWORK artifact_sha256=" + "a" * 64 + "\nreproduced"}
    row.update(changes)
    return row


def test_review_requires_one_named_post_request_gv_receipt():
    assert select_gv_verdict(_binding(), [_receipt()]) == "REWORK"
    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), [_receipt(), _receipt(ts="1780000003.000001")])
    with pytest.raises(ReviewBindingError):
        select_gv_verdict(_binding(), [_receipt(user="U0BFXDNTS2D")])
