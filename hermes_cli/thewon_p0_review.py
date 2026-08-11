"""Fail-closed binding for standing GV review receipts.

The Slack adapter supplies raw thread messages.  This module accepts a review
only when a single post-request message from the configured GV identity carries
an exact run and completion-key binding.  It cannot synthesize a receipt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
import re
from typing import Mapping, Sequence

from hermes_cli.thewon_p0_evidence import canonical_sha256


class ReviewBindingError(ValueError):
    """A GV review cannot be proven to bind to the requested completion."""


@dataclass(frozen=True)
class ReviewBinding:
    channel_id: str
    thread_ts: str
    request_ts: str
    run_id: str
    completion_key: str
    expected_gv_user_id: str
    expected_artifact_sha256: str


@dataclass(frozen=True)
class GVVerdict:
    message_ts: str
    user_id: str
    verdict: str
    artifact_sha256: str
    text_sha256: str


_VERDICTS = frozenset({"PASS", "WARN", "FAIL", "REWORK"})
_HEADER = re.compile(
    r"^\[P0-GV\]\s+run_id=(?P<run_id>[A-Za-z0-9._:-]+)\s+"
    r"completion_key=(?P<completion_key>[A-Za-z0-9._:-]+)\s+"
    r"verdict=(?P<verdict>PASS|WARN|FAIL|REWORK)\s+"
    r"artifact_sha256=(?P<artifact_sha256>[0-9a-f]{64})$"
)


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewBindingError(f"{name} must be non-empty")
    return value


def _ts(value: object, name: str) -> Decimal:
    raw = _text(value, name)
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise ReviewBindingError(f"{name} is malformed") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ReviewBindingError(f"{name} is malformed")
    return parsed


def _sha(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ReviewBindingError(f"{name} must be a lowercase SHA-256")
    return value


def select_gv_verdict(binding: ReviewBinding, messages: Sequence[Mapping[str, object]]) -> GVVerdict:
    """Select exactly one fully bound GV verdict from a complete thread page."""

    for value, name in (
        (binding.channel_id, "channel_id"),
        (binding.thread_ts, "thread_ts"),
        (binding.run_id, "run_id"),
        (binding.completion_key, "completion_key"),
        (binding.expected_gv_user_id, "expected_gv_user_id"),
    ):
        _text(value, name)
    expected_artifact_sha256 = _sha(
        binding.expected_artifact_sha256,
        "expected_artifact_sha256",
    )
    request_time = _ts(binding.request_ts, "request_ts")
    candidates: list[GVVerdict] = []
    for row in messages:
        if row.get("user") != binding.expected_gv_user_id:
            continue
        message_time = _ts(row.get("ts"), "GV message ts")
        if message_time <= request_time:
            continue
        text = _text(row.get("text"), "GV response text")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) < 2:
            continue
        match = _HEADER.fullmatch(lines[0])
        if match is None:
            continue
        review = match.groupdict()
        if review["run_id"] != binding.run_id or review["completion_key"] != binding.completion_key:
            continue
        if review["artifact_sha256"] != expected_artifact_sha256:
            continue
        candidates.append(
            GVVerdict(
                message_ts=str(row["ts"]),
                user_id=binding.expected_gv_user_id,
                verdict=review["verdict"],
                artifact_sha256=_sha(review["artifact_sha256"], "GV artifact_sha256"),
                text_sha256=canonical_sha256({"text": text}),
            )
        )
    if len(candidates) != 1:
        raise ReviewBindingError("expected exactly one post-request bound GV verdict")
    return candidates[0]


def build_gv_receipt(binding: ReviewBinding, verdict: GVVerdict) -> dict[str, object]:
    """Build a transparent receipt from, rather than in place of, GV evidence."""

    if verdict.user_id != binding.expected_gv_user_id:
        raise ReviewBindingError("receipt identity does not match the configured GV")
    if _ts(verdict.message_ts, "GV message ts") <= _ts(binding.request_ts, "request_ts"):
        raise ReviewBindingError("receipt predates the review request")
    if verdict.artifact_sha256 != _sha(
        binding.expected_artifact_sha256,
        "expected_artifact_sha256",
    ):
        raise ReviewBindingError("receipt artifact does not match the requested artifact")
    body = {
        "schema_version": "thewon-p0-gv-receipt/v1",
        **asdict(binding),
        "evaluated_message_ts": verdict.message_ts,
        "evaluated_user_id": verdict.user_id,
        "verdict": verdict.verdict,
        "artifact_sha256": verdict.artifact_sha256,
        "text_sha256": verdict.text_sha256,
    }
    return {**body, "receipt_sha256": canonical_sha256(body)}
