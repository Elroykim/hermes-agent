"""Exact standing-GV receipt selection for P0 candidates."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re
from typing import Mapping, Sequence


class ReviewBindingError(ValueError):
    """No single exact standing-GV verdict binds to the requested run."""


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
    verdict: str
    artifact_sha256: str


_HEADER = re.compile(r"^\[P0-GV\] run_id=(?P<run_id>[A-Za-z0-9._:-]+) completion_key=(?P<key>[A-Za-z0-9._:-]+) verdict=(?P<verdict>PASS|REWORK|FAIL) artifact_sha256=(?P<sha>[0-9a-f]{64})$")


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewBindingError(f"{name} must be non-empty")
    return value


def _time(value: object, name: str) -> Decimal:
    try:
        parsed = Decimal(_text(value, name))
    except InvalidOperation as exc:
        raise ReviewBindingError(f"{name} is malformed") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ReviewBindingError(f"{name} is malformed")
    return parsed


def select_gv_verdict(binding: ReviewBinding, messages: Sequence[Mapping[str, object]]) -> GVVerdict:
    request_time = _time(binding.request_ts, "request_ts")
    candidates: list[GVVerdict] = []
    for row in messages:
        if row.get("channel_id") != binding.channel_id or row.get("thread_ts") != binding.thread_ts:
            raise ReviewBindingError("thread message is outside the review binding")
        if row.get("user") != binding.expected_gv_user_id:
            continue
        if _time(row.get("ts"), "GV message ts") <= request_time:
            continue
        lines = [line.strip() for line in _text(row.get("text"), "GV text").splitlines() if line.strip()]
        if len(lines) < 2:
            continue
        match = _HEADER.fullmatch(lines[0])
        if match is None:
            continue
        value = match.groupdict()
        if value["key"] != binding.completion_key:
            continue
        if value["run_id"] != binding.run_id or value["sha"] != binding.expected_artifact_sha256:
            raise ReviewBindingError("GV receipt does not match requested run/artifact")
        candidates.append(GVVerdict(str(row["ts"]), value["verdict"], value["sha"]))
    if len(candidates) != 1:
        raise ReviewBindingError("expected exactly one post-request standing GV receipt")
    return candidates[0]
