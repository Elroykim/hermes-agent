"""Exact standing-GV receipt selection for P0 candidates."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re
from typing import Mapping, Sequence


class ReviewBindingError(ValueError):
    pass


@dataclass(frozen=True)
class ReviewBinding:
    channel_id: str
    thread_ts: str
    request_ts: str
    run_id: str
    completion_key: str
    expected_gv_user_id: str
    expected_artifact_sha256: str


_HEADER = re.compile(r"^\[P0-GV\] run_id=(?P<run_id>[A-Za-z0-9._:-]+) completion_key=(?P<key>[A-Za-z0-9._:-]+) verdict=(?P<verdict>PASS|REWORK|FAIL) artifact_sha256=(?P<sha>[0-9a-f]{64})$")


def select_gv_verdict(binding: ReviewBinding, messages: Sequence[Mapping[str, object]]) -> str:
    try:
        requested = Decimal(binding.request_ts)
    except Exception as exc:
        raise ReviewBindingError("request timestamp is invalid") from exc
    found: list[str] = []
    for row in messages:
        if row.get("channel_id") != binding.channel_id or row.get("thread_ts") != binding.thread_ts:
            raise ReviewBindingError("message outside bound thread")
        if row.get("user") != binding.expected_gv_user_id:
            continue
        try:
            if Decimal(str(row.get("ts"))) <= requested:
                continue
        except Exception as exc:
            raise ReviewBindingError("GV timestamp is invalid") from exc
        lines = str(row.get("text", "")).splitlines()
        if len(lines) < 2:
            continue
        match = _HEADER.fullmatch(lines[0].strip())
        if match is None:
            continue
        data = match.groupdict()
        if (data["run_id"], data["key"], data["sha"]) != (binding.run_id, binding.completion_key, binding.expected_artifact_sha256):
            raise ReviewBindingError("GV receipt binding mismatch")
        found.append(data["verdict"])
    if len(found) != 1:
        raise ReviewBindingError("expected exactly one standing GV receipt")
    return found[0]
