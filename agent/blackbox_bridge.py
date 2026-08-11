"""Best-effort bridge from Hermes session persistence to TheWon Blackbox.

The bridge sits below the agent loop at SessionDB persistence so gateway, CLI,
cron, and future frontends share one append-only audit path. It is config-gated
and fail-open: Blackbox failures must never block Hermes session persistence.

SessionDB commits each message and its durable Blackbox outbox row atomically,
then attempts delivery after commit. Receiver failures leave the outbox row
pending for a later bounded drain; recorder readiness and successful delivery
remain separate runtime facts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import struct
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_recorder: Any = None
_recorder_key: tuple[str, str] | None = None

MIRROR_DELIVERY_GATE = "DURABLE_OUTBOX_INSTALLED"


@dataclass(frozen=True)
class BlackboxRecordResult:
    """Content-free outcome returned by every bridge write attempt."""

    status: Literal["recorded", "disabled", "failed"]
    event_id: str | None = None
    receipt_payload_sha256: str | None = None
    reason: str | None = None
    error_type: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"recorded", "disabled", "failed"}:
            raise ValueError("invalid Blackbox record status")
        if self.status == "recorded" and (self.reason or self.error_type):
            raise ValueError("recorded result cannot contain failure metadata")
        if self.status != "recorded" and not self.reason:
            raise ValueError("non-recorded result requires a reason")
        if self.status != "recorded" and self.receipt_payload_sha256 is not None:
            raise ValueError("failed result cannot contain a durable receipt digest")


@dataclass(frozen=True)
class _ConfigResolution:
    """One call's immutable config snapshot and fail-closed outcome."""

    config: Mapping[str, Any]
    outcome: BlackboxRecordResult | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.config, MappingProxyType):
            raise TypeError("config resolution must contain an immutable mapping")
        if self.outcome is not None and self.outcome.status == "recorded":
            raise ValueError("config resolution cannot report a recorded outcome")


@dataclass(frozen=True)
class _RecorderResolution:
    """One call's recorder object or exact unavailable outcome."""

    recorder: Any = None
    outcome: BlackboxRecordResult | None = None

    def __post_init__(self) -> None:
        if (self.recorder is None) == (self.outcome is None):
            raise ValueError("recorder resolution requires exactly one result")
        if self.outcome is not None and self.outcome.status == "recorded":
            raise ValueError("recorder resolution cannot report a recorded outcome")


def _canonical_content_node(value: Any, active: set[int]) -> dict[str, Any]:
    """Encode supported content types without lossy string coercion."""
    if value is None:
        return {"type": "none"}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, float):
        return {
            "type": "float",
            "value": base64.b64encode(struct.pack(">d", value)).decode("ascii"),
        }
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "value": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, bytearray):
        return {
            "type": "bytearray",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }

    if isinstance(value, (list, tuple, dict)):
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic content is not canonicalizable")
        active.add(identity)
        try:
            if isinstance(value, (list, tuple)):
                return {
                    "type": "list" if isinstance(value, list) else "tuple",
                    "items": [
                        _canonical_content_node(item, active) for item in value
                    ],
                }

            encoded_items: list[
                tuple[str, str, dict[str, Any], dict[str, Any]]
            ] = []
            for key, item in value.items():
                encoded_key = _canonical_content_node(key, active)
                encoded_value = _canonical_content_node(item, active)
                sort_key = json.dumps(
                    encoded_key,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                value_sort_key = json.dumps(
                    encoded_value,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                encoded_items.append(
                    (sort_key, value_sort_key, encoded_key, encoded_value)
                )
            encoded_items.sort(key=lambda item: (item[0], item[1]))
            return {
                "type": "dict",
                "items": [
                    [encoded_key, encoded_value]
                    for _, _, encoded_key, encoded_value in encoded_items
                ],
            }
        finally:
            active.remove(identity)

    raise TypeError(f"unsupported Blackbox content type: {type(value).__name__}")


def _canonical_content(value: Any) -> tuple[str, str]:
    envelope = {
        "schema": "hermes-blackbox-content/v1",
        "content": _canonical_content_node(value, set()),
    }
    raw = json.dumps(
        envelope,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_text(value: Any, *, limit: int = 200_000) -> str:
    """Return a searchable, JSON-safe text representation."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                if item.get("type") in (None, "text", "input_text"):
                    parts.append(str(item.get("text") or ""))
                elif item.get("type") in {"image", "image_url", "input_image"}:
                    parts.append("[image]")
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, default=str))
            else:
                parts.append(str(item))
        text = "\n".join(part for part in parts if part)
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    if len(text) > limit:
        return text[:limit] + f"\n[blackbox_bridge truncated at {limit} chars]"
    return text


def _load_cfg() -> dict[str, Any]:
    from hermes_cli.config import load_config

    cfg = load_config() or {}
    section = cfg.get("blackbox") if isinstance(cfg, dict) else {}
    return section if isinstance(section, dict) else {}


def _enabled(cfg: Mapping[str, Any]) -> bool:
    value = cfg.get("enabled", False)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _outbox_delivery_after(cfg: Mapping[str, Any]) -> tuple[float | None, bool]:
    """Return an optional inclusive outbox cutover timestamp.

    A configured malformed value is fail-closed so activating a profile cannot
    accidentally replay preserved history. Omitting the field retains existing
    delivery semantics for profiles that do not need a recovery cutover.
    """
    value = cfg.get("outbox_delivery_after")
    if value is None:
        return None, True
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None, False
    if not math.isfinite(parsed) or parsed < 0:
        return None, False
    return parsed, True


def _resolve_thewon_system(cfg: Mapping[str, Any]) -> Path:
    raw = (
        cfg.get("thewon_system")
        or os.getenv("THEWON_SYSTEM")
        or "/Users/elroy/TheWon/System"
    )
    return Path(str(raw)).expanduser().resolve()


def _resolve_config() -> _ConfigResolution:
    try:
        config = _load_cfg()
    except Exception as exc:
        logger.debug(
            "blackbox_bridge: config load failed: error_type=%s",
            type(exc).__name__,
        )
        return _ConfigResolution(
            config=MappingProxyType({}),
            outcome=BlackboxRecordResult(
                status="failed",
                reason="CONFIG_LOAD_FAILED",
                error_type=type(exc).__name__,
            ),
        )

    frozen_config = MappingProxyType(dict(config))
    if not _enabled(frozen_config):
        return _ConfigResolution(
            config=frozen_config,
            outcome=BlackboxRecordResult(
                status="disabled",
                reason="CONFIG_DISABLED",
            ),
        )
    return _ConfigResolution(config=frozen_config)


def _get_recorder(cfg: Mapping[str, Any]) -> Any:
    """Return a cached BlackboxRecorder or None when unavailable."""
    global _recorder, _recorder_key

    agent_id = str(cfg.get("agent_id") or "MINA").strip() or "MINA"
    thewon_system = _resolve_thewon_system(cfg)
    key = (agent_id, str(thewon_system))

    with _lock:
        if _recorder is not None and _recorder_key == key:
            return _recorder
        system_root = thewon_system.parent / "00_System"
        if str(system_root) not in sys.path:
            sys.path.insert(0, str(system_root))
        os.environ.setdefault("THEWON_SYSTEM", str(thewon_system))
        from shared.blackbox_recorder import BlackboxRecorder

        _recorder = BlackboxRecorder(agent_id)
        _recorder_key = key
        return _recorder


def _resolve_recorder(config: _ConfigResolution) -> _RecorderResolution:
    if config.outcome is not None:
        return _RecorderResolution(outcome=config.outcome)
    try:
        recorder = _get_recorder(config.config)
    except Exception as exc:
        logger.warning(
            "TheWon blackbox bridge unavailable: error_type=%s",
            type(exc).__name__,
        )
        return _RecorderResolution(
            outcome=BlackboxRecordResult(
                status="failed",
                reason="RECORDER_UNAVAILABLE",
                error_type=type(exc).__name__,
            )
        )
    if recorder is None:
        return _RecorderResolution(
            outcome=BlackboxRecordResult(
                status="failed",
                reason="RECORDER_UNAVAILABLE",
                error_type="RecorderUnavailable",
            )
        )
    return _RecorderResolution(recorder=recorder)


def record_session_message(
    *,
    session_id: str,
    message_id: Optional[int],
    role: str,
    content: Any = None,
    tool_name: Optional[str] = None,
    tool_calls: Any = None,
    tool_call_id: Optional[str] = None,
    token_count: Optional[int] = None,
    finish_reason: Optional[str] = None,
    platform_message_id: Optional[str] = None,
    observed: bool = False,
    timestamp: Any = None,
    _durable_event_id: Optional[str] = None,
) -> BlackboxRecordResult:
    """Append one Hermes message to TheWon raw Blackbox, best-effort."""
    config = _resolve_config()
    recorder_resolution = _resolve_recorder(config)
    if recorder_resolution.outcome is not None:
        return recorder_resolution.outcome
    recorder = recorder_resolution.recorder
    cfg = config.config

    try:
        content_raw, content_raw_sha256 = _canonical_content(content)
    except Exception as exc:
        return BlackboxRecordResult(
            status="failed",
            reason="CONTENT_CANONICALIZATION_FAILED",
            error_type=type(exc).__name__,
        )

    role = str(role or "unknown")
    data = {
        "source": "hermes_state",
        "message_role": role,
        "content_text": _safe_text(content),
        "content_raw": content_raw,
        "content_raw_sha256": content_raw_sha256,
        "message_id": message_id,
        "platform_message_id": platform_message_id,
        "tool_name": tool_name,
        "tool_calls": tool_calls,
        "tool_call_id": tool_call_id,
        "token_count": token_count,
        "finish_reason": finish_reason,
        "observed": bool(observed),
    }
    if timestamp is not None:
        data["message_timestamp"] = str(timestamp)

    if role == "user":
        event_type = "input"
    elif role == "assistant":
        event_type = "output"
    elif role == "tool" or tool_name:
        event_type = "tool_call"
    else:
        event_type = "message"

    event = {
        "type": event_type,
        "session": session_id,
        "project": cfg.get("project"),
        "tags": ["hermes", "session_db", "raw"],
        "severity": "info",
        "data": data,
    }
    if _durable_event_id is not None:
        event["id"] = _durable_event_id
        record_durable = getattr(recorder, "record_durable", None)
        if not callable(record_durable):
            return BlackboxRecordResult(
                status="failed",
                reason="DURABLE_API_UNAVAILABLE",
                error_type="AttributeError",
            )
        try:
            receipt = record_durable(
                event,
                session_id=session_id,
                request_id=str(platform_message_id or message_id or session_id),
            )
            receipt_event_id = getattr(receipt, "event_id", None)
            if receipt_event_id != _durable_event_id:
                return BlackboxRecordResult(
                    status="failed",
                    reason="DURABLE_RECEIPT_MISMATCH",
                    error_type="ValueError",
                )
            receipt_digest = getattr(receipt, "payload_sha256", None)
            return BlackboxRecordResult(
                status="recorded",
                event_id=receipt_event_id,
                receipt_payload_sha256=(
                    receipt_digest if isinstance(receipt_digest, str) else None
                ),
            )
        except Exception as exc:
            return BlackboxRecordResult(
                status="failed",
                reason="RECORDER_WRITE_FAILED",
                error_type=type(exc).__name__,
            )

    try:
        event_id = recorder.record(
            event,
            session_id=session_id,
            request_id=str(platform_message_id or message_id or session_id),
        )
        return BlackboxRecordResult(
            status="recorded",
            event_id=event_id if isinstance(event_id, str) else None,
        )
    except Exception as exc:
        return BlackboxRecordResult(
            status="failed",
            reason="RECORDER_WRITE_FAILED",
            error_type=type(exc).__name__,
        )


def record_transcript_event(
    *,
    session_id: str,
    event_type: str,
    messages: list[dict[str, Any]] | None = None,
    extra: Optional[dict[str, Any]] = None,
) -> BlackboxRecordResult:
    """Record transcript-level rewrite or compaction boundaries."""
    config = _resolve_config()
    recorder_resolution = _resolve_recorder(config)
    if recorder_resolution.outcome is not None:
        return recorder_resolution.outcome
    recorder = recorder_resolution.recorder
    cfg = config.config

    messages = messages or []
    try:
        content_raw, content_raw_sha256 = _canonical_content(messages)
    except Exception as exc:
        return BlackboxRecordResult(
            status="failed",
            reason="CONTENT_CANONICALIZATION_FAILED",
            error_type=type(exc).__name__,
        )
    preview_parts: list[str] = []
    for message in messages[:20]:
        role = message.get("role", "unknown") if isinstance(message, dict) else "unknown"
        content = message.get("content") if isinstance(message, dict) else message
        text = _safe_text(content, limit=8_000)
        if text:
            preview_parts.append(f"[{role}] {text}")
    data = {
        "source": "hermes_state",
        "event": event_type,
        "message_count": len(messages),
        "content_text": "\n\n".join(preview_parts),
        "content_raw": content_raw,
        "content_raw_sha256": content_raw_sha256,
    }
    if extra:
        for key, value in extra.items():
            if key not in data:
                data[key] = value
    try:
        recorded_event_id = recorder.record(
            {
                "type": event_type,
                "session": session_id,
                "project": cfg.get("project"),
                "tags": [
                    "hermes",
                    "session_db",
                    "compression"
                    if "compact" in event_type or "compress" in event_type
                    else "rewrite",
                ],
                "severity": "info",
                "data": data,
            },
            session_id=session_id,
            request_id=f"{session_id}:{event_type}",
        )
        return BlackboxRecordResult(
            status="recorded",
            event_id=(
                recorded_event_id if isinstance(recorded_event_id, str) else None
            ),
        )
    except Exception as exc:
        return BlackboxRecordResult(
            status="failed",
            reason="RECORDER_WRITE_FAILED",
            error_type=type(exc).__name__,
        )


def status() -> dict[str, Any]:
    """Return a secret-free diagnostic snapshot."""
    config = _resolve_config()
    recorder_resolution = _resolve_recorder(config)
    cfg = config.config
    delivery_after, delivery_after_valid = _outbox_delivery_after(cfg)
    return {
        "enabled": _enabled(cfg),
        "agent_id": cfg.get("agent_id") or "MINA",
        "thewon_system": str(_resolve_thewon_system(cfg)),
        "recorder_ready": recorder_resolution.recorder is not None,
        "disabled_reason": (
            recorder_resolution.outcome.reason
            if recorder_resolution.outcome is not None
            else None
        ),
        "delivery_gate": MIRROR_DELIVERY_GATE,
        "outbox_delivery_after": delivery_after,
        "outbox_delivery_after_valid": delivery_after_valid,
    }
