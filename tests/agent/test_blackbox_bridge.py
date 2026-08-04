"""Regression tests for the optional SessionDB-to-Blackbox mirror."""

import base64
import hashlib
import json
import logging
import sqlite3
import struct
import threading
from unittest.mock import MagicMock

import agent.blackbox_bridge as bridge
from hermes_state import SessionDB


def _result(status, **kwargs):
    return bridge.BlackboxRecordResult(status=status, **kwargs)


def _decode_canonical(node):
    kind = node["type"]
    if kind == "none":
        return None
    if kind in {"bool", "str"}:
        return node["value"]
    if kind == "int":
        return int(node["value"])
    if kind == "float":
        return struct.unpack(">d", base64.b64decode(node["value"], validate=True))[0]
    if kind == "bytes":
        return base64.b64decode(node["value"], validate=True)
    if kind == "bytearray":
        return bytearray(base64.b64decode(node["value"], validate=True))
    if kind == "list":
        return [_decode_canonical(item) for item in node["items"]]
    if kind == "tuple":
        return tuple(_decode_canonical(item) for item in node["items"])
    if kind == "dict":
        return {
            _decode_canonical(key): _decode_canonical(value)
            for key, value in node["items"]
        }
    raise AssertionError(f"unknown canonical content kind: {kind}")


def _decode_content_raw(raw):
    envelope = json.loads(raw)
    assert envelope["schema"] == "hermes-blackbox-content/v1"
    return _decode_canonical(envelope["content"])


def test_record_session_message_builds_append_only_event(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(
        bridge,
        "_load_cfg",
        lambda: {
            "enabled": True,
            "agent_id": "MINA",
            "project": "TheWon",
        },
    )
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    result = bridge.record_session_message(
        session_id="s1",
        message_id=7,
        role="assistant",
        content=[{"type": "text", "text": "verified"}],
        platform_message_id="slack-1",
    )

    event = recorder.record.call_args.args[0]
    assert event["type"] == "output"
    assert event["session"] == "s1"
    assert event["data"]["content_text"] == "verified"
    assert _decode_content_raw(event["data"]["content_raw"]) == [
        {"type": "text", "text": "verified"}
    ]
    assert event["data"]["content_raw_sha256"] == hashlib.sha256(
        event["data"]["content_raw"].encode("utf-8")
    ).hexdigest()
    assert recorder.record.call_args.kwargs["request_id"] == "slack-1"
    assert result.status == "recorded"


def test_content_raw_round_trips_bytes_and_structured_content(monkeypatch):
    recorder = MagicMock()
    recorder.record.return_value = "evt-raw"
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)
    content = {
        "parts": ["text", b"\x00\xff", bytearray(b"mutable")],
        "nested": {
            "ok": True,
            "count": 10**400,
            "ratio": -0.0,
            "none": None,
        },
    }

    result = bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content=content
    )

    data = recorder.record.call_args.args[0]["data"]
    assert _decode_content_raw(data["content_raw"]) == content
    assert data["content_raw_sha256"] == hashlib.sha256(
        data["content_raw"].encode("utf-8")
    ).hexdigest()
    assert result == _result("recorded", event_id="evt-raw")


def test_content_raw_is_canonical_across_mapping_insertion_order(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content={"b": 2, "a": 1}
    )
    bridge.record_session_message(
        session_id="s1", message_id=2, role="user", content={"a": 1, "b": 2}
    )

    first = recorder.record.call_args_list[0].args[0]["data"]
    second = recorder.record.call_args_list[1].args[0]["data"]
    assert first["content_raw"] == second["content_raw"]
    assert first["content_raw_sha256"] == second["content_raw_sha256"]


def test_large_content_text_stays_truncated_but_raw_digest_covers_all(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)
    content = "x" * 200_123

    bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content=content
    )

    data = recorder.record.call_args.args[0]["data"]
    assert len(data["content_text"]) < len(content) + 100
    assert "truncated at 200000 chars" in data["content_text"]
    assert _decode_content_raw(data["content_raw"]) == content
    assert data["content_raw_sha256"] == hashlib.sha256(
        data["content_raw"].encode("utf-8")
    ).hexdigest()


def test_record_disabled_returns_structured_result(monkeypatch):
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": False})
    result = bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content="not recorded"
    )
    assert result == _result("disabled", reason="CONFIG_DISABLED")


def test_config_load_failure_is_failed_not_disabled(monkeypatch):
    monkeypatch.setattr(
        bridge,
        "_load_cfg",
        MagicMock(side_effect=PermissionError("private config detail")),
    )

    result = bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content="not recorded"
    )

    assert result == _result(
        "failed", reason="CONFIG_LOAD_FAILED", error_type="PermissionError"
    )


def test_config_failure_and_disabled_are_isolated_across_concurrent_calls(
    monkeypatch,
):
    import hermes_cli.config as config_module

    failure_started = threading.Event()
    disabled_reached_recorder = threading.Event()
    outcomes = {}

    def racing_load_config():
        if threading.current_thread().name == "config-failure":
            failure_started.set()
            raise PermissionError("private config detail")
        assert failure_started.wait(2)
        return {"blackbox": {"enabled": False}}

    def coordinated_get_recorder(_cfg):
        if threading.current_thread().name == "config-failure":
            assert disabled_reached_recorder.wait(2)
        else:
            disabled_reached_recorder.set()
        return None

    monkeypatch.setattr(config_module, "load_config", racing_load_config)
    monkeypatch.setattr(bridge, "_get_recorder", coordinated_get_recorder)

    def invoke(label):
        outcomes[label] = bridge.record_session_message(
            session_id=label,
            message_id=1,
            role="user",
            content="persisted",
        )

    failure_thread = threading.Thread(
        target=invoke,
        name="config-failure",
        args=("failure",),
    )
    disabled_thread = threading.Thread(
        target=invoke,
        name="config-disabled",
        args=("disabled",),
    )
    failure_thread.start()
    disabled_thread.start()
    failure_thread.join(3)
    disabled_thread.join(3)

    assert not failure_thread.is_alive()
    assert not disabled_thread.is_alive()
    assert outcomes["failure"] == _result(
        "failed",
        reason="CONFIG_LOAD_FAILED",
        error_type="PermissionError",
    )
    assert outcomes["disabled"] == _result(
        "disabled",
        reason="CONFIG_DISABLED",
    )


def test_unsupported_content_returns_failed_without_recorder_call(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    result = bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content=object()
    )

    assert result == _result(
        "failed", reason="CONTENT_CANONICALIZATION_FAILED", error_type="TypeError"
    )
    recorder.record.assert_not_called()


def test_record_failure_is_fail_open(monkeypatch):
    recorder = MagicMock()
    recorder.record.side_effect = RuntimeError("offline")
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    result = bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content="still persisted"
    )
    assert result == _result(
        "failed", reason="RECORDER_WRITE_FAILED", error_type="RuntimeError"
    )
    assert "offline" not in repr(result)


def test_transcript_event_raw_is_lossless_and_reserved_fields_cannot_be_overwritten(
    monkeypatch,
):
    recorder = MagicMock()
    recorder.record.return_value = "evt-transcript"
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)
    messages = [
        {"role": "user", "content": "before"},
        {"role": "assistant", "content": ["after", b"\x01"]},
    ]

    result = bridge.record_transcript_event(
        session_id="s1",
        event_type="context_compaction",
        messages=messages,
        extra={"content_raw": "forged", "content_raw_sha256": "0" * 64},
    )

    data = recorder.record.call_args.args[0]["data"]
    assert _decode_content_raw(data["content_raw"]) == messages
    assert data["content_raw_sha256"] == hashlib.sha256(
        data["content_raw"].encode("utf-8")
    ).hexdigest()
    assert result == _result("recorded", event_id="evt-transcript")


def test_transcript_recorder_exception_returns_failed_result(monkeypatch):
    recorder = MagicMock()
    recorder.record.side_effect = OSError("private recorder detail")
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    result = bridge.record_transcript_event(
        session_id="s1",
        event_type="transcript_rewrite",
        messages=[{"role": "user", "content": "persisted"}],
    )

    assert result == _result(
        "failed", reason="RECORDER_WRITE_FAILED", error_type="OSError"
    )
    assert "private recorder detail" not in repr(result)


def test_crash_gap_is_explicitly_open_without_durable_outbox():
    assert bridge.MIRROR_DELIVERY_GATE == "OPEN_NO_DURABLE_OUTBOX"


def test_sessiondb_hooks_append_rewrite_and_compaction(monkeypatch, tmp_path):
    message_hook = MagicMock(return_value=_result("recorded"))
    transcript_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    monkeypatch.setattr(bridge, "record_transcript_event", transcript_hook)

    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        message_id = db.append_message("s1", role="user", content="hello")
        db.replace_messages("s1", [{"role": "user", "content": "rewritten"}])
        inserted = db.archive_and_compact(
            "s1", [{"role": "assistant", "content": "summary"}]
        )
    finally:
        db.close()

    assert message_id > 0
    assert inserted == 1
    message_hook.assert_called_once()
    assert message_hook.call_args.kwargs["session_id"] == "s1"
    assert [call.kwargs["event_type"] for call in transcript_hook.call_args_list] == [
        "transcript_rewrite",
        "context_compaction",
    ]


def test_sessiondb_persistence_survives_bridge_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(
        bridge,
        "record_session_message",
        MagicMock(side_effect=RuntimeError("blackbox unavailable")),
    )
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        message_id = db.append_message("s1", role="user", content="durable")
        rows = db.get_messages("s1")
    finally:
        db.close()

    assert message_id > 0
    assert rows[-1]["content"] == "durable"


def test_sessiondb_single_append_warns_on_structured_bridge_failure(
    monkeypatch, tmp_path, caplog
):
    monkeypatch.setattr(
        bridge,
        "record_session_message",
        MagicMock(
            return_value=_result(
                "failed",
                reason="RECORDER_WRITE_FAILED",
                error_type="RuntimeError",
            )
        ),
    )
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        with caplog.at_level(logging.WARNING, logger="hermes_state"):
            row_id = db.append_message(
                "s1",
                role="user",
                content="durable",
                platform_message_id="platform-1",
            )
    finally:
        db.close()

    assert "blackbox bridge append_message failed" in caplog.text
    assert "session_id=s1" in caplog.text
    assert "platform_message_id=platform-1" in caplog.text
    assert f"row_id={row_id}" in caplog.text
    assert "reason=RECORDER_WRITE_FAILED" in caplog.text
    assert "error_type=RuntimeError" in caplog.text


def test_sessiondb_rewrite_and_compact_warn_on_structured_failure(
    monkeypatch, tmp_path, caplog
):
    monkeypatch.setattr(
        bridge,
        "record_transcript_event",
        MagicMock(
            return_value=_result(
                "failed",
                reason="RECORDER_WRITE_FAILED",
                error_type="OSError",
            )
        ),
    )
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        with caplog.at_level(logging.WARNING, logger="hermes_state"):
            db.replace_messages("s1", [{"role": "user", "content": "rewrite"}])
            db.archive_and_compact(
                "s1", [{"role": "assistant", "content": "summary"}]
            )
    finally:
        db.close()

    assert "event_type=transcript_rewrite" in caplog.text
    assert "event_type=context_compaction" in caplog.text
    assert caplog.text.count("reason=RECORDER_WRITE_FAILED") == 2


def _batch_messages():
    return [
        {
            "role": "user",
            "content": "question",
            "platform_message_id": "slack-user-1",
            "timestamp": 123.25,
        },
        {
            "role": "assistant",
            "content": [{"type": "text", "text": "checking"}],
            "tool_calls": [{"name": "terminal", "arguments": "{}"}],
            "finish_reason": "tool_calls",
        },
        {
            "role": "tool",
            "content": "tool output",
            "tool_name": "terminal",
            "tool_call_id": "call-1",
            "token_count": 17,
            "observed": True,
        },
        {
            "role": "assistant",
            "content": "answer",
            "message_id": "slack-assistant-1",
            "finish_reason": "stop",
        },
    ]


def test_sessiondb_batch_mirrors_committed_rows_in_input_order(monkeypatch, tmp_path):
    message_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        messages = _batch_messages()
        assert db.append_messages_batch("s1", messages) == 4
        row_ids = [
            row[0]
            for row in db._conn.execute(
                "SELECT id FROM messages WHERE session_id = ? ORDER BY id", ("s1",)
            )
        ]
    finally:
        db.close()

    calls = [call.kwargs for call in message_hook.call_args_list]
    assert [call["message_id"] for call in calls] == row_ids
    assert [call["content"] for call in calls] == [
        message["content"] for message in messages
    ]
    assert [call["role"] for call in calls] == [
        "user", "assistant", "tool", "assistant"
    ]
    assert calls[0]["platform_message_id"] == "slack-user-1"
    assert calls[0]["timestamp"] == 123.25
    assert calls[1]["tool_calls"] == [
        {"name": "terminal", "arguments": "{}"}
    ]
    assert calls[2]["tool_name"] == "terminal"
    assert calls[2]["tool_call_id"] == "call-1"
    assert calls[2]["token_count"] == 17
    assert calls[2]["observed"] is True
    assert calls[3]["platform_message_id"] == "slack-assistant-1"
    assert calls[3]["finish_reason"] == "stop"


def test_sessiondb_batch_db_failure_never_calls_bridge(monkeypatch, tmp_path):
    message_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        monkeypatch.setattr(
            db,
            "_execute_write",
            MagicMock(side_effect=sqlite3.OperationalError("commit failed")),
        )
        try:
            db.append_messages_batch("s1", _batch_messages())
        except sqlite3.OperationalError:
            pass
        else:
            raise AssertionError("database failure must propagate")
    finally:
        db.close()

    message_hook.assert_not_called()


def test_sessiondb_empty_batch_never_calls_bridge(monkeypatch, tmp_path):
    message_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        assert db.append_messages_batch("s1", []) == 0
    finally:
        db.close()
    message_hook.assert_not_called()


def test_sessiondb_chunked_batch_preserves_global_bridge_order(monkeypatch, tmp_path):
    message_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        messages = [
            {"role": "user", "content": f"message-{index}"}
            for index in range(7)
        ]
        assert db.append_messages_batch("s1", messages, chunk_rows=3) == 7
    finally:
        db.close()

    assert [
        call.kwargs["content"] for call in message_hook.call_args_list
    ] == [f"message-{index}" for index in range(7)]


def test_sessiondb_batch_bridge_failure_is_observable_and_continues(
    monkeypatch, tmp_path, caplog
):
    seen = []

    def flaky_hook(**kwargs):
        seen.append(kwargs)
        if len(seen) == 2:
            return _result(
                "failed",
                reason="RECORDER_WRITE_FAILED",
                error_type="RuntimeError",
            )
        return _result("recorded")

    monkeypatch.setattr(bridge, "record_session_message", flaky_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        with caplog.at_level(logging.WARNING, logger="hermes_state"):
            assert db.append_messages_batch("s1", _batch_messages()) == 4
        rows = db.get_messages("s1")
    finally:
        db.close()

    assert len(rows) == 4
    assert [item["content"] for item in seen] == [
        message["content"] for message in _batch_messages()
    ]
    assert "blackbox bridge append_messages_batch failed" in caplog.text
    assert "session_id=s1" in caplog.text
    assert "platform_message_id=None" in caplog.text
    assert f"row_id={seen[1]['message_id']}" in caplog.text
    assert "batch_index=1" in caplog.text
    assert "reason=RECORDER_WRITE_FAILED" in caplog.text
    assert "error_type=RuntimeError" in caplog.text


def test_sessiondb_batch_retry_matches_single_append_duplicate_semantics(
    monkeypatch, tmp_path
):
    message_hook = MagicMock(return_value=_result("recorded"))
    monkeypatch.setattr(bridge, "record_session_message", message_hook)
    db = SessionDB(db_path=tmp_path / "state.db")
    message = {
        "role": "user",
        "content": "retryable",
        "platform_message_id": "same-platform-id",
    }
    try:
        db.create_session("s1", "test")
        assert db.append_messages_batch("s1", [message]) == 1
        assert db.append_messages_batch("s1", [message]) == 1
    finally:
        db.close()

    calls = [call.kwargs for call in message_hook.call_args_list]
    assert len(calls) == 2
    assert calls[0]["message_id"] != calls[1]["message_id"]
    assert [call["platform_message_id"] for call in calls] == [
        "same-platform-id",
        "same-platform-id",
    ]
