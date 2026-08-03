"""Regression tests for the optional SessionDB-to-Blackbox mirror."""

from unittest.mock import MagicMock

import agent.blackbox_bridge as bridge
from hermes_state import SessionDB


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

    bridge.record_session_message(
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
    assert recorder.record.call_args.kwargs["request_id"] == "slack-1"


def test_record_failure_is_fail_open(monkeypatch):
    recorder = MagicMock()
    recorder.record.side_effect = RuntimeError("offline")
    monkeypatch.setattr(bridge, "_load_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)

    bridge.record_session_message(
        session_id="s1", message_id=1, role="user", content="still persisted"
    )


def test_sessiondb_hooks_append_rewrite_and_compaction(monkeypatch, tmp_path):
    message_hook = MagicMock()
    transcript_hook = MagicMock()
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
