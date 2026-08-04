from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import agent.blackbox_bridge as bridge
from hermes_state import SessionDB


class _DurableRecorder:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = []

    def record_durable(self, event, **kwargs):
        self.calls.append((event, kwargs))
        if self.fail:
            raise OSError("receiver unavailable")
        return SimpleNamespace(
            event_id=event["id"],
            payload_sha256="receiver-" + event["id"],
        )


class _LegacyRecorder:
    def record(self, event, **kwargs):
        return "legacy-event"


def _configure(monkeypatch, recorder) -> None:
    monkeypatch.setattr(
        bridge,
        "_load_cfg",
        lambda: {"enabled": True, "agent_id": "MINA", "project": "TheWon"},
    )
    monkeypatch.setattr(bridge, "_get_recorder", lambda _cfg: recorder)


def _outbox_rows(db: SessionDB):
    return db._conn.execute(
        "SELECT event_id, message_id, payload_json, payload_sha256, status, "
        "attempt_count, receiver_event_id, receiver_payload_sha256 "
        "FROM blackbox_message_outbox ORDER BY id"
    ).fetchall()


def test_append_message_enqueues_and_delivers_after_commit(monkeypatch, tmp_path):
    recorder = _DurableRecorder()
    _configure(monkeypatch, recorder)
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        message_id = db.append_message("s1", role="user", content={"b": 2, "a": 1})
        rows = _outbox_rows(db)
        assert db._conn.in_transaction is False
    finally:
        db.close()

    assert len(rows) == 1
    row = rows[0]
    assert row["message_id"] == message_id
    assert row["event_id"].startswith(f"hermes-message-{message_id}-")
    assert row["event_id"].endswith(row["payload_sha256"])
    assert row["status"] == "delivered"
    assert row["attempt_count"] == 1
    assert row["receiver_event_id"] == row["event_id"]
    assert row["receiver_payload_sha256"].startswith("receiver-hermes-message-")
    assert recorder.calls[0][0]["id"] == row["event_id"]


def test_outbox_insert_failure_rolls_back_message(monkeypatch, tmp_path):
    _configure(monkeypatch, _LegacyRecorder())
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        db._conn.execute(
            "CREATE TRIGGER fail_blackbox_outbox BEFORE INSERT "
            "ON blackbox_message_outbox BEGIN "
            "SELECT RAISE(ABORT, 'forced outbox failure'); END"
        )
        try:
            db.append_message("s1", role="user", content="not committed")
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("outbox failure must roll back the message")
        message_count = db._conn.execute(
            "SELECT COUNT(*) FROM messages WHERE session_id = 's1'"
        ).fetchone()[0]
        outbox_count = db._conn.execute(
            "SELECT COUNT(*) FROM blackbox_message_outbox"
        ).fetchone()[0]
    finally:
        db.close()

    assert message_count == 0
    assert outbox_count == 0


def test_batch_enqueues_rows_in_message_order(monkeypatch, tmp_path):
    _configure(monkeypatch, _LegacyRecorder())
    db = SessionDB(db_path=tmp_path / "state.db")
    messages = [
        {"role": "user", "content": "one"},
        {"role": "assistant", "content": ["two", {"n": 2}]},
        {"role": "tool", "content": "three", "tool_name": "terminal"},
    ]
    try:
        db.create_session("s1", "test")
        assert db.append_messages_batch("s1", messages) == 3
        message_ids = [
            row[0]
            for row in db._conn.execute(
                "SELECT id FROM messages WHERE session_id = 's1' ORDER BY id"
            )
        ]
        rows = _outbox_rows(db)
    finally:
        db.close()

    assert [row["message_id"] for row in rows] == message_ids
    assert [json.loads(row["payload_json"])["content"] for row in rows] == [
        "one",
        ["two", {"n": 2}],
        "three",
    ]
    assert all(row["status"] == "pending" for row in rows)


def test_missing_receiver_api_keeps_pending_without_failing_session(
    monkeypatch, tmp_path
):
    _configure(monkeypatch, _LegacyRecorder())
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", "test")
        message_id = db.append_message("s1", role="user", content="persisted")
        rows = db.get_messages("s1")
        outbox = _outbox_rows(db)[0]
    finally:
        db.close()

    assert rows[-1]["id"] == message_id
    assert outbox["status"] == "pending"
    assert outbox["attempt_count"] == 1


def test_receiver_failure_reopens_and_auto_delivers_pending_once(monkeypatch, tmp_path):
    failing = _DurableRecorder(fail=True)
    _configure(monkeypatch, failing)
    path = tmp_path / "state.db"
    first = SessionDB(db_path=path)
    try:
        first.create_session("s1", "test")
        first.append_message("s1", role="assistant", content="recoverable")
        assert _outbox_rows(first)[0]["status"] == "pending"
    finally:
        first.close()

    healthy = _DurableRecorder()
    _configure(monkeypatch, healthy)
    reopened = SessionDB(db_path=path)
    try:
        assert reopened.drain_blackbox_message_outbox() == 0
        row = _outbox_rows(reopened)[0]
    finally:
        reopened.close()

    assert row["status"] == "delivered"
    assert row["attempt_count"] == 2
    assert len(healthy.calls) == 1
