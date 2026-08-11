"""Behavior and production-seam tests for direct-hook teacher receipts."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.teacher_receipt_recovery import (
    MAX_RECEIPT_BYTES,
    ApprovalDenied,
    NativeKanbanAttachmentPublisher,
    ReceiptRecoveryError,
    ReceiptStore,
    RecoveryCoordinator,
    ToolRouteError,
    canonical_sha256,
)


def _event(task_id: str = "t_test", run_id: int = 1, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "completion_key": "completion-1",
        "task_id": task_id,
        "run_id": run_id,
        "channel_id": "C-test",
        "thread_ts": "1234567890.123456",
        "summary": "event",
    }
    value.update(overrides)
    return value


def _result(task_id: str = "t_test", run_id: int = 1, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "completion_key": "completion-1",
        "task_id": task_id,
        "run_id": run_id,
        "verdict": "PASS",
        "summary": "result",
    }
    value.update(overrides)
    return value


@pytest.fixture
def board(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str, int]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="teacher receipt target", assignee="dev")
        now = int(time.time())
        cursor = conn.execute(
            "INSERT INTO task_runs (task_id, profile, status, started_at) VALUES (?, ?, ?, ?)",
            (task_id, "dev", "running", now),
        )
        run_id = int(cursor.lastrowid)
        conn.execute("UPDATE tasks SET current_run_id = ? WHERE id = ?", (run_id, task_id))
        conn.commit()
    return home, task_id, run_id


def test_ascii_size_and_exact_task_run_event_result_binding(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    event = _event(summary="한글 event")
    result = _result()
    outcome = store.publish(event, result)
    payload = Path(outcome.receipt_path).read_bytes()
    receipt = json.loads(payload)

    assert payload.isascii()
    assert len(payload) <= MAX_RECEIPT_BYTES
    assert receipt["task_id"] == event["task_id"] == result["task_id"]
    assert receipt["run_id"] == event["run_id"] == result["run_id"]
    assert receipt["event_id"] == f"evt_{canonical_sha256(event)}"
    assert receipt["result_id"] == f"res_{canonical_sha256(result)}"


def test_oversize_and_serialization_fail_before_side_effect(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    with pytest.raises(ReceiptRecoveryError, match="receipt_too_large"):
        store.publish(_event(summary="x" * 20_000), _result())
    with pytest.raises(ReceiptRecoveryError, match="malformed_receipt_payload"):
        store.publish(_event(summary=Path("not-json")), _result())
    assert list((tmp_path / "receipts").glob("*.json")) == []


@pytest.mark.parametrize(
    ("event", "result"),
    [
        (_event(task_id="t_one"), _result(task_id="t_two")),
        (_event(run_id=1), _result(run_id=2)),
        (_event(), _result(completion_key="different")),
        (_event(), _result(verdict="UNKNOWN")),
    ],
)
def test_malformed_identity_tuple_is_rejected_before_write(
    tmp_path: Path, event: dict[str, object], result: dict[str, object]
) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    with pytest.raises(ReceiptRecoveryError, match="malformed_receipt_payload"):
        store.publish(event, result)
    assert list((tmp_path / "receipts").glob("*.json")) == []


def test_receipt_path_creation_failure_is_classified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "blocked"
    original = Path.mkdir

    def fail_target(path: Path, *args: object, **kwargs: object) -> None:
        if path == target:
            raise OSError("path denied")
        original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_target)
    with pytest.raises(ReceiptRecoveryError, match="receipt_path_failed"):
        ReceiptStore(target)


def test_write_and_readback_failures_are_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    monkeypatch.setattr(store, "_exclusive_write", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(ReceiptRecoveryError) as caught:
        store.publish(_event(), _result())
    assert caught.value.code == "receipt_write_failed" and caught.value.retryable

    store = ReceiptStore(tmp_path / "receipts-2")
    original_read = store._read_bytes
    reads = 0

    def fail_first(path: Path) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 1:
            raise OSError("read unavailable")
        return original_read(path)

    monkeypatch.setattr(store, "_read_bytes", fail_first)
    with pytest.raises(ReceiptRecoveryError) as caught:
        store.publish(_event(), _result())
    assert caught.value.code == "receipt_readback_failed" and caught.value.retryable
    assert store.read("completion-1")["result"]["verdict"] == "PASS"


@pytest.mark.parametrize("fail_fsync_call", [1, 2])
def test_file_and_directory_fsync_failures_are_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_fsync_call: int
) -> None:
    store = ReceiptStore(tmp_path / f"receipts-{fail_fsync_call}")
    real_fsync = store._fsync
    calls = 0

    def injected(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == fail_fsync_call:
            raise OSError(f"fsync {fail_fsync_call} failed")
        real_fsync(descriptor)

    monkeypatch.setattr(store, "_fsync", injected)
    with pytest.raises(ReceiptRecoveryError) as caught:
        store.publish(_event(), _result())
    assert caught.value.code == "receipt_write_failed" and caught.value.retryable


def test_existing_receipt_is_immutable(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    first = store.publish(_event(), _result())
    original = Path(first.receipt_path).read_bytes()
    duplicate = store.publish(_event(), _result())
    assert duplicate.created is False
    with pytest.raises(ReceiptRecoveryError, match="immutable_receipt_conflict"):
        store.publish(_event(), _result(verdict="FAIL"))
    assert Path(first.receipt_path).read_bytes() == original


def test_native_attachment_is_exactly_once_with_ambiguous_response(
    board: tuple[Path, str, int]
) -> None:
    _, task_id, run_id = board
    calls = 0

    def ambiguous_store(*args: object, **kwargs: object) -> int:
        nonlocal calls
        calls += 1
        attachment_id = kb.store_attachment_bytes(*args, **kwargs)
        raise OSError(f"response lost after storing {attachment_id}")

    publisher = NativeKanbanAttachmentPublisher(store_fn=ambiguous_store)
    store = ReceiptStore(Path(os.environ["HERMES_HOME"]) / "receipts")
    outcome = store.publish(
        _event(task_id, run_id),
        _result(task_id, run_id),
        attachment_publisher=publisher,
    )
    replay = store.publish(
        _event(task_id, run_id),
        _result(task_id, run_id),
        attachment_publisher=publisher,
    )

    assert calls == 1
    assert outcome.attached and replay.attached
    with kb.connect() as conn:
        attachments = kb.list_attachments(conn, task_id)
    assert len(attachments) == 1
    stored = Path(attachments[0].stored_path).read_bytes()
    assert stored == Path(outcome.receipt_path).read_bytes()


def test_native_attachment_readback_failure_does_not_claim_success(
    board: tuple[Path, str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, task_id, run_id = board
    publisher = NativeKanbanAttachmentPublisher()
    original = Path.read_bytes

    def fail_attachment(path: Path) -> bytes:
        if "attachments" in path.parts:
            raise OSError("stored bytes unavailable")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", fail_attachment)
    store = ReceiptStore(Path(os.environ["HERMES_HOME"]) / "receipts")
    with pytest.raises(ReceiptRecoveryError) as caught:
        store.publish(
            _event(task_id, run_id),
            _result(task_id, run_id),
            attachment_publisher=publisher,
        )
    assert caught.value.code == "attachment_readback_failed"


def test_native_attachment_rejects_wrong_task_run_before_attach(
    board: tuple[Path, str, int]
) -> None:
    _, task_id, run_id = board
    store = ReceiptStore(Path(os.environ["HERMES_HOME"]) / "receipts")
    coordinator = RecoveryCoordinator(Path(os.environ["HERMES_HOME"]) / "state", max_attempts=3)
    outcome = coordinator.attempt(
        "completion-1",
        lambda: store.publish(
            _event(task_id, run_id + 999),
            _result(task_id, run_id + 999),
            attachment_publisher=NativeKanbanAttachmentPublisher(),
        ),
    )
    assert outcome.status == "terminal"
    assert outcome.reason == "tool_route_error"
    assert outcome.artifact_count == 0
    with kb.connect() as conn:
        assert kb.list_attachments(conn, task_id) == []


def test_approval_denial_and_tool_route_fail_first_attempt_artifact_zero(tmp_path: Path) -> None:
    for error, reason in [
        (ApprovalDenied("operator denied"), "approval_denied"),
        (ToolRouteError("tool route unavailable"), "tool_route_error"),
    ]:
        coordinator = RecoveryCoordinator(tmp_path / reason, max_attempts=3)
        calls = 0

        def operation() -> None:
            nonlocal calls
            calls += 1
            raise error

        first = coordinator.attempt("completion-1", operation)
        replay = coordinator.attempt("completion-1", operation)
        assert first.status == "terminal"
        assert first.reason == reason
        assert first.attempts == 1
        assert first.artifact_count == 0
        assert replay == first
        assert calls == 1


def test_tool_route_error_removes_new_local_receipt(tmp_path: Path) -> None:
    class DeniedPublisher:
        def publish(self, **_: object) -> None:
            raise ToolRouteError("tool route unavailable")

    store = ReceiptStore(tmp_path / "receipts")
    with pytest.raises(ToolRouteError):
        store.publish(_event(), _result(), attachment_publisher=DeniedPublisher())  # type: ignore[arg-type]
    assert list((tmp_path / "receipts").glob("*.json")) == []


def test_natural_publish_outcome_persists_and_first_failure_survives(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    coordinator = RecoveryCoordinator(tmp_path / "state", max_attempts=3)
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ReceiptRecoveryError("receipt_write_failed", "disk full", retryable=True)
        return store.publish(_event(), _result())

    first = coordinator.attempt("completion-1", operation)
    second = coordinator.attempt("completion-1", operation)
    state = coordinator.read_state("completion-1")
    assert first.status == "retryable"
    assert second.status == "completed"
    assert state["first_failure"] == {
        "attempt": 1,
        "reason": "receipt_write_failed",
        "detail": "disk full",
    }
    assert state["result"]["receipt_path"].endswith("completion-1.json")


def test_retry_cap_boundary_and_exhaustion_are_deterministic(tmp_path: Path) -> None:
    coordinator = RecoveryCoordinator(tmp_path / "state", max_attempts=3)
    calls = 0

    def transient() -> None:
        nonlocal calls
        calls += 1
        raise ReceiptRecoveryError("receipt_write_failed", "temporary", retryable=True)

    outcomes = [coordinator.attempt("completion-1", transient) for _ in range(5)]
    assert [item.status for item in outcomes] == [
        "retryable", "retryable", "terminal", "terminal", "terminal"
    ]
    assert outcomes[2].reason == "retry_cap_exhausted"
    assert outcomes[2].attempts == 3
    assert calls == 3


@pytest.mark.parametrize("fail_fsync_call", [1, 2])
def test_recovery_state_file_and_directory_fsync_fail_closed_before_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_fsync_call: int
) -> None:
    coordinator = RecoveryCoordinator(tmp_path / "state", max_attempts=3)
    real_fsync = os.fsync
    calls = 0
    operation_calls = 0

    def injected(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == fail_fsync_call:
            raise OSError(f"state fsync {fail_fsync_call} failed")
        real_fsync(descriptor)

    def operation() -> str:
        nonlocal operation_calls
        operation_calls += 1
        return "must not run"

    monkeypatch.setattr(os, "fsync", injected)
    with pytest.raises(ReceiptRecoveryError) as caught:
        coordinator.attempt("completion-1", operation)
    assert caught.value.code == "recovery_state_write_failed"
    assert caught.value.retryable is False
    assert operation_calls == 0


def test_concurrent_duplicate_triggers_execute_once(tmp_path: Path) -> None:
    coordinators = [
        RecoveryCoordinator(tmp_path / "state", max_attempts=3),
        RecoveryCoordinator(tmp_path / "state", max_attempts=3),
    ]
    barrier = threading.Barrier(2)
    calls = 0
    lock = threading.Lock()
    outcomes = []

    def operation() -> str:
        nonlocal calls
        with lock:
            calls += 1
        time.sleep(0.05)
        return "ok"

    def worker(coordinator: RecoveryCoordinator) -> None:
        barrier.wait(timeout=2)
        outcomes.append(coordinator.attempt("completion-1", operation))

    threads = [threading.Thread(target=worker, args=(item,)) for item in coordinators]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert calls == 1
    assert len(outcomes) == 2
    assert {item.status for item in outcomes} == {"completed"}


def test_no_pythonpath_cli_production_import_and_native_invocation(
    board: tuple[Path, str, int], tmp_path: Path
) -> None:
    home, task_id, run_id = board
    event_path = tmp_path / "event.json"
    result_path = tmp_path / "result.json"
    event_path.write_text(json.dumps(_event(task_id, run_id)), encoding="utf-8")
    result_path.write_text(json.dumps(_result(task_id, run_id)), encoding="utf-8")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermes_cli.main",
            "hooks",
            "teacher-receipt",
            "--event-file",
            str(event_path),
            "--result-file",
            str(result_path),
            "--receipt-dir",
            str(tmp_path / "receipts"),
            "--state-dir",
            str(tmp_path / "state"),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env={**env, "HERMES_HOME": str(home)},
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    assert lines, completed.stdout
    outcome = json.loads(lines[-1])
    assert outcome["status"] == "completed"
    assert outcome["artifact_count"] == 1
    with kb.connect() as conn:
        attachments = kb.list_attachments(conn, task_id)
    assert len(attachments) == 1
    assert Path(attachments[0].stored_path).read_bytes().isascii()


def test_cli_terminal_failure_returns_nonzero_without_artifact(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    result_path = tmp_path / "result.json"
    event_path.write_text(json.dumps(_event()), encoding="utf-8")
    result_path.write_text(json.dumps(_result(task_id="t_other")), encoding="utf-8")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermes_cli.main",
            "hooks",
            "teacher-receipt",
            "--event-file",
            str(event_path),
            "--result-file",
            str(result_path),
            "--receipt-dir",
            str(tmp_path / "receipts"),
            "--state-dir",
            str(tmp_path / "state"),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 2
    assert '"status": "terminal"' in completed.stdout
    assert list((tmp_path / "receipts").glob("*.json")) == []


# ---------------------------------------------------------------------------
# Hook lifecycle integration tests
# ---------------------------------------------------------------------------


def test_observer_handles_on_session_end() -> None:
    from hermes_cli.observability.teacher_receipt_observer import handles_hook

    assert handles_hook("on_session_end") is True
    assert handles_hook("on_session_start") is False
    assert handles_hook("pre_llm_call") is False


def test_plugin_hook_dispatches_to_the_first_party_teacher_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hermes_cli import plugins
    from hermes_cli.observability import teacher_receipt_observer

    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        teacher_receipt_observer,
        "observe_lifecycle",
        lambda hook_name, **kwargs: calls.append((hook_name, kwargs)),
    )
    monkeypatch.setattr(
        plugins,
        "get_plugin_manager",
        lambda: SimpleNamespace(invoke_hook=lambda *_args, **_kwargs: []),
    )

    assert plugins.invoke_hook("on_session_end", task_id="t_test") == []
    assert calls == [("on_session_end", {"task_id": "t_test"})]


def test_native_attachment_store_bounds_and_collision(
    board: tuple[Path, str, int],
) -> None:
    _, task_id, _ = board
    with kb.connect() as conn:
        first = kb.store_attachment_bytes(
            conn, task_id, "receipt.json", b"first"
        )
        second = kb.store_attachment_bytes(
            conn, task_id, "receipt.json", b"second"
        )
        attachments = kb.list_attachments(conn, task_id)

        with pytest.raises(kb.AttachmentTooLarge):
            kb.store_attachment_bytes(
                conn, task_id, "too-large.json", b"12", max_bytes=1
            )

    assert first != second
    assert [item.filename for item in attachments] == [
        "receipt.json",
        "receipt (1).json",
    ]
    assert [Path(item.stored_path).read_bytes() for item in attachments] == [
        b"first",
        b"second",
    ]


def test_observer_skips_when_no_task_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Observer must not crash or publish when task_id is missing."""
    from hermes_cli.observability.teacher_receipt_observer import observe_lifecycle

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))

    # Should not raise — just return silently
    observe_lifecycle("on_session_end", session_id="s1", completed=True)
    assert not (home / "teacher-receipts").exists()


def test_observer_publishes_receipt_on_session_end(
    board: tuple[Path, str, int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full lifecycle: on_session_end fires, observer publishes receipt + attachment."""
    from hermes_cli.observability.teacher_receipt_observer import observe_lifecycle

    home, task_id, run_id = board
    monkeypatch.setenv("HERMES_HOME", str(home))

    observe_lifecycle(
        "on_session_end",
        session_id="s1",
        task_id=task_id,
        turn_id="t1",
        completed=True,
        failed=False,
        interrupted=False,
        turn_exit_reason="text_response(stop)",
        model="test-model",
        platform="test",
    )

    receipt_dir = home / "teacher-receipts"
    state_dir = home / "teacher-receipt-recovery"
    assert receipt_dir.exists()
    assert state_dir.exists()

    receipts = list(receipt_dir.glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text())
    assert receipt["task_id"] == task_id
    assert receipt["run_id"] == run_id
    assert receipt["result"]["verdict"] == "PASS"

    with kb.connect() as conn:
        attachments = kb.list_attachments(conn, task_id)
    assert len(attachments) == 1


def test_observer_records_failed_state_when_recovery_cannot_write(
    board: tuple[Path, str, int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from hermes_cli.observability import teacher_receipt_observer as observer
    from hermes_cli import teacher_receipt_recovery as recovery

    home, task_id, _ = board

    class FailingCoordinator:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def attempt(self, *_: object, **__: object) -> None:
            raise ReceiptRecoveryError(
                "recovery_state_write_failed", "state device unavailable", retryable=False
            )

    monkeypatch.setattr(recovery, "RecoveryCoordinator", FailingCoordinator)
    with caplog.at_level(logging.ERROR, logger=observer.__name__):
        observer.observe_lifecycle(
            "on_session_end", task_id=task_id, turn_id="recovery-failure", completed=True
        )

    completion_key = f"{task_id}-recovery-failure"
    state = json.loads(observer._observer_state_path(home, completion_key).read_text())
    assert state["status"] == "failed"
    assert state["reason"] == "recovery_state_write_failed"
    assert state["observer_attempt"] == 1
    assert state["recovery_attempts"] is None
    assert all("completed" not in record.message for record in caplog.records)
    assert any("Teacher-receipt observer failed" in record.message for record in caplog.records)


def test_observer_retries_publish_failure_and_persists_retry_exhaustion(
    board: tuple[Path, str, int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from hermes_cli.observability import teacher_receipt_observer as observer

    home, task_id, _ = board
    calls = 0
    backoff: list[int] = []

    def fail_publish(self: ReceiptStore, *_: object, **__: object) -> None:
        nonlocal calls
        calls += 1
        raise ReceiptRecoveryError("receipt_attach_failed", "attachment unavailable", retryable=True)

    monkeypatch.setattr(ReceiptStore, "publish", fail_publish)
    monkeypatch.setattr(observer, "_sleep_for_retry", backoff.append)
    with caplog.at_level(logging.WARNING, logger=observer.__name__):
        observer.observe_lifecycle(
            "on_session_end", task_id=task_id, turn_id="publish-failure", completed=True
        )

    completion_key = f"{task_id}-publish-failure"
    recovery_state = RecoveryCoordinator(
        home / "teacher-receipt-recovery", max_attempts=3
    ).read_state(completion_key)
    observer_state = json.loads(observer._observer_state_path(home, completion_key).read_text())
    assert calls == 3
    assert backoff == [1, 2]
    assert recovery_state["status"] == "terminal"
    assert recovery_state["reason"] == "retry_cap_exhausted"
    assert recovery_state["artifact_count"] == 0
    assert recovery_state["result"] is None
    assert observer_state["status"] == "failed"
    assert observer_state["reason"] == "retry_cap_exhausted"
    assert observer_state["observer_attempt"] == 3
    assert observer_state["recovery_attempts"] == 3
    assert any("deferred" in record.message for record in caplog.records)
    assert list((home / "teacher-receipts").glob("*.json")) == []

    with kb.connect() as conn:
        assert kb.list_attachments(conn, task_id) == []


def test_observer_verdict_fail_and_interrupted(
    board: tuple[Path, str, int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hermes_cli.observability.teacher_receipt_observer import observe_lifecycle

    home, task_id, run_id = board
    monkeypatch.setenv("HERMES_HOME", str(home))

    # FAIL
    observe_lifecycle(
        "on_session_end",
        task_id=task_id,
        turn_id="t-fail",
        completed=False,
        failed=True,
        interrupted=False,
    )
    receipt = json.loads((home / "teacher-receipts" / f"{task_id}-t-fail.json").read_text())
    assert receipt["result"]["verdict"] == "FAIL"

    # BLOCK (interrupted)
    observe_lifecycle(
        "on_session_end",
        task_id=task_id,
        turn_id="t-block",
        completed=False,
        failed=False,
        interrupted=True,
    )
    receipt = json.loads((home / "teacher-receipts" / f"{task_id}-t-block.json").read_text())
    assert receipt["result"]["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# NULL=superseded tests
# ---------------------------------------------------------------------------


def test_null_current_run_id_is_superseded(
    board: tuple[Path, str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """When current_run_id is NULL, the attachment publisher returns None (superseded)."""
    home, task_id, run_id = board

    # Clear current_run_id to simulate a completed/closed task
    with kb.connect() as conn:
        conn.execute("UPDATE tasks SET current_run_id = NULL WHERE id = ?", (task_id,))
        conn.commit()

    publisher = NativeKanbanAttachmentPublisher()
    store = ReceiptStore(home / "receipts")
    outcome = store.publish(
        _event(task_id, run_id),
        _result(task_id, run_id),
        attachment_publisher=publisher,
    )
    # Receipt is published locally but attachment is skipped (superseded)
    assert outcome.attached is False
    assert outcome.attachment_id is None
    assert Path(outcome.receipt_path).exists()


def test_null_current_run_id_observer_skips_attachment(
    board: tuple[Path, str, int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observer publishes receipt but skips attachment when task is superseded."""
    from hermes_cli.observability.teacher_receipt_observer import observe_lifecycle

    home, task_id, run_id = board
    monkeypatch.setenv("HERMES_HOME", str(home))

    # Clear current_run_id
    with kb.connect() as conn:
        conn.execute("UPDATE tasks SET current_run_id = NULL WHERE id = ?", (task_id,))
        conn.commit()

    observe_lifecycle(
        "on_session_end",
        task_id=task_id,
        turn_id="t-superseded",
        completed=True,
        failed=False,
        interrupted=False,
    )

    # Receipt is still published locally
    receipt_dir = home / "teacher-receipts"
    receipts = list(receipt_dir.glob("*.json"))
    assert len(receipts) == 1

    # But no attachment (superseded)
    with kb.connect() as conn:
        attachments = kb.list_attachments(conn, task_id)
    assert len(attachments) == 0
