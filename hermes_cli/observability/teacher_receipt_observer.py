"""Publish a durable teacher receipt after a task-bound session finishes."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HANDLED_HOOKS = frozenset({"on_session_end"})
MAX_PUBLICATION_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (0.05, 0.1)
OBSERVER_STATE_SCHEMA = "hermes-teacher-receipt-observer/v1"


def observe_lifecycle(hook_name: str, **kwargs: Any) -> None:
    """Publish a receipt for one completed task/run when the session ends."""
    if hook_name != "on_session_end":
        return

    task_id = str(kwargs.get("task_id") or "")
    if not task_id:
        return

    home = _hermes_home()
    completion_key = _completion_key(task_id, kwargs)
    for observer_attempt in range(1, MAX_PUBLICATION_ATTEMPTS + 1):
        try:
            outcome = _publish_teacher_receipt(task_id, kwargs)
        except Exception as exc:
            reason, detail, retryable = _failure_details(exc)
            _record_observer_state(
                home,
                completion_key,
                task_id,
                status="deferred" if retryable and observer_attempt < MAX_PUBLICATION_ATTEMPTS else "failed",
                observer_attempt=observer_attempt,
                recovery_attempts=None,
                reason=reason,
                detail=detail,
            )
            if retryable and observer_attempt < MAX_PUBLICATION_ATTEMPTS:
                _log_deferred(
                    task_id, completion_key, observer_attempt, reason, detail, exc_info=True
                )
                _sleep_for_retry(observer_attempt)
                continue
            logger.error(
                "Teacher-receipt observer failed: task_id=%s completion_key=%s "
                "attempt=%s/%s reason=%s detail=%s",
                task_id,
                completion_key,
                observer_attempt,
                MAX_PUBLICATION_ATTEMPTS,
                reason,
                detail,
                exc_info=True,
            )
            return

        if outcome is None:
            return
        if outcome.status == "completed":
            _clear_observer_state(home, completion_key)
            return

        reason = str(outcome.reason or "recovery_incomplete")
        detail = str(outcome.detail or "")
        retryable = outcome.status == "retryable"
        _record_observer_state(
            home,
            completion_key,
            task_id,
            status="deferred" if retryable and observer_attempt < MAX_PUBLICATION_ATTEMPTS else "failed",
            observer_attempt=observer_attempt,
            recovery_attempts=outcome.attempts,
            reason=reason,
            detail=detail,
        )
        if retryable and observer_attempt < MAX_PUBLICATION_ATTEMPTS:
            _log_deferred(task_id, completion_key, observer_attempt, reason, detail)
            _sleep_for_retry(observer_attempt)
            continue
        logger.error(
            "Teacher-receipt observer failed: task_id=%s completion_key=%s "
            "attempt=%s/%s reason=%s detail=%s",
            task_id,
            completion_key,
            observer_attempt,
            MAX_PUBLICATION_ATTEMPTS,
            reason,
            detail,
        )
        return


def handles_hook(hook_name: str) -> bool:
    return hook_name in HANDLED_HOOKS


def _publish_teacher_receipt(task_id: str, hook_kwargs: dict[str, Any]) -> Any:
    from hermes_cli import kanban_db
    from hermes_cli.teacher_receipt_recovery import (
        ApprovalDenied,
        NativeKanbanAttachmentPublisher,
        ReceiptRecoveryError,
        ReceiptStore,
        RecoveryCoordinator,
        ToolRouteError,
    )

    with kanban_db.connect() as conn:
        task = kanban_db.get_task(conn, task_id)
        if task is None:
            return
        run_id = task.current_run_id
        superseded = run_id is None
        if superseded:
            row = conn.execute(
                "SELECT id FROM task_runs WHERE task_id = ? ORDER BY started_at DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            if row is None:
                return
            run_id = int(row["id"])

    home = _hermes_home()
    completion_key = _completion_key(task_id, hook_kwargs)
    event: dict[str, object] = {
        "completion_key": completion_key,
        "task_id": task_id,
        "run_id": run_id,
        "session_id": str(hook_kwargs.get("session_id") or ""),
        "platform": str(hook_kwargs.get("platform") or ""),
        "model": str(hook_kwargs.get("model") or ""),
    }
    result: dict[str, object] = {
        "completion_key": completion_key,
        "task_id": task_id,
        "run_id": run_id,
        "verdict": _verdict_from_hook(hook_kwargs),
        "completed": hook_kwargs.get("completed", False),
        "failed": hook_kwargs.get("failed", False),
        "interrupted": hook_kwargs.get("interrupted", False),
        "turn_exit_reason": str(hook_kwargs.get("turn_exit_reason") or ""),
    }
    coordinator = RecoveryCoordinator(
        home / "teacher-receipt-recovery", max_attempts=MAX_PUBLICATION_ATTEMPTS
    )
    publisher = None if superseded else NativeKanbanAttachmentPublisher()

    def publish() -> Any:
        try:
            store = ReceiptStore(home / "teacher-receipts")
            return store.publish(event, result, attachment_publisher=publisher)
        except (ApprovalDenied, ToolRouteError, ReceiptRecoveryError, OSError):
            raise
        except Exception as exc:
            raise ReceiptRecoveryError(
                "receipt_publish_failed", str(exc), retryable=True
            ) from exc

    return coordinator.attempt(completion_key, publish)


def _failure_details(exc: Exception) -> tuple[str, str, bool]:
    from hermes_cli.teacher_receipt_recovery import ReceiptRecoveryError

    if isinstance(exc, ReceiptRecoveryError):
        return exc.code, exc.detail, exc.retryable
    if isinstance(exc, OSError):
        return "observer_operation_failed", str(exc), True
    return "observer_unexpected_failure", f"{type(exc).__name__}: {exc}", False


def _log_deferred(
    task_id: str,
    completion_key: str,
    observer_attempt: int,
    reason: str,
    detail: str,
    *,
    exc_info: bool = False,
) -> None:
    logger.warning(
        "Teacher-receipt observer deferred: task_id=%s completion_key=%s "
        "attempt=%s/%s reason=%s detail=%s",
        task_id,
        completion_key,
        observer_attempt,
        MAX_PUBLICATION_ATTEMPTS,
        reason,
        detail,
        exc_info=exc_info,
    )


def _sleep_for_retry(observer_attempt: int) -> None:
    time.sleep(RETRY_BACKOFF_SECONDS[observer_attempt - 1])


def _observer_state_path(home: Path, completion_key: str) -> Path:
    safe_key = completion_key
    allowed = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
    )
    if (
        not safe_key
        or len(safe_key) > 128
        or safe_key[0] not in allowed - frozenset("._-")
        or any(char not in allowed for char in safe_key)
    ):
        safe_key = f"invalid-{hashlib.sha256(completion_key.encode('utf-8')).hexdigest()}"
    return home / "teacher-receipt-recovery" / f"{safe_key}.observer-state.json"


def _record_observer_state(
    home: Path,
    completion_key: str,
    task_id: str,
    *,
    status: str,
    observer_attempt: int,
    recovery_attempts: int | None,
    reason: str,
    detail: str,
) -> None:
    path = _observer_state_path(home, completion_key)
    payload = {
        "schema_version": OBSERVER_STATE_SCHEMA,
        "completion_key": completion_key,
        "task_id": task_id,
        "status": status,
        "observer_attempt": observer_attempt,
        "recovery_attempts": recovery_attempts,
        "reason": reason,
        "detail": detail,
    }
    try:
        _write_observer_state(path, payload)
    except OSError:
        logger.error(
            "Teacher-receipt observer could not persist failure state: "
            "task_id=%s completion_key=%s",
            task_id,
            completion_key,
            exc_info=True,
        )


def _write_observer_state(path: Path, value: dict[str, object]) -> None:
    root = path.parent
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise OSError("teacher receipt recovery root must be a real directory")
    os.chmod(root, 0o700)
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=root)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _clear_observer_state(home: Path, completion_key: str) -> None:
    path = _observer_state_path(home, completion_key)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        logger.warning(
            "Teacher-receipt observer could not clear deferred state: completion_key=%s",
            completion_key,
            exc_info=True,
        )
        return
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        logger.warning(
            "Teacher-receipt observer could not fsync cleared deferred state: "
            "completion_key=%s",
            completion_key,
            exc_info=True,
        )


def _completion_key(task_id: str, hook_kwargs: dict[str, Any]) -> str:
    turn_id = str(hook_kwargs.get("turn_id") or "")
    return f"{task_id}-{turn_id}" if turn_id else task_id


def _verdict_from_hook(kwargs: dict[str, Any]) -> str:
    if kwargs.get("failed"):
        return "FAIL"
    if kwargs.get("interrupted"):
        return "BLOCK"
    if kwargs.get("completed"):
        return "PASS"
    return "WARN"


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
