"""Publish a durable teacher receipt after a task-bound session finishes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HANDLED_HOOKS = frozenset({"on_session_end"})


def observe_lifecycle(hook_name: str, **kwargs: Any) -> None:
    """Publish a receipt for one completed task/run when the session ends."""
    if hook_name != "on_session_end":
        return

    task_id = str(kwargs.get("task_id") or "")
    if not task_id:
        return

    try:
        _publish_teacher_receipt(task_id, kwargs)
    except Exception:
        logger.warning("Teacher-receipt observer failed", exc_info=True)


def handles_hook(hook_name: str) -> bool:
    return hook_name in HANDLED_HOOKS


def _publish_teacher_receipt(task_id: str, hook_kwargs: dict[str, Any]) -> None:
    from hermes_cli import kanban_db
    from hermes_cli.teacher_receipt_recovery import (
        NativeKanbanAttachmentPublisher,
        ReceiptStore,
        RecoveryCoordinator,
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
    store = ReceiptStore(home / "teacher-receipts")
    coordinator = RecoveryCoordinator(home / "teacher-receipt-recovery", max_attempts=3)
    publisher = None if superseded else NativeKanbanAttachmentPublisher()
    coordinator.attempt(
        completion_key,
        lambda: store.publish(event, result, attachment_publisher=publisher),
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
    import os

    return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
