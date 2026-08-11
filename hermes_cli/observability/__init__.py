"""First-party observability hooks available on the fork source baseline."""

from __future__ import annotations

from typing import Any

from . import teacher_receipt_observer


def observe_lifecycle(hook_name: str, **kwargs: Any) -> None:
    """Dispatch a lifecycle event to the built-in P0 observer."""
    teacher_receipt_observer.observe_lifecycle(hook_name, **kwargs)


def handles_hook(hook_name: str) -> bool:
    """Return whether a built-in observer consumes the event."""
    return teacher_receipt_observer.handles_hook(hook_name)
