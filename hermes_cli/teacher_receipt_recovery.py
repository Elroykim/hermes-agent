"""Durable teacher-receipt publication for direct-hook recovery.

This module is the repository-managed production seam used by ``hermes hooks
teacher-receipt``.  It binds one Kanban task/run/completion tuple to immutable
canonical event/result bytes, publishes an optional native Kanban attachment,
and records bounded retry state without repeating terminal or completed work.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Callable, Optional


RECEIPT_SCHEMA = "hermes-direct-hook-teacher-receipt/v2"
MAX_RECEIPT_BYTES = 16_384
_COMPLETION_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TASK_ID_RE = re.compile(r"^t_[A-Za-z0-9]+$")
_ALLOWED_VERDICTS = frozenset({"PASS", "WARN", "FAIL", "REWORK", "BLOCK"})


class ReceiptRecoveryError(RuntimeError):
    """A classified publication or recovery failure."""

    def __init__(self, code: str, detail: str, *, retryable: bool) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.retryable = retryable


class ApprovalDenied(RuntimeError):
    """The operator or policy layer explicitly denied publication."""


class ToolRouteError(RuntimeError):
    """The native attachment route is unavailable or rejected."""


@dataclass(frozen=True)
class NativeAttachmentOutcome:
    attachment_id: int
    stored_path: str
    stored_bytes: int
    sha256: str
    created: bool


@dataclass(frozen=True)
class PublishOutcome:
    receipt_path: str
    receipt_sha256: str
    stored_bytes: int
    created: bool
    attached: bool
    attachment_id: Optional[int] = None
    attachment_created: bool = False


@dataclass(frozen=True)
class RecoveryOutcome:
    status: str
    attempts: int
    reason: Optional[str] = None
    detail: Optional[str] = None
    first_failure: Optional[dict[str, object]] = None
    result: Any = None
    artifact_count: int = 0


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReceiptRecoveryError(
            "malformed_receipt_payload",
            f"payload is not canonical ASCII JSON: {exc}",
            retryable=False,
        ) from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _json_safe(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _json_safe(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ReceiptRecoveryError(
        "result_serialization_failed",
        f"unsupported result type: {type(value).__name__}",
        retryable=False,
    )


def _validate_completion_key(value: object) -> str:
    if not isinstance(value, str) or not _COMPLETION_KEY_RE.fullmatch(value):
        raise ReceiptRecoveryError(
            "malformed_receipt_payload",
            "completion_key must be a path-safe 1-128 character identifier",
            retryable=False,
        )
    return value


def _validate_task_id(value: object) -> str:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise ReceiptRecoveryError(
            "malformed_receipt_payload",
            "task_id must be a canonical t_<id> identifier",
            retryable=False,
        )
    return value


def _validate_run_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReceiptRecoveryError(
            "malformed_receipt_payload",
            "run_id must be a positive integer",
            retryable=False,
        )
    return value


class NativeKanbanAttachmentPublisher:
    """Idempotently store and read back a receipt through native Kanban APIs."""

    def __init__(
        self,
        *,
        board: Optional[str] = None,
        uploaded_by: str = "direct-hook-teacher-receipt",
        connect_fn: Optional[Callable[[], Any]] = None,
        store_fn: Optional[Callable[..., int]] = None,
    ) -> None:
        self.board = board
        self.uploaded_by = uploaded_by
        self._connect_fn = connect_fn
        self._store_fn = store_fn

    def _connect(self):
        if self._connect_fn is not None:
            return self._connect_fn()
        from hermes_cli import kanban_db

        return kanban_db.connect(board=self.board)

    @staticmethod
    def _filename(completion_key: str) -> str:
        return f"teacher-receipt-{_validate_completion_key(completion_key)}.json"

    def _read_existing(
        self, task_id: str, run_id: int, filename: str, payload: bytes
    ) -> Optional[NativeAttachmentOutcome]:
        from hermes_cli import kanban_db

        expected_sha = hashlib.sha256(payload).hexdigest()
        with self._connect() as conn:
            task = kanban_db.get_task(conn, task_id)
            run = kanban_db.get_run(conn, run_id)
            if (
                task is None
                or task.current_run_id is None
                or task.current_run_id != run_id
                or run is None
                or run.task_id != task_id
            ):
                if task is not None and task.current_run_id is None:
                    # Task has been completed/closed — this receipt is superseded.
                    return None
                raise ToolRouteError(
                    f"Kanban run {run_id} is not the current run for task {task_id}"
                )
            matches = [
                item
                for item in kanban_db.list_attachments(conn, task_id)
                if item.filename == filename
            ]
            if not matches:
                return None
            if len(matches) != 1:
                raise ReceiptRecoveryError(
                    "attachment_consistency_failed",
                    f"multiple native attachments exist for idempotency key {filename}",
                    retryable=False,
                )
            item = matches[0]
            try:
                stored = Path(item.stored_path).read_bytes()
            except OSError as exc:
                raise ReceiptRecoveryError(
                    "attachment_readback_failed", str(exc), retryable=True
                ) from exc
            if (
                stored != payload
                or item.size != len(payload)
                or hashlib.sha256(stored).hexdigest() != expected_sha
            ):
                raise ReceiptRecoveryError(
                    "attachment_consistency_failed",
                    "native attachment stored bytes/hash do not match receipt",
                    retryable=False,
                )
            return NativeAttachmentOutcome(
                attachment_id=item.id,
                stored_path=item.stored_path,
                stored_bytes=len(stored),
                sha256=expected_sha,
                created=False,
            )

    def publish(
        self, *, task_id: str, run_id: int, completion_key: str, payload: bytes
    ) -> Optional[NativeAttachmentOutcome]:
        from hermes_cli import kanban_db

        filename = self._filename(completion_key)
        existing = self._read_existing(task_id, run_id, filename, payload)
        if existing is not None:
            return existing

        # Check for superseded task before attempting storage.
        with self._connect() as conn:
            task = kanban_db.get_task(conn, task_id)
            if task is not None and task.current_run_id is None:
                # Task has been completed/closed — receipt is superseded.
                return None

        try:
            with self._connect() as conn:
                store = self._store_fn or kanban_db.store_attachment_bytes
                attachment_id = store(
                    conn,
                    task_id,
                    filename,
                    payload,
                    content_type="application/json",
                    uploaded_by=self.uploaded_by,
                    board=self.board,
                    max_bytes=MAX_RECEIPT_BYTES,
                )
        except ApprovalDenied:
            raise
        except ToolRouteError:
            raise
        except Exception as exc:
            # The response may have been lost after the transaction committed.
            # Probe the native store before classifying the call as failed; this
            # prevents a retry from creating a collision-suffixed duplicate.
            recovered = self._read_existing(task_id, run_id, filename, payload)
            if recovered is not None:
                return recovered
            if isinstance(exc, OSError):
                raise ReceiptRecoveryError(
                    "receipt_attach_failed", str(exc), retryable=True
                ) from exc
            raise ToolRouteError(str(exc)) from exc

        verified = self._read_existing(task_id, run_id, filename, payload)
        if verified is None:
            # Task may have been completed between storage and verification
            # (superseded).  The attachment was stored; return a best-effort
            # outcome without the verified attachment_id.
            return NativeAttachmentOutcome(
                attachment_id=attachment_id,
                stored_path="",
                stored_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                created=True,
            )
        if verified.attachment_id != attachment_id:
            raise ReceiptRecoveryError(
                "attachment_readback_failed",
                "native attachment row was not readable after storage",
                retryable=True,
            )
        return NativeAttachmentOutcome(
            attachment_id=verified.attachment_id,
            stored_path=verified.stored_path,
            stored_bytes=verified.stored_bytes,
            sha256=verified.sha256,
            created=True,
        )


class ReceiptStore:
    """Publish immutable receipts and verify their durable stored bytes."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.root.is_symlink() or not self.root.is_dir():
                raise OSError("receipt root must be a real directory")
            os.chmod(self.root, 0o700)
        except OSError as exc:
            raise ReceiptRecoveryError(
                "receipt_path_failed", str(exc), retryable=True
            ) from exc

    def _receipt_path(self, completion_key: str) -> Path:
        return self.root / f"{_validate_completion_key(completion_key)}.json"

    def _build_receipt(
        self, event: dict[str, object], result: dict[str, object]
    ) -> dict[str, object]:
        if not isinstance(event, dict) or not isinstance(result, dict):
            raise ReceiptRecoveryError(
                "malformed_receipt_payload",
                "event and result must be JSON objects",
                retryable=False,
            )
        completion_key = _validate_completion_key(event.get("completion_key"))
        task_id = _validate_task_id(event.get("task_id"))
        run_id = _validate_run_id(event.get("run_id"))
        if (
            result.get("completion_key") != completion_key
            or result.get("task_id") != task_id
            or result.get("run_id") != run_id
            or result.get("verdict") not in _ALLOWED_VERDICTS
        ):
            raise ReceiptRecoveryError(
                "malformed_receipt_payload",
                "task_id/run_id/completion_key must match and verdict must be valid",
                retryable=False,
            )
        event_sha256 = canonical_sha256(event)
        result_sha256 = canonical_sha256(result)
        body: dict[str, object] = {
            "schema_version": RECEIPT_SCHEMA,
            "task_id": task_id,
            "run_id": run_id,
            "completion_key": completion_key,
            "event_id": f"evt_{event_sha256}",
            "event_sha256": event_sha256,
            "result_id": f"res_{result_sha256}",
            "result_sha256": result_sha256,
            "event": event,
            "result": result,
        }
        body["receipt_sha256"] = canonical_sha256(body)
        payload = _canonical_bytes(body) + b"\n"
        if len(payload) > MAX_RECEIPT_BYTES:
            raise ReceiptRecoveryError(
                "receipt_too_large",
                f"receipt is {len(payload)} bytes; maximum is {MAX_RECEIPT_BYTES}",
                retryable=False,
            )
        return body

    def _fsync(self, descriptor: int) -> None:
        os.fsync(descriptor)

    def _exclusive_write(self, path: Path, payload: bytes) -> bool:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=self.root)
        temporary = Path(temporary_name)
        published = False
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                self._fsync(handle.fileno())
            try:
                os.link(temporary, path)
                published = True
            except FileExistsError:
                return False
            directory_fd = os.open(self.root, os.O_RDONLY)
            try:
                self._fsync(directory_fd)
            finally:
                os.close(directory_fd)
            os.chmod(path, 0o600)
            return True
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            if not published and path.exists():
                # Existing immutable receipt is intentionally preserved.
                pass

    def _read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def _decode_and_verify(self, path: Path, payload: bytes) -> dict[str, object]:
        if len(payload) > MAX_RECEIPT_BYTES or not payload.isascii():
            raise ReceiptRecoveryError(
                "receipt_consistency_failed",
                "receipt violates ASCII or size contract",
                retryable=False,
            )
        try:
            value = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReceiptRecoveryError(
                "receipt_consistency_failed", str(exc), retryable=False
            ) from exc
        if not isinstance(value, dict):
            raise ReceiptRecoveryError(
                "receipt_consistency_failed", "receipt root must be an object", retryable=False
            )
        body = {key: item for key, item in value.items() if key != "receipt_sha256"}
        try:
            event = value["event"]
            result = value["result"]
            completion_key = _validate_completion_key(value["completion_key"])
            task_id = _validate_task_id(value["task_id"])
            run_id = _validate_run_id(value["run_id"])
        except (KeyError, ReceiptRecoveryError) as exc:
            raise ReceiptRecoveryError(
                "receipt_consistency_failed", str(exc), retryable=False
            ) from exc
        consistent = bool(
            value.get("schema_version") == RECEIPT_SCHEMA
            and path == self._receipt_path(completion_key)
            and isinstance(event, dict)
            and isinstance(result, dict)
            and event.get("task_id") == task_id == result.get("task_id")
            and event.get("run_id") == run_id == result.get("run_id")
            and event.get("completion_key") == completion_key == result.get("completion_key")
            and value.get("event_sha256") == canonical_sha256(event)
            and value.get("event_id") == f"evt_{canonical_sha256(event)}"
            and value.get("result_sha256") == canonical_sha256(result)
            and value.get("result_id") == f"res_{canonical_sha256(result)}"
            and value.get("receipt_sha256") == canonical_sha256(body)
        )
        if not consistent:
            raise ReceiptRecoveryError(
                "receipt_consistency_failed",
                "task/run/event/result/receipt tuple did not verify",
                retryable=False,
            )
        return value

    def read_bytes(self, completion_key: str) -> bytes:
        path = self._receipt_path(completion_key)
        try:
            payload = self._read_bytes(path)
        except OSError as exc:
            raise ReceiptRecoveryError(
                "receipt_readback_failed", str(exc), retryable=True
            ) from exc
        self._decode_and_verify(path, payload)
        return payload

    def read(self, completion_key: str) -> dict[str, object]:
        path = self._receipt_path(completion_key)
        return self._decode_and_verify(path, self.read_bytes(completion_key))

    def _remove_uncommitted(self, path: Path) -> None:
        path.unlink(missing_ok=True)
        directory_fd = os.open(self.root, os.O_RDONLY)
        try:
            self._fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def publish(
        self,
        event: dict[str, object],
        result: dict[str, object],
        *,
        attachment_publisher: Optional[NativeKanbanAttachmentPublisher] = None,
    ) -> PublishOutcome:
        receipt = self._build_receipt(event, result)
        completion_key = str(receipt["completion_key"])
        task_id = str(receipt["task_id"])
        run_id = _validate_run_id(receipt["run_id"])
        path = self._receipt_path(completion_key)
        payload = _canonical_bytes(receipt) + b"\n"
        try:
            created = self._exclusive_write(path, payload)
        except OSError as exc:
            raise ReceiptRecoveryError(
                "receipt_write_failed", str(exc), retryable=True
            ) from exc

        try:
            persisted = self.read_bytes(completion_key)
            if persisted != payload:
                raise ReceiptRecoveryError(
                    "immutable_receipt_conflict",
                    "existing receipt bytes differ from canonical event/result",
                    retryable=False,
                )
            attachment = (
                attachment_publisher.publish(
                    task_id=task_id,
                    run_id=run_id,
                    completion_key=completion_key,
                    payload=persisted,
                )
                if attachment_publisher is not None
                else None
            )
        except (ApprovalDenied, ToolRouteError):
            if created:
                self._remove_uncommitted(path)
            raise

        return PublishOutcome(
            receipt_path=str(path),
            receipt_sha256=hashlib.sha256(payload).hexdigest(),
            stored_bytes=len(payload),
            created=created,
            attached=attachment is not None,
            attachment_id=attachment.attachment_id if attachment else None,
            attachment_created=attachment.created if attachment else False,
        )


class RecoveryCoordinator:
    """Persist bounded attempt state and serialize duplicate direct-hook triggers."""

    def __init__(self, root: Path, *, max_attempts: int) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        self.root = Path(root)
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.root, 0o700)
        except OSError as exc:
            raise ReceiptRecoveryError("recovery_path_failed", str(exc), retryable=True) from exc
        self.max_attempts = max_attempts
        self._thread_locks_guard = threading.Lock()
        self._thread_locks: dict[str, threading.Lock] = {}

    def _paths(self, completion_key: str) -> tuple[Path, Path]:
        key = _validate_completion_key(completion_key)
        return self.root / f"{key}.state.json", self.root / f"{key}.lock"

    def _thread_lock(self, completion_key: str) -> threading.Lock:
        with self._thread_locks_guard:
            return self._thread_locks.setdefault(completion_key, threading.Lock())

    def _write_state(self, path: Path, outcome: RecoveryOutcome) -> None:
        payload = _canonical_bytes(_json_safe(asdict(outcome))) + b"\n"
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", dir=self.root
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                directory_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                temporary.unlink(missing_ok=True)
        except OSError as exc:
            raise ReceiptRecoveryError(
                "recovery_state_write_failed", str(exc), retryable=False
            ) from exc

    def _read_outcome(self, path: Path) -> Optional[RecoveryOutcome]:
        try:
            value = json.loads(path.read_text(encoding="ascii"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReceiptRecoveryError("recovery_state_invalid", str(exc), retryable=False) from exc
        if not isinstance(value, dict):
            raise ReceiptRecoveryError(
                "recovery_state_invalid", "state root must be an object", retryable=False
            )
        try:
            return RecoveryOutcome(
                status=str(value["status"]),
                attempts=int(value["attempts"]),
                reason=value.get("reason"),
                detail=value.get("detail"),
                first_failure=value.get("first_failure"),
                result=value.get("result"),
                artifact_count=int(value.get("artifact_count", 0)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReceiptRecoveryError("recovery_state_invalid", str(exc), retryable=False) from exc

    def read_state(self, completion_key: str) -> dict[str, object]:
        state_path, _ = self._paths(completion_key)
        outcome = self._read_outcome(state_path)
        return _json_safe(asdict(outcome)) if outcome else {}

    @staticmethod
    def _first_failure(
        prior: Optional[RecoveryOutcome], attempt: int, reason: str, detail: str
    ) -> dict[str, object]:
        return prior.first_failure if prior and prior.first_failure else {
            "attempt": attempt,
            "reason": reason,
            "detail": detail,
        }

    def attempt(self, completion_key: str, operation: Callable[[], Any]) -> RecoveryOutcome:
        state_path, lock_path = self._paths(completion_key)
        with self._thread_lock(completion_key):
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                prior = self._read_outcome(state_path)
                if prior and prior.status in {"completed", "terminal"}:
                    return prior
                attempts = (prior.attempts if prior else 0) + 1
                self._write_state(
                    state_path,
                    RecoveryOutcome(
                        status="in_progress",
                        attempts=attempts,
                        first_failure=prior.first_failure if prior else None,
                    ),
                )
                try:
                    raw_result = operation()
                    result = _json_safe(raw_result)
                except ApprovalDenied as exc:
                    reason, detail = "approval_denied", str(exc)
                    outcome = RecoveryOutcome(
                        status="terminal",
                        attempts=attempts,
                        reason=reason,
                        detail=detail,
                        first_failure=self._first_failure(prior, attempts, reason, detail),
                        artifact_count=0,
                    )
                except ToolRouteError as exc:
                    reason, detail = "tool_route_error", str(exc)
                    outcome = RecoveryOutcome(
                        status="terminal",
                        attempts=attempts,
                        reason=reason,
                        detail=detail,
                        first_failure=self._first_failure(prior, attempts, reason, detail),
                        artifact_count=0,
                    )
                except ReceiptRecoveryError as exc:
                    first = self._first_failure(prior, attempts, exc.code, exc.detail)
                    if not exc.retryable:
                        outcome = RecoveryOutcome(
                            status="terminal",
                            attempts=attempts,
                            reason=exc.code,
                            detail=exc.detail,
                            first_failure=first,
                            artifact_count=0,
                        )
                    elif attempts >= self.max_attempts:
                        outcome = RecoveryOutcome(
                            status="terminal",
                            attempts=attempts,
                            reason="retry_cap_exhausted",
                            detail=exc.code,
                            first_failure=first,
                            artifact_count=0,
                        )
                    else:
                        outcome = RecoveryOutcome(
                            status="retryable",
                            attempts=attempts,
                            reason=exc.code,
                            detail=exc.detail,
                            first_failure=first,
                            artifact_count=0,
                        )
                except OSError as exc:
                    reason, detail = "operation_failed", str(exc)
                    first = self._first_failure(prior, attempts, reason, detail)
                    outcome = RecoveryOutcome(
                        status="terminal" if attempts >= self.max_attempts else "retryable",
                        attempts=attempts,
                        reason="retry_cap_exhausted" if attempts >= self.max_attempts else reason,
                        detail=detail,
                        first_failure=first,
                        artifact_count=0,
                    )
                else:
                    artifact_count = int(
                        isinstance(result, dict) and bool(result.get("attached"))
                    )
                    outcome = RecoveryOutcome(
                        status="completed",
                        attempts=attempts,
                        first_failure=prior.first_failure if prior else None,
                        result=result,
                        artifact_count=artifact_count,
                    )
                self._write_state(state_path, outcome)
                return outcome
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
