"""STOP-CANCEL-001: gateway ownership for background review work."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest

import run_agent as run_agent_module
from gateway import status as gateway_status
from gateway.config import Platform
from gateway.platforms.base import MessageEvent, MessageType
from gateway.run import GatewayRunner, _INTERRUPT_REASON_STOP
from gateway.session import SessionSource
from run_agent import AIAgent
from tests.run_agent.test_background_review import _bare_agent, _memory_add_review


class _Adapter:
    def __init__(self):
        self._pending_messages = {}

    async def interrupt_session_activity(self, session_key, chat_id):
        return None

    def get_pending_message(self, session_key):
        return self._pending_messages.pop(session_key, None)


class _AsyncStore:
    def __init__(self, session_key, store):
        self._session_key = session_key
        self._store = store

    async def get_or_create_session(self, source):
        return SimpleNamespace(session_key=self._session_key)


def _runner() -> GatewayRunner:
    runner = object.__new__(GatewayRunner)
    runner._running_agents = {}
    runner._running_agents_ts = {}
    runner._sessions = {}
    runner._auxiliary_work = {}
    runner._auxiliary_work_lock = threading.Lock()
    runner._agent_cache = {}
    runner._agent_cache_lock = threading.Lock()
    runner._background_tasks = set()
    runner._turn_leases = None
    runner.adapters = {Platform.SLACK: _Adapter()}
    runner._persist_active_agents = lambda: None
    runner._active_cron_job_count = lambda: 0
    runner._active_api_run_count = lambda: 0
    runner._update_runtime_status = lambda *args, **kwargs: None
    return runner


def _bind_parent(runner, parent, session_key):
    parent.background_review_lifecycle_callback = (
        lambda event, handle: runner._on_background_review_lifecycle(
            session_key, event, handle
        )
    )


@pytest.mark.asyncio
async def test_stop_cancels_evicted_review_and_suppresses_late_work(monkeypatch):
    """Old review must remain session-owned after its parent leaves the cache."""
    runner = _runner()
    source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C123",
        chat_type="channel",
        user_id="U123",
        thread_id="1700000000.000001",
    )
    session_key = "slack:C123:thread:1700000000.000001"
    provider_entered = threading.Event()
    provider_release = threading.Event()
    finished = threading.Event()
    counts = {"hard_interrupt": 0, "provider_return": 0, "callback": 0}

    class FakeReviewAgent:
        def __init__(self, **kwargs):
            self._session_messages = []
            self._interrupted = False

        def run_conversation(self, **kwargs):
            provider_entered.set()
            assert provider_release.wait(2)
            self._session_messages = _memory_add_review()
            counts["provider_return"] += 1

        def hard_interrupt(self, message=None):
            self._interrupted = True
            counts["hard_interrupt"] += 1

        def shutdown_memory_provider(self):
            pass

        def close(self):
            finished.set()

    monkeypatch.setattr(run_agent_module, "AIAgent", FakeReviewAgent)

    old_parent = _bare_agent()
    old_parent.background_review_callback = lambda _message: counts.__setitem__(
        "callback", counts["callback"] + 1
    )
    _bind_parent(runner, old_parent, session_key)
    old_parent._spawn_background_review(
        messages_snapshot=[{"role": "user", "content": "old turn"}],
        review_memory=True,
    )
    assert provider_entered.wait(2)
    assert runner._active_work_count() == 1

    # Cache eviction drops the old parent.  A fresh parent then owns the same
    # routing key before /stop arrives.
    old_parent.release_clients()
    new_parent = SimpleNamespace(hard_interrupt=lambda _message=None: None)
    _bind_parent(runner, new_parent, session_key)
    runner._running_agents[session_key] = new_parent
    await runner._interrupt_and_clear_session(
        session_key,
        source,
        interrupt_reason="explicit stop",
        invalidation_reason="test_stop",
        release_running_state=False,
    )

    provider_release.set()
    assert finished.wait(2)
    assert counts == {"hard_interrupt": 1, "provider_return": 1, "callback": 0}
    assert runner._active_auxiliary_work_count() == 0


def test_cancelled_provider_failure_does_not_publish_auxiliary_failure(monkeypatch):
    parent = _bare_agent()
    provider_entered = threading.Event()
    provider_release = threading.Event()
    provider_interrupted = threading.Event()
    review_finished = threading.Event()
    failures = []
    handles = []

    class FakeReviewAgent:
        def __init__(self, **kwargs):
            self._session_messages = []

        def run_conversation(self, **kwargs):
            provider_entered.set()
            assert provider_release.wait(2)
            raise RuntimeError("provider retry exhausted after stop")

        def hard_interrupt(self, message=None):
            provider_interrupted.set()

        def shutdown_memory_provider(self):
            pass

        def close(self):
            pass

    def lifecycle_callback(event, handle):
        if event == "register":
            handles.append(handle)
        elif event == "complete":
            review_finished.set()

    parent.background_review_lifecycle_callback = lifecycle_callback
    parent._emit_auxiliary_failure = lambda *args: failures.append(args)
    monkeypatch.setattr(run_agent_module, "AIAgent", FakeReviewAgent)

    parent._spawn_background_review(
        messages_snapshot=[{"role": "user", "content": "hello"}],
        review_memory=True,
    )
    assert provider_entered.wait(2)
    assert len(handles) == 1
    assert handles[0].cancel("stop") is True
    assert provider_interrupted.wait(2)
    provider_release.set()
    assert review_finished.wait(2)

    assert failures == []
    assert handles[0].done is True


@pytest.mark.asyncio
async def test_auxiliary_review_participates_in_drain(monkeypatch):
    runner = _runner()
    handle = SimpleNamespace(done=False)
    runner._register_auxiliary_work("slack:C123:thread:T1", handle)

    assert runner._active_work_count() == 1

    async def complete_after_drain_starts():
        await asyncio.sleep(0.02)
        handle.done = True
        runner._complete_auxiliary_work("slack:C123:thread:T1", handle)

    completion = asyncio.create_task(complete_after_drain_starts())
    _snapshot, timed_out = await runner._drain_active_agents(0.5)
    await completion

    assert timed_out is False
    assert runner._active_work_count() == 0


@pytest.mark.asyncio
async def test_stop_without_foreground_agent_cancels_owned_auxiliary_review():
    runner = _runner()
    session_key = "slack:C123:thread:1700000000.000001"
    cancelled = []

    class Handle:
        done = False

        def cancel(self, reason):
            cancelled.append(reason)
            return True

    runner._register_auxiliary_work(session_key, Handle())
    runner.session_store = object()
    runner._async_session_store = _AsyncStore(session_key, runner.session_store)
    runner._sibling_thread_run_keys = lambda source, own_key: []

    source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C123",
        chat_type="channel",
        user_id="U123",
        thread_id="1700000000.000001",
    )
    result = await runner._handle_stop_command(
        MessageEvent(text="/stop", message_type=MessageType.TEXT, source=source)
    )

    assert cancelled == [_INTERRUPT_REASON_STOP]
    assert "stopped" in str(getattr(result, "text", result)).lower()


@pytest.mark.asyncio
async def test_stop_cancels_auxiliary_only_sibling_session():
    runner = _runner()
    thread_id = "1700000000.000001"
    workspace_id = "TWORKSPACE"
    runner.config = SimpleNamespace(
        group_sessions_per_user=True,
        thread_sessions_per_user=True,
        multiplex_profiles=True,
    )
    own_source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C123",
        chat_type="channel",
        user_id="U123",
        thread_id=thread_id,
        scope_id=workspace_id,
        profile="mina",
    )
    sibling_source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C123",
        chat_type="channel",
        user_id="U999",
        thread_id=thread_id,
        scope_id=workspace_id,
        profile="mina",
    )
    own_key = runner._session_key_for_source(own_source)
    sibling_key = runner._session_key_for_source(sibling_source)
    cancelled = []

    class Handle:
        def __init__(self, key):
            self.key = key

        done = False

        def cancel(self, reason):
            cancelled.append((self.key, reason))
            return True

    runner._register_auxiliary_work(own_key, Handle(own_key))
    runner._register_auxiliary_work(sibling_key, Handle(sibling_key))
    runner.session_store = object()
    runner._async_session_store = _AsyncStore(own_key, runner.session_store)
    runner._is_user_authorized = lambda source: True

    async def interrupt(key, source, *, interrupt_reason, **kwargs):
        runner._cancel_auxiliary_work(key, interrupt_reason)

    runner._interrupt_and_clear_session = interrupt
    result = await runner._handle_stop_command(
        MessageEvent(text="/stop", message_type=MessageType.TEXT, source=own_source)
    )

    assert sorted(cancelled) == sorted(
        [
            (own_key, _INTERRUPT_REASON_STOP),
            (sibling_key, _INTERRUPT_REASON_STOP),
        ]
    )
    assert "stopped" in str(getattr(result, "text", result)).lower()


def test_runtime_status_writes_are_serialized(tmp_path, monkeypatch):
    path = tmp_path / "gateway_state.json"
    monkeypatch.setattr(gateway_status, "_get_runtime_status_path", lambda: path)
    gateway_status.write_runtime_status(
        gateway_state="running",
        active_agents=0,
        platform="slack",
        platform_state="connected",
    )

    real_read = gateway_status._read_json_file
    first_read = threading.Event()
    release_first = threading.Event()

    def controlled_read(target):
        payload = real_read(target)
        if threading.current_thread().name == "active-writer":
            first_read.set()
            assert release_first.wait(2)
        return payload

    monkeypatch.setattr(gateway_status, "_read_json_file", controlled_read)
    active_writer = threading.Thread(
        name="active-writer",
        target=lambda: gateway_status.write_runtime_status(active_agents=1),
    )
    platform_writer = threading.Thread(
        name="platform-writer",
        target=lambda: gateway_status.write_runtime_status(
            platform="telegram", platform_state="connected"
        ),
    )

    active_writer.start()
    assert first_read.wait(2)
    platform_writer.start()
    platform_writer.join(0.2)
    release_first.set()
    active_writer.join(2)
    platform_writer.join(2)

    payload = real_read(path)
    assert payload["active_agents"] == 1
    assert payload["platforms"]["slack"]["state"] == "connected"
    assert payload["platforms"]["telegram"]["state"] == "connected"
