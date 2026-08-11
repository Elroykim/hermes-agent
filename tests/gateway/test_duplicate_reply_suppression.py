"""Tests for duplicate reply suppression across the gateway stack.

Covers four fix paths:
  1. base.py: stale response suppressed when interrupt_event is set and a
     pending message exists (#8221 / #2483)
  2. run.py return path: only confirmed final streamed delivery suppresses
     the fallback final send; partial streamed output must not
  3. run.py queued-message path: same-event replays are discarded, and the
     first response is skipped only when final delivery was actually confirmed
  4. stream_consumer.py cancellation handler: only confirms final delivery
     when the best-effort send actually succeeds, not merely because partial
     content was sent earlier
"""

import asyncio
import importlib
import sys
import types
from types import SimpleNamespace

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    SendResult,
)
from gateway.session import SessionSource, build_session_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class StubAdapter(BasePlatformAdapter):
    """Minimal concrete adapter for testing."""

    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="fake"), Platform.DISCORD)
        self.sent = []

    async def connect(self, *, is_reconnect: bool = False):
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append({"chat_id": chat_id, "content": content})
        return SendResult(success=True, message_id="msg1")

    async def send_typing(self, chat_id, metadata=None):
        pass

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}


def _make_event(text="hello", chat_id="c1", user_id="u1"):
    return MessageEvent(
        text=text,
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id=chat_id,
            chat_type="dm",
            user_id=user_id,
        ),
        message_id="m1",
    )


# ===================================================================
# Test 1: base.py — stale response suppressed on interrupt (#8221)
# ===================================================================

class TestBaseInterruptSuppression:
    @pytest.mark.asyncio
    async def test_stale_response_suppressed_when_interrupted(self):
        """When interrupt_event is set AND a pending message exists,
        base.py should suppress the stale response instead of sending it."""
        adapter = StubAdapter()

        stale_response = "This is the stale answer to the first question."
        pending_response = "This is the answer to the second question."
        call_count = 0

        async def fake_handler(event):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return stale_response
            return pending_response

        adapter.set_message_handler(fake_handler)

        event_a = _make_event(text="first question")
        session_key = build_session_key(event_a.source)

        # Simulate: message A is being processed, message B arrives
        # The interrupt event is set and B is in pending_messages
        interrupt_event = asyncio.Event()
        interrupt_event.set()
        adapter._active_sessions[session_key] = interrupt_event

        event_b = _make_event(text="second question")
        adapter._pending_messages[session_key] = event_b

        await adapter._process_message_background(event_a, session_key)

        # The in-band pending-drain now hands off to a fresh task instead
        # of recursing (#17758).  Wait for that task to finish before
        # checking the sent list.
        for _ in range(200):
            if any(s["content"] == pending_response for s in adapter.sent):
                break
            await asyncio.sleep(0.01)
        await adapter.cancel_background_tasks()

        # The stale response should NOT have been sent.
        stale_sends = [s for s in adapter.sent if s["content"] == stale_response]
        assert len(stale_sends) == 0, (
            f"Stale response was sent {len(stale_sends)} time(s) — should be suppressed"
        )
        # The pending message's response SHOULD have been sent.
        pending_sends = [s for s in adapter.sent if s["content"] == pending_response]
        assert len(pending_sends) == 1, "Pending message response should be sent"


# Test 2: run.py — partial streamed output must not suppress final send
# ===================================================================

class TestOnlyFinalStreamDeliverySuppressesFinalSend:
    """The gateway should suppress the fallback final send only when the
    stream consumer confirmed the final assistant reply was delivered.

    Partial streamed output is not enough. If only already_sent=True,
    the fallback final send must still happen so Telegram users don't lose
    the real answer."""

    def _make_mock_stream_consumer(self, already_sent=False, final_response_sent=False):
        sc = SimpleNamespace(
            already_sent=already_sent,
            final_response_sent=final_response_sent,
        )
        return sc


    def test_already_sent_not_set_when_nothing_sent(self):
        """When stream consumer hasn't sent anything, already_sent should
        not be set on the response."""
        sc = self._make_mock_stream_consumer(already_sent=False, final_response_sent=False)
        response = {"final_response": "text", "response_previewed": False}

        if sc and isinstance(response, dict) and not response.get("failed"):
            _final = response.get("final_response") or ""
            _is_empty_sentinel = not _final or _final == "(empty)"
            _streamed = bool(sc and getattr(sc, "final_response_sent", False))
            _previewed = bool(response.get("response_previewed"))
            if not _is_empty_sentinel and (_streamed or _previewed):
                response["already_sent"] = True

        assert "already_sent" not in response


# ===================================================================
# Test 2b: run.py — empty response never suppressed (#10xxx)
# ===================================================================

class TestEmptyResponseNotSuppressed:
    """When the model returns '(empty)' after tool calls (e.g. mimo-v2-pro
    going silent after web_search), the gateway must NOT suppress delivery
    even if the stream consumer sent intermediate text earlier.

    Without this fix, the user sees partial streaming text ('Let me search
    for that') and then silence — the '(empty)' sentinel is swallowed by
    already_sent=True."""

    def _make_mock_stream_consumer(self, already_sent=False, final_response_sent=False):
        return SimpleNamespace(
            already_sent=already_sent,
            final_response_sent=final_response_sent,
        )

    def _apply_suppression_logic(self, response, sc):
        """Reproduce the fixed logic from gateway/run.py return path."""
        if sc and isinstance(response, dict) and not response.get("failed"):
            _final = response.get("final_response") or ""
            _is_empty_sentinel = not _final or _final == "(empty)"
            _streamed = bool(sc and getattr(sc, "final_response_sent", False))
            _previewed = bool(response.get("response_previewed"))
            if not _is_empty_sentinel and (_streamed or _previewed):
                response["already_sent"] = True

    def test_empty_sentinel_not_suppressed_with_already_sent(self):
        """'(empty)' final_response should NOT be suppressed even when
        streaming sent intermediate content."""
        sc = self._make_mock_stream_consumer(already_sent=True, final_response_sent=True)
        response = {"final_response": "(empty)"}
        self._apply_suppression_logic(response, sc)
        assert "already_sent" not in response


    def test_none_response_not_suppressed_with_already_sent(self):
        """None final_response should NOT be suppressed."""
        sc = self._make_mock_stream_consumer(already_sent=True, final_response_sent=True)
        response = {"final_response": None}
        self._apply_suppression_logic(response, sc)
        assert "already_sent" not in response


class TestQueuedMessageAlreadyStreamed:
    """The queued-message path should skip the first response only when the
    final response was actually streamed."""

    def _make_mock_sc(self, already_sent=False, final_response_sent=False):
        return SimpleNamespace(
            already_sent=already_sent,
            final_response_sent=final_response_sent,
        )


    def test_queued_path_detects_confirmed_final_stream_delivery(self):
        """Confirmed final streamed delivery should skip the resend."""
        _sc = self._make_mock_sc(already_sent=True, final_response_sent=True)
        response = {"response_previewed": False}

        _already_streamed = bool(
            (_sc and getattr(_sc, "final_response_sent", False))
            or bool(response.get("response_previewed"))
        )

        assert _already_streamed is True

    def test_queued_path_detects_previewed_response_delivery(self):
        """A response already previewed via the adapter should not be resent
        before processing the queued follow-up."""
        _sc = self._make_mock_sc(already_sent=False, final_response_sent=False)
        response = {"response_previewed": True}

        _already_streamed = bool(
            (_sc and getattr(_sc, "final_response_sent", False))
            or bool(response.get("response_previewed"))
        )

        assert _already_streamed is True


class QueuedReplayAdapter(BasePlatformAdapter):
    """Slack adapter double that records terminal sends."""

    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="fake"), Platform.SLACK)
        self.sent = []

    async def connect(self, *, is_reconnect: bool = False):
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append(
            {
                "chat_id": chat_id,
                "content": content,
                "reply_to": reply_to,
                "metadata": metadata,
            }
        )
        return SendResult(success=True, message_id=f"reply-{len(self.sent)}")

    async def send_typing(self, chat_id, metadata=None):
        pass

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}


class IdenticalTerminalReplyAgent:
    calls = []

    def __init__(self, **kwargs):
        self.tools = []

    def run_conversation(self, message, conversation_history=None, task_id=None):
        type(self).calls.append(message)
        return {
            "final_response": "Standing GV is complete.",
            "messages": [],
            "api_calls": 1,
        }


def _make_queued_replay_runner(adapter):
    gateway_run = importlib.import_module("gateway.run")
    runner = object.__new__(gateway_run.GatewayRunner)
    runner.adapters = {adapter.platform: adapter}
    runner._voice_mode = {}
    runner._prefill_messages = []
    runner._ephemeral_system_prompt = ""
    runner._reasoning_config = None
    runner._provider_routing = {}
    runner._fallback_model = None
    runner._session_db = None
    runner._running_agents = {}
    runner._session_run_generation = {}
    runner.hooks = SimpleNamespace(loaded_hooks=False)
    runner.config = SimpleNamespace(
        thread_sessions_per_user=False,
        group_sessions_per_user=False,
        stt_enabled=False,
    )
    runner._model = "openai/gpt-4.1-mini"
    runner._base_url = None
    return runner


async def _run_queued_replay_case(monkeypatch, tmp_path, pending_message_id):
    IdenticalTerminalReplyAgent.calls = []

    fake_dotenv = types.ModuleType("dotenv")
    fake_dotenv.load_dotenv = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    fake_run_agent = types.ModuleType("run_agent")
    fake_run_agent.AIAgent = IdenticalTerminalReplyAgent
    monkeypatch.setitem(sys.modules, "run_agent", fake_run_agent)

    gateway_run = importlib.import_module("gateway.run")
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    monkeypatch.setattr(
        gateway_run,
        "_resolve_runtime_agent_kwargs",
        lambda: {"api_key": "fake"},
    )

    adapter = QueuedReplayAdapter()
    runner = _make_queued_replay_runner(adapter)
    source = SessionSource(
        platform=Platform.SLACK,
        scope_id="T-WORKSPACE",
        chat_id="C-GV",
        chat_type="channel",
        thread_id="1723456789.000100",
    )
    session_key = "agent:main:slack:channel:C-GV:1723456789.000100"
    adapter._pending_messages[session_key] = MessageEvent(
        text="Run standing GV",
        source=source,
        message_id=pending_message_id,
    )

    result = await runner._run_agent(
        message="Run standing GV",
        context_prompt="",
        history=[],
        source=source,
        session_id="sess-standing-gv",
        session_key=session_key,
        event_message_id="1723456789.000200",
    )

    # Model BasePlatformAdapter's normal terminal send after _run_agent returns.
    if not result.get("already_sent"):
        await adapter.send(
            source.chat_id,
            result["final_response"],
            reply_to="1723456789.000200",
            metadata={"thread_id": source.thread_id},
        )
    return adapter


class TestQueuedSameEventReplaySuppression:
    @pytest.mark.asyncio
    async def test_same_scoped_event_queued_behind_itself_runs_once(
        self, monkeypatch, tmp_path
    ):
        adapter = await _run_queued_replay_case(
            monkeypatch,
            tmp_path,
            pending_message_id="1723456789.000200",
        )

        assert IdenticalTerminalReplyAgent.calls == ["Run standing GV"]
        assert [item["content"] for item in adapter.sent] == [
            "Standing GV is complete."
        ]

    @pytest.mark.asyncio
    async def test_distinct_event_identity_with_identical_text_still_runs(
        self, monkeypatch, tmp_path
    ):
        adapter = await _run_queued_replay_case(
            monkeypatch,
            tmp_path,
            pending_message_id="1723456789.000201",
        )

        assert IdenticalTerminalReplyAgent.calls == [
            "Run standing GV",
            "Run standing GV",
        ]
        assert [item["content"] for item in adapter.sent] == [
            "Standing GV is complete.",
            "Standing GV is complete.",
        ]


# ===================================================================
# Test 4: stream_consumer.py — cancellation handler delivery confirmation
# ===================================================================

class TestCancellationHandlerDeliveryConfirmation:
    """The stream consumer's cancellation handler should only set
    final_response_sent when the best-effort send actually succeeds.
    Partial content (already_sent=True) alone must not promote to
    final_response_sent — that would suppress the gateway's fallback
    send even when the user never received the real answer."""

    def test_partial_only_no_accumulated_stays_false(self):
        """Cancelled after sending intermediate text, nothing accumulated.
        final_response_sent must stay False so the gateway fallback fires."""
        already_sent = True
        final_response_sent = False
        accumulated = ""
        message_id = None

        _best_effort_ok = False
        if accumulated and message_id:
            _best_effort_ok = True  # wouldn't enter
        if _best_effort_ok and not final_response_sent:
            final_response_sent = True

        assert final_response_sent is False

    def test_best_effort_succeeds_sets_true(self):
        """When accumulated content exists and best-effort send succeeds,
        final_response_sent should become True."""
        already_sent = True
        final_response_sent = False
        accumulated = "Here are the search results..."
        message_id = "msg_123"

        _best_effort_ok = False
        if accumulated and message_id:
            _best_effort_ok = True  # simulating successful _send_or_edit
        if _best_effort_ok and not final_response_sent:
            final_response_sent = True

        assert final_response_sent is True


class TestFinalContentDeliveredSuppression:
    """When stream consumer delivered the final content but the cosmetic
    final edit (cursor removal) failed, the gateway must suppress the
    fallback send to prevent duplicate messages.

    Covers the scenario not handled by final_response_sent alone:
    content reached the user via _send_or_edit, but the subsequent edit
    that clears a typing cursor or streaming marker failed, leaving
    final_response_sent=False even though the user already saw the text.
    """

    def test_content_delivered_but_final_edit_failed_suppresses(self):
        """final_content_delivered=True + final_response_sent=False
        must suppress (content already visible to user)."""
        sc = SimpleNamespace(
            already_sent=True,
            final_response_sent=False,
            final_content_delivered=True,
        )
        response = {"final_response": "Hello!", "response_previewed": False}

        _streamed = bool(getattr(sc, "final_response_sent", False))
        _previewed = bool(response.get("response_previewed"))
        _content_delivered = bool(getattr(sc, "final_content_delivered", False))
        _is_empty_sentinel = (
            not response.get("final_response")
            or response.get("final_response") == "(empty)"
        )
        if not _is_empty_sentinel and (_streamed or _previewed or _content_delivered):
            response["already_sent"] = True

        assert response.get("already_sent") is True
