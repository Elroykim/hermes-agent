"""Regression tests for gateway approval prompt delivery failures."""

import asyncio
from types import SimpleNamespace
from typing import cast

import pytest

from gateway import run as gateway_run


class _Future:
    def __init__(self, value=None, exc=None):
        self._value = value
        self._exc = exc

    def result(self, timeout=None):
        if self._exc:
            raise self._exc
        return self._value


class _Adapter:
    typed_command_prefix = "!"

    async def send_exec_approval(self, **kwargs):
        raise AssertionError("coroutine should be intercepted by fake scheduler")

    async def send(self, chat_id, content, metadata=None):
        raise AssertionError("coroutine should be intercepted by fake scheduler")


def _close(coro):
    if hasattr(coro, "close"):
        coro.close()


def test_approval_notify_raises_when_button_and_text_delivery_fail(monkeypatch):
    """A failed Slack button send plus failed text fallback must fail notify.

    Returning normally here makes tools.approval wait for user input even though
    no approval prompt was delivered to the chat surface.
    """
    scheduled = []

    def fake_schedule(coro, loop, logger=None, log_message=None):
        scheduled.append(log_message)
        _close(coro)
        if log_message == "send_exec_approval scheduling error":
            return _Future(SimpleNamespace(success=False, error="invalid_auth"))
        return _Future(SimpleNamespace(success=False, error="channel_not_found"))

    monkeypatch.setattr(gateway_run, "safe_schedule_threadsafe", fake_schedule)

    with pytest.raises(RuntimeError, match="approval text-send failed"):
        gateway_run._send_exec_approval_or_text_sync(
            adapter=_Adapter(),
            chat_id="C1",
            command="rm -rf .git",
            session_key="agent:main:slack:group:C1",
            description="recursive delete",
            metadata={"thread_id": "1.2"},
            loop=cast(asyncio.AbstractEventLoop, object()),
        )

    assert scheduled == [
        "send_exec_approval scheduling error",
        "Approval text-send scheduling error",
    ]


def test_approval_notify_accepts_successful_text_fallback(monkeypatch):
    scheduled = []

    def fake_schedule(coro, loop, logger=None, log_message=None):
        scheduled.append(log_message)
        _close(coro)
        if log_message == "send_exec_approval scheduling error":
            return _Future(SimpleNamespace(success=False, error="invalid_blocks"))
        return _Future(SimpleNamespace(success=True, error=None))

    monkeypatch.setattr(gateway_run, "safe_schedule_threadsafe", fake_schedule)

    gateway_run._send_exec_approval_or_text_sync(
        adapter=_Adapter(),
        chat_id="C1",
        command="rm -rf .git",
        session_key="agent:main:slack:group:C1",
        description="recursive delete",
        metadata=None,
        loop=cast(asyncio.AbstractEventLoop, object()),
    )

    assert scheduled == [
        "send_exec_approval scheduling error",
        "Approval text-send scheduling error",
    ]


def test_approval_notify_returns_after_successful_button_send(monkeypatch):
    scheduled = []

    def fake_schedule(coro, loop, logger=None, log_message=None):
        scheduled.append(log_message)
        _close(coro)
        return _Future(SimpleNamespace(success=True, error=None))

    monkeypatch.setattr(gateway_run, "safe_schedule_threadsafe", fake_schedule)

    gateway_run._send_exec_approval_or_text_sync(
        adapter=_Adapter(),
        chat_id="C1",
        command="rm -rf .git",
        session_key="agent:main:slack:group:C1",
        description="recursive delete",
        metadata=None,
        loop=cast(asyncio.AbstractEventLoop, object()),
    )

    assert scheduled == ["send_exec_approval scheduling error"]
