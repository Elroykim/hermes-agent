"""MINA governed auto-goal activation on configured messaging platforms."""

from __future__ import annotations

import pytest

from gateway.config import Platform
from gateway.platforms.base import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource
from hermes_cli import goals


class _SessionEntry:
    session_id = "mina-auto-supervision-sid"


@pytest.mark.asyncio
async def test_ordinary_telegram_turn_becomes_supervised_goal(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        """
goals:
  max_turns: 9
  supervision:
    enabled: true
    auto_activate_platforms: [telegram]
    checkpoint_minutes: 45
    minimum_checkpoint_minutes: 30
    maximum_checkpoint_minutes: 60
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    goals._DB_CACHE.clear()

    runner = object.__new__(GatewayRunner)
    runner.config = {}
    monkeypatch.setattr(
        GatewayRunner,
        "_set_mina_supervision_heartbeat",
        lambda self, event, entry: True,
    )
    source = SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="mina-chat",
        chat_type="dm",
        user_id="elroy",
    )
    event = MessageEvent(
        text="현재 Git 작업을 검증하고 안전하게 마무리해",
        message_type=MessageType.TEXT,
        source=source,
    )

    try:
        activated = await GatewayRunner._ensure_auto_supervised_goal(
            runner, event, source, _SessionEntry()
        )
        state = goals.GoalManager(_SessionEntry.session_id).state
        assert activated is True
        assert state is not None and state.status == "active"
        assert state.goal == event.text
        assert state.max_turns == 9
    finally:
        goals._DB_CACHE.clear()


@pytest.mark.asyncio
async def test_synthetic_continuation_does_not_replace_goal(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        """
goals:
  supervision:
    enabled: true
    auto_activate_platforms: [telegram]
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    goals._DB_CACHE.clear()
    runner = object.__new__(GatewayRunner)
    runner.config = {}
    source = SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="mina-chat",
        chat_type="dm",
        user_id="elroy",
    )
    event = MessageEvent(
        text="[Continuing toward your standing goal]\nGoal: test",
        message_type=MessageType.TEXT,
        source=source,
    )
    try:
        activated = await GatewayRunner._ensure_auto_supervised_goal(
            runner, event, source, _SessionEntry()
        )
        assert activated is False
        assert goals.GoalManager(_SessionEntry.session_id).state is None
    finally:
        goals._DB_CACHE.clear()
