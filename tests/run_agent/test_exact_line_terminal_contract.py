"""Fail-closed delivery for explicit one-line terminal contracts."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest
from unittest.mock import Mock, patch

sys.modules.setdefault("fire", types.SimpleNamespace(Fire=lambda *a, **k: None))
sys.modules.setdefault("firecrawl", types.SimpleNamespace(Firecrawl=object))
sys.modules.setdefault("fal_client", types.SimpleNamespace())


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("[HERMES_EXACT_TERMINAL_V1] READY", "READY"),
        ("Do not output exactly this one line: READY", None),
        ("quoted: [HERMES_EXACT_TERMINAL_V1] READY", None),
        ("[HERMES_EXACT_TERMINAL_V1] READY\nmore", None),
        ("[HERMES_EXACT_TERMINAL_V1] " + ("x" * 4097), None),
        ([{"type": "text", "text": "[HERMES_EXACT_TERMINAL_V1] READY"}], None),
    ],
)
def test_exact_line_contract_extraction_is_explicit_and_bounded(message, expected):
    from agent.conversation_loop import _extract_exact_line_contract

    assert _extract_exact_line_contract(message) == expected


def _response(content: str):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=content,
                    reasoning=None,
                    reasoning_content=None,
                    reasoning_details=None,
                    tool_calls=None,
                ),
                finish_reason="stop",
            )
        ],
        usage=None,
        model="test-model",
    )


def _agent(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("{}\n", encoding="utf-8")
    from run_agent import AIAgent

    agent = AIAgent(
        model="test-model",
        api_key="sk-dummy",
        base_url="https://example.invalid/v1",
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        platform="slack",
    )
    agent._disable_streaming = True
    return agent


def test_exact_line_contract_retries_partial_stop_then_returns_full(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "[MINA][FINAL] candidate=abc; overall=NOT_LIVE"
    responses = [_response(expected[:21]), _response(expected)]
    monkeypatch.setattr(
        agent,
        "_interruptible_api_call",
        lambda api_kwargs: responses.pop(0),
    )

    result = agent.run_conversation(
        f"No tools.\n[HERMES_EXACT_TERMINAL_V1] {expected}",
        stream_callback=lambda text: None,
    )

    assert result["final_response"] == expected
    assert result["api_calls"] == 2
    assert agent._stream_callback is None
    assert not any(
        message.get("role") == "assistant"
        and message.get("content") == expected[:21]
        for message in result["messages"]
    )


def test_exact_line_contract_sends_only_contract_bound_history(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "MINA_VISIBLE_TERMINAL_OK"
    captured = []

    def _call(api_kwargs):
        captured.append(api_kwargs)
        return _response(expected)

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)

    result = agent.run_conversation(
        "[PDCA-3E] bounded live canary\n"
        f"[HERMES_EXACT_TERMINAL_V1] {expected}",
        conversation_history=[
            {"role": "user", "content": "HISTORICAL_SENTINEL " * 4000},
            {"role": "assistant", "content": "old answer"},
        ],
    )

    assert result["final_response"] == expected
    assert len(captured) == 1
    request_messages = captured[0]["messages"]
    assert [message["role"] for message in request_messages] == ["system", "user"]
    assert request_messages[-1]["content"] == (
        "Return exactly this terminal line and nothing else:\n" + expected
    )
    assert "HISTORICAL_SENTINEL" not in repr(request_messages)
    assert sum(len(str(message.get("content", ""))) for message in request_messages) < 1000
    assert "HISTORICAL_SENTINEL" in repr(result["messages"])


def test_gateway_wrapped_slack_contract_sends_only_two_bound_messages(
    tmp_path, monkeypatch
):
    """Exercise the shape produced by GatewayRunner before run_conversation."""
    agent = _agent(tmp_path, monkeypatch)
    expected = "MINA_VISIBLE_TERMINAL_OK"
    captured = {}

    def _call(api_kwargs):
        captured.update(api_kwargs)
        return _response(expected)

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)
    gateway_message = (
        '[Replying to: "P0 parent"]\n\n'
        "[Thread context — prior messages in this thread "
        "(not yet in conversation history):]\n"
        "[assistant] [HERMES_EXACT_TERMINAL_V1] STALE_QUOTED_VALUE\n"
        "[End of thread context]\n\n"
        "[New message]\n"
        "[Elroy | Slack user <@U0APE8BDM0W>] "
        f"[HERMES_EXACT_TERMINAL_V1] {expected}"
    )

    result = agent.run_conversation(
        gateway_message,
        conversation_history=[
            {"role": "user", "content": "GATEWAY_HISTORY_SENTINEL " * 4000},
            {"role": "assistant", "content": "old answer"},
        ],
    )

    assert result["final_response"] == expected
    assert [message["role"] for message in captured["messages"]] == [
        "system",
        "user",
    ]
    assert captured["messages"][-1]["content"].endswith(expected)
    assert "GATEWAY_HISTORY_SENTINEL" not in repr(captured)
    assert "STALE_QUOTED_VALUE" not in repr(captured)
    assert "tools" not in captured
    assert "tool_choice" not in captured


def test_gateway_wrapped_stale_contract_is_not_reactivated(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    captured = {}

    def _call(api_kwargs):
        captured.update(api_kwargs)
        return _response("ordinary response")

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)
    gateway_message = (
        "[Thread context — prior messages in this thread "
        "(not yet in conversation history):]\n"
        "[user] [HERMES_EXACT_TERMINAL_V1] STALE_QUOTED_VALUE\n"
        "[End of thread context]\n\n"
        "[New message]\n"
        "[Elroy | Slack user <@U0APE8BDM0W>] ordinary follow-up"
    )

    result = agent.run_conversation(
        gateway_message,
        conversation_history=[
            {"role": "user", "content": "ORDINARY_HISTORY_SENTINEL"},
            {"role": "assistant", "content": "old answer"},
        ],
    )

    assert result["final_response"] == "ordinary response"
    assert "ORDINARY_HISTORY_SENTINEL" in repr(captured["messages"])


def test_exact_line_contract_execution_middleware_cannot_reinflate_request(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "MINA_VISIBLE_TERMINAL_OK"
    captured = {}

    def _execution_middleware(request, next_call, **_context):
        replacement = dict(request)
        replacement["messages"] = [
            {"role": "user", "content": "MIDDLEWARE_HISTORY_SENTINEL"},
        ]
        replacement["tools"] = [{"type": "function", "function": {}}]
        replacement["tool_choice"] = "auto"
        return next_call(replacement)

    def _call(api_kwargs):
        captured.update(api_kwargs)
        return _response(expected)

    monkeypatch.setattr(
        "hermes_cli.middleware.run_llm_execution_middleware",
        _execution_middleware,
    )
    monkeypatch.setattr(agent, "_interruptible_api_call", _call)

    result = agent.run_conversation(
        f"[HERMES_EXACT_TERMINAL_V1] {expected}"
    )

    assert result["final_response"] == expected
    assert [message["role"] for message in captured["messages"]] == [
        "system",
        "user",
    ]
    assert "MIDDLEWARE_HISTORY_SENTINEL" not in repr(captured)
    assert "tools" not in captured
    assert "tool_choice" not in captured


def test_exact_line_contract_retry_remains_isolated_from_history(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "MINA_VISIBLE_TERMINAL_OK"
    captured = []
    responses = [_response("MINA_VISIBLE"), _response(expected)]

    def _call(api_kwargs):
        captured.append(api_kwargs)
        return responses.pop(0)

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)

    result = agent.run_conversation(
        f"[HERMES_EXACT_TERMINAL_V1] {expected}",
        conversation_history=[
            {"role": "user", "content": "RETRY_HISTORY_SENTINEL"},
            {"role": "assistant", "content": "old answer"},
        ],
    )

    assert result["final_response"] == expected
    assert len(captured) == 2
    for request in captured:
        request_messages = request["messages"]
        assert [message["role"] for message in request_messages] == [
            "system",
            "user",
        ]
        assert request_messages[-1]["content"].endswith(expected)
        assert "RETRY_HISTORY_SENTINEL" not in repr(request_messages)


def test_ordinary_slack_turn_preserves_conversation_history(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    captured = {}

    def _call(api_kwargs):
        captured.update(api_kwargs)
        return _response("ordinary response")

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)

    result = agent.run_conversation(
        "ordinary Slack request",
        conversation_history=[
            {"role": "user", "content": "NORMAL_HISTORY_SENTINEL"},
            {"role": "assistant", "content": "old answer"},
        ],
    )

    assert result["final_response"] == "ordinary response"
    assert "NORMAL_HISTORY_SENTINEL" in repr(captured["messages"])


def test_exact_line_contract_never_delivers_mismatch_after_retry(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "[MINA][FINAL] source=complete-pointer"
    responses = [_response("[P0][FINAL] source=comp"), _response(expected[:18])]
    monkeypatch.setattr(
        agent,
        "_interruptible_api_call",
        lambda api_kwargs: responses.pop(0),
    )

    result = agent.run_conversation(
        f"[HERMES_EXACT_TERMINAL_V1] {expected}"
    )

    final = result["final_response"]
    assert final.startswith("TERMINAL_CONTRACT_INCOMPLETE ")
    assert "expected_sha256=" in final
    assert "observed_chars=18" in final
    assert result["turn_exit_reason"] == "terminal_contract_incomplete"
    assert expected not in final
    assert "[P0][FINAL]" not in final
    assert sum(
        message.get("role") == "assistant" and message.get("content") == final
        for message in result["messages"]
    ) == 1
    assert not any(
        message.get("role") == "assistant"
        and message.get("content") in {
            "[P0][FINAL] source=comp",
            expected[:18],
        }
        for message in result["messages"]
    )


def test_exact_line_contract_forces_non_streaming_and_blocks_tools(
    tmp_path, monkeypatch
):
    agent = _agent(tmp_path, monkeypatch)
    agent._disable_streaming = False
    agent.thinking_callback = lambda text: None
    expected = "[MINA][FINAL] READY"
    tool_call = SimpleNamespace(
        id="tool-1",
        function=SimpleNamespace(name="read_file", arguments="{}"),
    )
    tool_response = _response("trying a tool")
    tool_response.choices[0].message.tool_calls = [tool_call]
    responses = [tool_response, _response(expected)]
    monkeypatch.setattr(
        agent,
        "_interruptible_api_call",
        lambda api_kwargs: responses.pop(0),
    )
    streaming_call = Mock(side_effect=AssertionError("streaming must be disabled"))
    monkeypatch.setattr(agent, "_interruptible_streaming_api_call", streaming_call)

    with patch("run_agent.handle_function_call") as dispatch:
        result = agent.run_conversation(
            f"[HERMES_EXACT_TERMINAL_V1] {expected}"
        )

    assert result["final_response"] == expected
    assert result["api_calls"] == 2
    streaming_call.assert_not_called()
    dispatch.assert_not_called()
    assert not any(
        message.get("_exact_line_contract_synthetic")
        for message in result["messages"]
    )


@pytest.mark.parametrize(
    ("terminal_error", "expected_prefix", "failed"),
    [
        (
            InterruptedError("user stopped the second request"),
            "TERMINAL_CONTRACT_INTERRUPTED ",
            False,
        ),
        (
            RuntimeError("provider secret must not escape"),
            "TERMINAL_CONTRACT_PROVIDER_ERROR ",
            True,
        ),
    ],
)
def test_exact_line_contract_abnormal_second_call_drops_retry_scaffolding(
    tmp_path, monkeypatch, terminal_error, expected_prefix, failed
):
    agent = _agent(tmp_path, monkeypatch)
    expected = "[MINA][FINAL] source=complete-pointer"
    partial = "[MINA][FINAL] source=comp"
    calls = iter([_response(partial), terminal_error])

    def _call(api_kwargs):
        outcome = next(calls)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(agent, "_interruptible_api_call", _call)

    result = agent.run_conversation(
        f"[HERMES_EXACT_TERMINAL_V1] {expected}"
    )

    assert result["final_response"].startswith(expected_prefix)
    assert "expected_sha256=" in result["final_response"]
    assert result["failed"] is failed
    assert "provider secret" not in result["final_response"]
    assert not any(
        message.get("_exact_line_contract_synthetic")
        or message.get("content") == partial
        or "Return the exact terminal line" in (message.get("content") or "")
        for message in result["messages"]
    )


def test_exact_line_retry_scaffolding_is_ephemeral_at_every_history_boundary():
    from agent.conversation_compression import _is_real_user_message
    from agent.turn_finalizer import (
        _drop_verification_continuation_scaffolding,
    )
    from run_agent import _is_ephemeral_scaffolding

    assistant = {
        "role": "assistant",
        "content": "rejected prefix",
        "_exact_line_contract_synthetic": True,
    }
    nudge = {
        "role": "user",
        "content": "private retry nudge",
        "_exact_line_contract_synthetic": True,
    }
    messages = [assistant, nudge, {"role": "user", "content": "real intent"}]

    assert _is_ephemeral_scaffolding(assistant)
    assert _is_ephemeral_scaffolding(nudge)
    assert not _is_real_user_message(nudge)

    _drop_verification_continuation_scaffolding(messages)
    assert messages == [{"role": "user", "content": "real intent"}]


@pytest.mark.parametrize("platform,kanban", [("cli", False), ("slack", True)])
def test_exact_line_contract_is_not_authoritative_outside_slack_user_turns(
    tmp_path, monkeypatch, platform, kanban
):
    agent = _agent(tmp_path, monkeypatch)
    agent.platform = platform
    if kanban:
        monkeypatch.setenv("HERMES_KANBAN_TASK", "task-1")
    response = "ordinary model response"
    monkeypatch.setattr(
        agent,
        "_interruptible_api_call",
        lambda api_kwargs: _response(response),
    )

    result = agent.run_conversation(
        "[HERMES_EXACT_TERMINAL_V1] expected terminal"
    )

    assert result["final_response"] == response
    assert result["api_calls"] == (3 if kanban else 1)
    assert result["turn_exit_reason"].startswith("text_response(")
