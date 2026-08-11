"""Tests for the empty-terminal reasoning surface.

When the empty-response ladder is fully exhausted (prefill continuation,
empty-content retries, provider fallback), internal reasoning must not be
promoted into the delivered response.

Invariants pinned here:
- The persisted assistant message keeps the "(empty)" sentinel and the
  ``_empty_terminal_sentinel`` marker (replay semantics unchanged).
- Raw reasoning is never delivered or persisted.
- A truly empty exhaustion (no reasoning either) still returns "(empty)".
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

# Stub optional heavy imports so run_agent imports cleanly in isolation.
sys.modules.setdefault("fire", types.SimpleNamespace(Fire=lambda *a, **k: None))
sys.modules.setdefault("firecrawl", types.SimpleNamespace(Firecrawl=object))
sys.modules.setdefault("fal_client", types.SimpleNamespace())


def _build_agent(tmp_path, monkeypatch):
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
        platform="cli",
    )
    # Route through the non-streaming _interruptible_api_call path so the
    # monkeypatched fake responses are what the loop consumes.
    agent._disable_streaming = True
    return agent


def _reasoning_only_response():
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(
                content="",
                reasoning="The answer is 42 because of the calculation above.",
                reasoning_content=None,
                reasoning_details=None,
                tool_calls=None,
            ),
            finish_reason="stop",
        )],
        usage=None,
        model="test-model",
    )


def _truly_empty_response():
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(
                content="",
                reasoning=None,
                reasoning_content=None,
                reasoning_details=None,
                tool_calls=None,
            ),
            finish_reason="stop",
        )],
        usage=None,
        model="test-model",
    )


def test_exhausted_reasoning_only_delivers_opaque_failure(
    tmp_path, monkeypatch, caplog
):
    """Reasoning-only exhaustion is visible without exposing its contents."""
    agent = _build_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(
        agent, "_interruptible_api_call",
        lambda api_kwargs: _reasoning_only_response(),
    )

    result = agent.run_conversation("what is the answer?")

    final = result["final_response"]
    assert final.startswith("MODEL_EMPTY_TERMINAL ")
    assert "reasoning_sha256=" in final
    assert "The answer is 42" not in final
    assert "The answer is 42" not in caplog.text

    # The turn finalizer strips the internal empty sentinel from the transcript
    # tail; neither the reasoning nor the opaque delivery sentinel is durable
    # assistant content.
    assert not any(
        m.get("role") == "assistant"
        and (
            "The answer is 42" in (m.get("content") or "")
            or "MODEL_EMPTY_TERMINAL" in (m.get("content") or "")
        )
        for m in result["messages"]
    )


def test_exhausted_truly_empty_keeps_existing_behavior(tmp_path, monkeypatch):
    """No reasoning anywhere → behavior unchanged from main: the '(empty)'
    terminal (possibly rewritten by the downstream turn-completion explainer)
    is delivered, and no reasoning excerpt appears."""
    agent = _build_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(
        agent, "_interruptible_api_call",
        lambda api_kwargs: _truly_empty_response(),
    )

    result = agent.run_conversation("hello?")

    final = result["final_response"]
    # Either the raw sentinel (explainer off) or the explainer's rewrite —
    # never the reasoning-excerpt frame, which requires reasoning to exist.
    assert final == "(empty)" or final.startswith("⚠️ No reply:")
    assert "only internal reasoning" not in final


def test_reasoning_never_promoted_before_ladder_exhaustion(tmp_path, monkeypatch):
    """A reasoning-only response must first go through prefill continuation —
    if the model then produces real text, THAT is the answer, and no labeled
    reasoning excerpt appears."""
    agent = _build_agent(tmp_path, monkeypatch)
    responses = [
        _reasoning_only_response(),
        SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(
                    content="42.",
                    reasoning=None,
                    reasoning_content=None,
                    reasoning_details=None,
                    tool_calls=None,
                ),
                finish_reason="stop",
            )],
            usage=None,
            model="test-model",
        ),
    ]
    monkeypatch.setattr(
        agent, "_interruptible_api_call",
        lambda api_kwargs: responses.pop(0),
    )

    result = agent.run_conversation("what is the answer?")

    assert result["final_response"] == "42."
    assert "only internal reasoning" not in result["final_response"]
