import pytest

from agent.conversation_loop import _extract_exact_line_contract
from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent
from gateway.run import GatewayRunner
from gateway.session import SessionSource


def _make_runner(config: GatewayConfig) -> GatewayRunner:
    runner = object.__new__(GatewayRunner)
    runner.config = config
    runner.adapters = {}
    runner._model = "openai/gpt-4.1-mini"
    runner._base_url = None
    return runner


@pytest.mark.asyncio
async def test_preprocess_includes_slack_author_mention_for_shared_thread():
    """Shared Slack threads expose the current author's verifiable user ID
    next to the display name so 'mention me again' requests can bind the
    mention to the CURRENT speaker (#17916)."""
    runner = _make_runner(
        GatewayConfig(
            platforms={
                Platform.SLACK: PlatformConfig(enabled=True, token="fake"),
            },
        )
    )
    source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C123",
        chat_name="team-channel",
        chat_type="group",
        user_id="U123",
        user_name="Alice",
        thread_id="171.000",
    )
    event = MessageEvent(text="mention me again", source=source)

    result = await runner._prepare_inbound_message_text(
        event=event,
        source=source,
        history=[],
    )

    assert result == "[Alice | Slack user <@U123>] mention me again"


@pytest.mark.asyncio
async def test_preprocess_preserves_exact_terminal_contract_at_live_gateway_boundary():
    runner = _make_runner(
        GatewayConfig(
            group_sessions_per_user=False,
            platforms={
                Platform.SLACK: PlatformConfig(enabled=True, token="fake"),
            },
        )
    )
    source = SessionSource(
        platform=Platform.SLACK,
        chat_id="C0BLPP2N6BX",
        chat_name="thewon-system-control",
        chat_type="group",
        user_id="U0APE8BDM0W",
        user_name="Elroy",
        thread_id="1785382723.729409",
    )
    event = MessageEvent(
        text="[HERMES_EXACT_TERMINAL_V1] MINA_VISIBLE_TERMINAL_OK",
        source=source,
        channel_context=(
            "[Thread context — prior messages in this thread]\n"
            "[assistant] [HERMES_EXACT_TERMINAL_V1] STALE_QUOTED_VALUE\n"
            "[End of thread context]"
        ),
        reply_to_message_id="1785382723.729409",
        reply_to_text="P0 parent",
    )

    result = await runner._prepare_inbound_message_text(
        event=event,
        source=source,
        history=[],
    )

    assert _extract_exact_line_contract(result) == "MINA_VISIBLE_TERMINAL_OK"
    assert "STALE_QUOTED_VALUE" in result

