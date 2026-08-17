import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from agent.error_classifier import FailoverReason
from agent.thewon_model_mode_bridge import notify_rate_limit


def _agent(provider="openai-codex", base_url="https://chatgpt.com/backend-api/codex"):
    return SimpleNamespace(provider=provider, base_url=base_url, model="gpt-5.6-sol")


def test_bridge_is_inert_without_explicit_enablement(tmp_path):
    runner = Mock()
    assert notify_rate_limit(
        _agent(),
        FailoverReason.rate_limit,
        config={"thewon_model_mode": {"controller_enabled": False}},
        runner=runner,
    ) is False
    runner.assert_not_called()


def test_bridge_forwards_normalized_codex_signal(tmp_path):
    controller = tmp_path / "controller.py"
    controller.write_text("# fixture\n", encoding="utf-8")
    key = tmp_path / "bridge.key"
    key.write_bytes(b"b" * 32)
    os.chmod(key, 0o600)
    captured = {}

    def run(command, **kwargs):
        proof_path = command[command.index("--identity-proof") + 1]
        captured["proof"] = json.loads(Path(proof_path).read_text(encoding="utf-8"))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    runner = Mock(side_effect=run)
    config = {
        "thewon_model_mode": {
            "controller_enabled": True,
            "controller_path": str(controller),
            "identity_key_path": str(key),
        }
    }

    assert notify_rate_limit(
        _agent(),
        FailoverReason.rate_limit,
        config=config,
        runner=runner,
    ) is True

    command = runner.call_args.args[0]
    assert command[2:6] == ["signal", "--provider", "codex", "--available"]
    assert command[6] == "no"
    assert "--actor" not in command
    assert captured["proof"]["actor"] == "hermes-rate-limit-bridge"
    assert captured["proof"]["operation"] == "degradation"
    assert "gpt-5.6-sol" in command
    assert "hermes-classified:rate_limit" in command


def test_bridge_maps_local_ollama_endpoint_and_ignores_non_rate_limit(tmp_path):
    controller = tmp_path / "controller.py"
    controller.write_text("# fixture\n", encoding="utf-8")
    key = tmp_path / "bridge.key"
    key.write_bytes(b"b" * 32)
    os.chmod(key, 0o600)
    runner = Mock(return_value=SimpleNamespace(returncode=0, stdout="{}", stderr=""))
    config = {
        "thewon_model_mode": {
            "controller_enabled": True,
            "controller_path": str(controller),
            "identity_key_path": str(key),
        }
    }
    agent = _agent(provider="custom", base_url="http://localhost:11434/v1")

    assert notify_rate_limit(agent, FailoverReason.rate_limit, config=config, runner=runner) is True
    assert "ollama" in runner.call_args.args[0]
    runner.reset_mock()
    assert notify_rate_limit(agent, FailoverReason.timeout, config=config, runner=runner) is False
    runner.assert_not_called()
