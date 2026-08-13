import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from tools.delegate_tool import DELEGATE_TASK_SCHEMA, delegate_task
from tools.sac_profiles import SACProfileError, resolve_sac_profile


def _registry(tmp_path: Path) -> Path:
    path = tmp_path / "sac_registry.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "agents": {
                    "report_writer": {
                        "task_role": "producer",
                        "difficulty": "standard",
                        "identity": {
                            "title": "Report Writer",
                            "expertise": ["reports", "citations"],
                            "instruction": "Write clearly.",
                            "constraints": "Do not invent evidence.",
                        },
                        "tools": ["spawn_sac", "read_file"],
                    },
                    "cto_agent": {
                        "task_role": "orchestrator",
                        "difficulty": "expert",
                        "identity": {"title": "CTO"},
                    },
                }
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path


def _catalog_module(path: Path):
    agents = yaml.safe_load(path.read_text(encoding="utf-8"))["agents"]
    module = MagicMock()
    module._REGISTRY_PATH = path
    module.list_sac_roles.return_value = sorted(agents)
    aliases = {
        "cto": "cto_agent",
        "chief_technology_officer": "cto_agent",
        "cso": "cso_agent",
        "chief_strategy_officer": "cso_agent",
        "cdo": "cdo_agent",
        "chief_development_officer": "cdo_agent",
    }
    module.resolve_role_alias.side_effect = lambda role: aliases.get(role, role)
    module.get_registry_agent.side_effect = agents.get
    module.get_agent_difficulty.side_effect = lambda role: agents[role]["difficulty"]
    module.get_role_identity.side_effect = lambda role: {
        "identity": agents[role]["identity"].get("title", role),
        "expertise": ", ".join(agents[role]["identity"].get("expertise", [])),
        "instruction": agents[role]["identity"].get("instruction", ""),
        "constraints": agents[role]["identity"].get("constraints", ""),
    }
    return module


def _config(path: Path):
    return {
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "max_iterations": 50,
        "sac": {
            "enabled": True,
            "registry_path": str(path),
            "provider": "custom",
            "base_url": "http://localhost:11434/v1",
            "api_key": "ollama",
            "default_model": "deepseek-v4-flash:cloud",
            "fallback_model": "qwen3.5:122b",
            "expected_catalog_roles": 2,
            "allow_expert": False,
            "model_by_difficulty": {
                "standard": "deepseek-v4-flash:cloud",
                "advanced": "deepseek-v4-pro:cloud",
                "expert": "deepseek-v4-pro:cloud",
            },
            "blocked_roles": ["cto_agent", "cso_agent", "cdo_agent"],
        },
    }


def test_schema_exposes_sac_fields_for_single_and_batch():
    props = DELEGATE_TASK_SCHEMA["parameters"]["properties"]
    assert "sac_type" in props
    assert "difficulty" in props
    task_props = props["tasks"]["items"]["properties"]
    assert "sac_type" in task_props
    assert "difficulty" in task_props


def test_profile_uses_flash_and_qwen_fallback(tmp_path):
    path = _registry(tmp_path)
    with patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}):
        profile = resolve_sac_profile("report_writer", None, _config(path))
    assert profile["model"] == "deepseek-v4-flash:cloud"
    assert profile["fallback_model"] == [
        {
            "provider": "custom",
            "model": "qwen3.5:122b",
            "base_url": "http://localhost:11434/v1",
            "api_key": "ollama",
        }
    ]
    assert "spawn_sac" not in profile["prompt"]
    assert "leaf worker" in profile["prompt"]


def test_difficulty_escalates_primary_model(tmp_path):
    path = _registry(tmp_path)
    with patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}):
        profile = resolve_sac_profile("report_writer", "advanced", _config(path))
    assert profile["model"] == "deepseek-v4-pro:cloud"
    assert profile["fallback_model"][0]["model"] == "qwen3.5:122b"


def test_unknown_and_authority_collision_fail_closed(tmp_path):
    path = _registry(tmp_path)
    config = _config(path)
    with patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}):
        for role in ("missing", "cto_agent"):
            try:
                resolve_sac_profile(role, None, config)
            except SACProfileError:
                pass
            else:
                raise AssertionError(f"{role} should be rejected")


def test_named_agent_aliases_are_blocked_after_canonicalization(tmp_path):
    path = _registry(tmp_path)
    config = _config(path)
    aliases = (
        "cto",
        "chief_technology_officer",
        "cso",
        "chief_strategy_officer",
        "cdo",
        "chief_development_officer",
    )
    with patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}):
        for alias in aliases:
            try:
                resolve_sac_profile(alias, None, config)
            except SACProfileError as exc:
                assert "named-agent authority" in str(exc)
            else:
                raise AssertionError(f"{alias} should be rejected")


def test_expert_requires_operator_gate(tmp_path):
    path = _registry(tmp_path)
    with patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}):
        try:
            resolve_sac_profile("report_writer", "expert", _config(path))
        except SACProfileError as exc:
            assert "operator approval" in str(exc)
        else:
            raise AssertionError("expert escalation should be gated")


def test_delegate_injects_profile_and_forces_leaf(tmp_path):
    config = _config(_registry(tmp_path))
    parent = MagicMock()
    parent._delegate_depth = 0
    parent._fallback_chain = [{"provider": "openrouter", "model": "parent-fallback"}]
    parent._active_children = []
    parent.session_id = "parent"
    child = MagicMock()
    child._delegate_role = "leaf"
    child.session_id = "child"
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return child

    completed = {
        "task_index": 0,
        "status": "completed",
        "summary": "ok",
        "api_calls": 1,
        "duration_seconds": 0.1,
    }
    creds = {
        "model": "generic",
        "provider": "custom",
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "api_mode": "chat_completions",
        "request_overrides": None,
        "max_output_tokens": None,
    }
    with (
        patch.dict(sys.modules, {"sac_catalog": _catalog_module(Path(config["sac"]["registry_path"]))}),
        patch("tools.delegate_tool._load_config", return_value=config),
        patch("tools.delegate_tool._resolve_delegation_credentials", return_value=creds),
        patch("tools.delegate_tool._build_child_preserving_parent_tools", side_effect=_capture),
        patch("tools.delegate_tool._run_single_child", return_value=completed),
        patch("tools.delegate_tool._finalize_child_results"),
        patch("tools.delegate_tool.create_live_transcripts", create=True),
    ):
        result = delegate_task(
            goal="Write the report",
            context="Use the supplied evidence.",
            role="orchestrator",
            sac_type="report_writer",
            parent_agent=parent,
        )

    assert '"status": "completed"' in result
    assert captured["role"] == "leaf"
    assert captured["model"] == "deepseek-v4-flash:cloud"
    assert captured["override_fallback_model"][0]["model"] == "qwen3.5:122b"
    assert "MINA SAC PROFILE" in captured["context"]


def test_mixed_batch_invalid_sac_fails_before_any_spawn(tmp_path):
    path = _registry(tmp_path)
    config = _config(path)
    parent = MagicMock()
    parent._delegate_depth = 0
    creds = {
        "model": "generic",
        "provider": "custom",
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "api_mode": "chat_completions",
        "request_overrides": None,
        "max_output_tokens": None,
    }
    with (
        patch.dict(sys.modules, {"sac_catalog": _catalog_module(path)}),
        patch("tools.delegate_tool._load_config", return_value=config),
        patch("tools.delegate_tool._resolve_delegation_credentials", return_value=creds),
        patch("tools.delegate_tool._build_child_preserving_parent_tools") as build_child,
    ):
        result = delegate_task(
            tasks=[
                {"goal": "Write the evidence report", "sac_type": "report_writer"},
                {"goal": "Review all source claims", "sac_type": "missing_role"},
            ],
            parent_agent=parent,
        )

    assert "Unknown SAC role" in result
    build_child.assert_not_called()
