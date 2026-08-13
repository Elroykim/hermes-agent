from argparse import Namespace
from pathlib import Path
import sys

import pytest

from hermes_cli import main
from hermes_cli import oneshot


def _args(**overrides):
    values = {
        "continue_last": None,
        "in_dir": None,
        "no_restore_cwd": False,
        "resume": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_prepare_oneshot_context_enters_explicit_directory(monkeypatch, tmp_path):
    start = tmp_path / "start"
    target = tmp_path / "target"
    start.mkdir()
    target.mkdir()
    monkeypatch.chdir(start)

    args = _args(in_dir=str(target))
    workspace = main._prepare_oneshot_context(args)

    assert Path.cwd() == target
    assert args.no_restore_cwd is True
    assert workspace == str(target)


def test_prepare_oneshot_context_rejects_missing_directory(tmp_path, capsys):
    args = _args(in_dir=str(tmp_path / "missing"))

    with pytest.raises(SystemExit) as exc:
        main._prepare_oneshot_context(args)

    assert exc.value.code == 1
    assert "--in directory not found" in capsys.readouterr().err


@pytest.mark.parametrize(
    "overrides",
    [
        {"resume": "20260813_094901_80854a"},
        {"continue_last": True},
    ],
)
def test_prepare_oneshot_context_rejects_silent_resume(overrides, capsys):
    args = _args(**overrides)

    with pytest.raises(SystemExit) as exc:
        main._prepare_oneshot_context(args)

    assert exc.value.code == 2
    assert "cannot be combined with --resume or --continue" in capsys.readouterr().err


def test_fast_oneshot_enters_directory_before_startup(monkeypatch, tmp_path):
    start = tmp_path / "start"
    target = tmp_path / "target"
    start.mkdir()
    target.mkdir()
    monkeypatch.chdir(start)
    monkeypatch.setattr(sys, "argv", ["hermes", "--in", str(target), "-z", "hello"])
    monkeypatch.setattr(main, "_wants_tui_early", lambda _argv: False)

    observed = []

    def fake_startup(_args):
        observed.append(("startup", Path.cwd()))

    def fake_oneshot(_prompt, **kwargs):
        observed.append(("oneshot", Path.cwd(), kwargs.get("workspace")))
        raise SystemExit(0)

    monkeypatch.setattr(main, "_prepare_agent_startup", fake_startup)
    monkeypatch.setattr(main, "_run_and_exit_oneshot", fake_oneshot)

    with pytest.raises(SystemExit) as exc:
        main._try_fast_chat_launch()

    assert exc.value.code == 0
    assert observed == [
        ("startup", target),
        ("oneshot", target, str(target)),
    ]


def test_fast_oneshot_rejects_resume_before_startup(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["hermes", "--resume", "20260813_094901_80854a", "-z", "hello"],
    )
    monkeypatch.setattr(main, "_wants_tui_early", lambda _argv: False)
    startup_called = False

    def fake_startup(_args):
        nonlocal startup_called
        startup_called = True

    monkeypatch.setattr(main, "_prepare_agent_startup", fake_startup)

    with pytest.raises(SystemExit) as exc:
        main._try_fast_chat_launch()

    assert exc.value.code == 2
    assert startup_called is False


def test_bind_oneshot_workspace_pins_tool_task_cwd(tmp_path):
    from tools import terminal_tool

    agent = Namespace(session_id="oneshot-workspace-test")
    try:
        task_id = oneshot._bind_oneshot_workspace(agent, str(tmp_path))

        assert task_id == agent.session_id
        assert terminal_tool.resolve_task_overrides(task_id)["cwd"] == str(tmp_path)
        assert terminal_tool.get_session_cwd(task_id) == str(tmp_path)
    finally:
        terminal_tool.clear_task_env_overrides(agent.session_id)


def test_bind_oneshot_workspace_requires_session_id(tmp_path):
    with pytest.raises(RuntimeError, match="requires a bound session id"):
        oneshot._bind_oneshot_workspace(Namespace(session_id=""), str(tmp_path))


def test_pin_oneshot_workspace_context_is_scoped(tmp_path):
    from agent.runtime_cwd import resolve_agent_cwd

    original = resolve_agent_cwd()
    handle = oneshot._pin_oneshot_workspace_context(str(tmp_path))
    try:
        assert resolve_agent_cwd() == tmp_path
    finally:
        oneshot._reset_oneshot_workspace_context(handle)

    assert resolve_agent_cwd() == original
