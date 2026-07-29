"""Idle client eviction for the LSP service."""
from __future__ import annotations

import asyncio
import math
import time
from typing import Any, Tuple, cast

from agent.lsp.manager import DEFAULT_IDLE_TIMEOUT, LSPService


class FakeClient:
    def __init__(self, key: Tuple[str, str]) -> None:
        self.server_id = key[0]
        self.workspace_root = key[1]
        self.shutdown_calls = 0

    @property
    def is_running(self) -> bool:
        return self.shutdown_calls == 0

    @property
    def state(self) -> str:
        return "running"

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


def _service(*, idle_timeout: float = 0.01) -> LSPService:
    return LSPService(
        enabled=True,
        wait_mode="document",
        wait_timeout=1.0,
        install_strategy="manual",
        idle_timeout=idle_timeout,
    )


def _put_client(svc: LSPService, client: FakeClient, *, last_used: float) -> None:
    key = (client.server_id, client.workspace_root)
    with svc._state_lock:
        svc._clients[key] = client
        svc._last_used[key] = last_used


def test_idle_reaper_reaps_stale_clients_automatically():
    svc = _service(idle_timeout=0.01)
    key = ("pyright", "/tmp/workspace-a")
    client = FakeClient(key)
    try:
        _put_client(svc, client, last_used=time.monotonic() - 60.0)

        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            with svc._state_lock:
                removed = key not in svc._clients
            if removed and client.shutdown_calls == 1:
                break
            time.sleep(0.01)

        with svc._state_lock:
            assert key not in svc._clients
            assert key not in svc._last_used
            assert key not in svc._active_clients
            assert key not in svc._spawning
        assert client.shutdown_calls == 1
    finally:
        svc.shutdown()


def test_idle_reaper_preserves_active_client_until_released():
    svc = _service(idle_timeout=0.01)
    key = ("pyright", "/tmp/workspace-b")
    client = FakeClient(key)
    try:
        _put_client(svc, client, last_used=time.monotonic() - 60.0)

        async def scenario() -> None:
            acquired = await svc._acquire_existing_client(key)
            assert acquired is client
            await asyncio.sleep(0.12)
            with svc._state_lock:
                assert svc._clients.get(key) is client
                assert svc._active_clients[key] == 1
            assert client.shutdown_calls == 0

            svc._release_client(cast(Any, client))
            with svc._state_lock:
                svc._last_used[key] = time.monotonic() - 60.0
            await svc._reap_idle_clients()

        svc._loop.run(scenario(), timeout=2.0)

        with svc._state_lock:
            assert key not in svc._clients
            assert key not in svc._last_used
            assert key not in svc._active_clients
        assert client.shutdown_calls == 1
    finally:
        svc.shutdown()


def test_idle_reaper_cleans_completed_spawn_and_client_maps():
    svc = _service(idle_timeout=0.01)
    key = ("yaml", "/tmp/workspace-c")
    client = FakeClient(key)
    try:
        _put_client(svc, client, last_used=time.monotonic() - 60.0)

        async def scenario() -> None:
            spawn_future = asyncio.get_running_loop().create_future()
            spawn_future.set_result(client)
            with svc._state_lock:
                svc._spawning[key] = spawn_future
                svc._active_clients[key] = 0
            await svc._reap_idle_clients()

        svc._loop.run(scenario(), timeout=2.0)

        with svc._state_lock:
            assert key not in svc._clients
            assert key not in svc._last_used
            assert key not in svc._spawning
            assert key not in svc._active_clients
        assert client.shutdown_calls == 1
    finally:
        svc.shutdown()


def test_shutdown_is_idempotent_and_clears_reaper_clients_and_maps():
    svc = _service(idle_timeout=3600.0)
    key = ("pyright", "/tmp/workspace-idempotent")
    client = FakeClient(key)
    _put_client(svc, client, last_used=time.monotonic() - 60.0)
    with svc._state_lock:
        svc._broken.add(key)
        svc._active_clients[key] = 1
        loop = svc._loop._loop
        assert loop is not None
        spawn_future = loop.create_future()
        spawn_future.set_result(client)
        svc._spawning[key] = spawn_future

    svc.shutdown()
    svc.shutdown()

    with svc._state_lock:
        assert svc._clients == {}
        assert svc._last_used == {}
        assert svc._active_clients == {}
        assert svc._spawning == {}
        assert svc._broken == set()
    assert svc._reaper_task is None
    assert client.shutdown_calls == 1


def test_reaper_does_not_reap_active_client_during_concurrent_acquire_release_churn():
    svc = _service(idle_timeout=3600.0)
    key = ("pyright", "/tmp/workspace-churn")
    client = FakeClient(key)
    try:
        _put_client(svc, client, last_used=time.monotonic() - 60.0)

        async def scenario() -> None:
            guard = await svc._acquire_existing_client(key)
            assert guard is client

            async def churn_acquire_release() -> None:
                for _ in range(100):
                    acquired = await svc._acquire_existing_client(key)
                    assert acquired is client
                    await asyncio.sleep(0)
                    svc._release_client(cast(Any, client))
                    await asyncio.sleep(0)

            churn = asyncio.create_task(churn_acquire_release())
            for _ in range(50):
                await svc._reap_idle_clients(now=time.monotonic() + 7200.0)
                with svc._state_lock:
                    assert svc._clients.get(key) is client
                    assert svc._active_clients.get(key, 0) >= 1
                assert client.shutdown_calls == 0
                await asyncio.sleep(0)
            await churn
            svc._release_client(cast(Any, client))
            with svc._state_lock:
                svc._last_used[key] = time.monotonic() - 60.0
            await svc._reap_idle_clients(now=time.monotonic() + 7200.0)

        svc._loop.run(scenario(), timeout=5.0)

        with svc._state_lock:
            assert key not in svc._clients
            assert key not in svc._last_used
            assert key not in svc._active_clients
            assert key not in svc._spawning
        assert client.shutdown_calls == 1
    finally:
        svc.shutdown()


def test_concurrent_reap_of_multiple_stale_clients_shuts_each_down_once_and_clears_maps():
    svc = _service(idle_timeout=3600.0)
    keys = [("pyright", f"/tmp/workspace-multi-{idx}") for idx in range(12)]
    clients = [FakeClient(key) for key in keys]
    try:
        for client in clients:
            _put_client(svc, client, last_used=time.monotonic() - 60.0)

        async def scenario() -> None:
            now = time.monotonic() + 7200.0
            await asyncio.gather(
                svc._reap_idle_clients(now=now),
                svc._reap_idle_clients(now=now),
            )

        svc._loop.run(scenario(), timeout=5.0)

        with svc._state_lock:
            assert svc._clients == {}
            assert svc._last_used == {}
            assert svc._active_clients == {}
            assert svc._spawning == {}
        assert [client.shutdown_calls for client in clients] == [1] * len(clients)
    finally:
        svc.shutdown()


def test_idle_timeout_zero_reaps_idle_but_preserves_active_client():
    svc = _service(idle_timeout=0.0)
    active_key = ("pyright", "/tmp/workspace-zero-active")
    idle_key = ("pyright", "/tmp/workspace-zero-idle")
    active_client = FakeClient(active_key)
    idle_client = FakeClient(idle_key)
    try:
        now = time.monotonic()
        _put_client(svc, active_client, last_used=now)
        _put_client(svc, idle_client, last_used=now)

        async def scenario() -> None:
            acquired = await svc._acquire_existing_client(active_key)
            assert acquired is active_client
            await svc._reap_idle_clients(now=now + 0.001)
            with svc._state_lock:
                assert svc._clients.get(active_key) is active_client
                assert idle_key not in svc._clients
            assert active_client.shutdown_calls == 0
            assert idle_client.shutdown_calls == 1
            svc._release_client(cast(Any, active_client))
            with svc._state_lock:
                svc._last_used[active_key] = now
            await svc._reap_idle_clients(now=now + 0.002)

        svc._loop.run(scenario(), timeout=2.0)
        with svc._state_lock:
            assert active_key not in svc._clients
            assert active_key not in svc._last_used
            assert active_key not in svc._active_clients
        assert active_client.shutdown_calls == 1
    finally:
        svc.shutdown()


def test_idle_timeout_non_finite_and_invalid_values_fall_back_to_default():
    invalid_values = [math.nan, math.inf, -math.inf, -1.0, "not-a-number", None]
    services = []
    try:
        for value in invalid_values:
            svc = _service(idle_timeout=value)  # type: ignore[arg-type]
            services.append(svc)
            assert svc._idle_timeout == float(DEFAULT_IDLE_TIMEOUT)
            assert svc._idle_reaper_interval() == 60.0
    finally:
        for svc in services:
            svc.shutdown()


def test_create_from_config_accepts_zero_and_defaults_invalid_idle_timeout(monkeypatch):
    from hermes_cli import config as hermes_config

    monkeypatch.setattr(
        hermes_config,
        "load_config",
        lambda: {"lsp": {"enabled": True, "idle_timeout": 0, "install_strategy": "manual"}},
    )
    zero_svc = LSPService.create_from_config()
    try:
        assert zero_svc is not None
        assert zero_svc._idle_timeout == 0.0
    finally:
        if zero_svc is not None:
            zero_svc.shutdown()

    monkeypatch.setattr(
        hermes_config,
        "load_config",
        lambda: {"lsp": {"enabled": True, "idle_timeout": "nan", "install_strategy": "manual"}},
    )
    invalid_svc = LSPService.create_from_config()
    try:
        assert invalid_svc is not None
        assert invalid_svc._idle_timeout == float(DEFAULT_IDLE_TIMEOUT)
    finally:
        if invalid_svc is not None:
            invalid_svc.shutdown()
