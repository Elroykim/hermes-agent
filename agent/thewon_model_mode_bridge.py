"""Optional bridge from Hermes rate-limit failover to TheWon A/B/C/D modes.

The bridge is inert unless ``thewon_model_mode.controller_enabled`` is true
and the configured controller path exists.  It forwards only normalized
provider/model/reason metadata; raw error bodies and credentials never leave
the Hermes process through this path.
"""

from __future__ import annotations

import logging
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from agent.error_classifier import FailoverReason


logger = logging.getLogger(__name__)
RATE_LIMIT_REASONS = {
    FailoverReason.rate_limit,
    FailoverReason.upstream_rate_limit,
}
IDENTITY_ACTOR = "hermes-rate-limit-bridge"


def _write_identity_proof(key_path: Path, request: Mapping[str, Any]) -> Path:
    if not key_path.is_file():
        raise ValueError("identity key is missing")
    stat = key_path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("identity key permissions must be owner-only")
    key = key_path.read_bytes()
    if len(key) < 32:
        raise ValueError("identity key must contain at least 32 bytes")
    issued_at = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(16)
    payload = json.dumps(
        {
            "actor": IDENTITY_ACTOR,
            "issued_at": issued_at,
            "nonce": nonce,
            "operation": "degradation",
            "request": request,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    proof = {
        "actor": IDENTITY_ACTOR,
        "operation": "degradation",
        "issued_at": issued_at,
        "nonce": nonce,
        "signature": hmac.new(key, payload, hashlib.sha256).hexdigest(),
    }
    descriptor, name = tempfile.mkstemp(prefix="mina-mode-proof-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(proof, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o600)
        return Path(name)
    except Exception:
        if os.path.exists(name):
            os.unlink(name)
        raise


def _mode_config(config: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    if config is None:
        try:
            from hermes_cli.config import load_config

            config = load_config()
        except Exception as exc:
            logger.debug("TheWon model-mode config unavailable: %s", exc)
            return {}
    value = config.get("thewon_model_mode") if isinstance(config, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _provider_kind(agent: Any) -> str | None:
    provider = str(getattr(agent, "provider", "") or "").strip().lower()
    base_url = str(getattr(agent, "base_url", "") or "").strip().lower()
    if provider == "openai-codex" or "chatgpt.com/backend-api/codex" in base_url:
        return "codex"
    if provider == "ollama" or "localhost:11434" in base_url or "127.0.0.1:11434" in base_url:
        return "ollama"
    return None


def notify_rate_limit(
    agent: Any,
    reason: FailoverReason | None,
    *,
    config: Mapping[str, Any] | None = None,
    runner=subprocess.run,
) -> bool:
    """Notify the configured controller once Hermes commits to rate-limit failover.

    Returns ``True`` only when the controller command completes successfully.
    Failure is deliberately non-fatal: Hermes still follows its in-process
    fallback chain for the current request.
    """

    if reason not in RATE_LIMIT_REASONS:
        return False
    mode_config = _mode_config(config)
    if mode_config.get("controller_enabled") is not True:
        return False
    controller = Path(str(mode_config.get("controller_path") or "")).expanduser()
    if not controller.is_file():
        logger.warning("TheWon model-mode controller missing: %s", controller)
        return False
    provider = _provider_kind(agent)
    if provider is None:
        return False
    model = str(getattr(agent, "model", "") or "").strip()
    reason_value = reason.value
    key_path = Path(str(mode_config.get("identity_key_path") or "")).expanduser()
    request = {
        "provider": provider,
        "available": False,
        "reason": reason_value,
        "evidence": f"hermes-classified:{reason_value}",
        "model": model,
        "retry_after_seconds": None,
        "recovery_probe": None,
    }
    try:
        proof_path = _write_identity_proof(key_path, request)
    except Exception as exc:
        logger.warning("TheWon model-mode identity proof unavailable: %s", exc)
        return False
    command = [
        sys.executable,
        str(controller),
        "signal",
        "--provider",
        provider,
        "--available",
        "no",
        "--identity-proof",
        str(proof_path),
        "--reason",
        reason_value,
        "--evidence",
        f"hermes-classified:{reason_value}",
        "--model",
        model,
    ]
    try:
        completed = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception as exc:
        logger.warning("TheWon model-mode notification failed: %s", exc)
        return False
    finally:
        proof_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        stderr = str(completed.stderr or "").strip().splitlines()
        logger.warning(
            "TheWon model-mode controller rejected signal (rc=%s): %s",
            completed.returncode,
            stderr[-1] if stderr else "no diagnostic",
        )
        return False
    logger.info(
        "TheWon model-mode rate-limit signal accepted: provider=%s model=%s reason=%s",
        provider,
        model,
        reason_value,
    )
    return True
