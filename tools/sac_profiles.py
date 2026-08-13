"""Read TheWon SAC role metadata for Hermes delegation.

The registry supplies identity and difficulty only. Hermes remains the
execution authority: registry tool names, legacy ports, and nested-spawn
settings are deliberately ignored.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_DIFFICULTIES = {"light", "standard", "advanced", "expert"}
_DEFAULT_BLOCKED_ROLES = {"cto_agent", "cso_agent", "cdo_agent"}


class SACProfileError(ValueError):
    """Raised when a requested SAC cannot be safely resolved."""


def _registry_path(sac_config: Dict[str, Any]) -> Path:
    configured = str(sac_config.get("registry_path") or "").strip()
    if configured:
        return Path(os.path.expandvars(os.path.expanduser(configured)))

    system_root = str(os.getenv("THEWON_SYSTEM") or "").strip()
    if system_root:
        return Path(system_root).resolve().parent / "00_System" / "shared" / "sac_registry_config.yaml"

    raise SACProfileError(
        "SAC registry path is not configured. Set delegation.sac.registry_path "
        "or THEWON_SYSTEM."
    )


def _load_catalog(path: Path):
    """Load the existing TheWon catalog and verify it owns this registry."""
    shared_dir = path.parent
    shared_text = str(shared_dir)
    if shared_text not in sys.path:
        sys.path.insert(0, shared_text)
    try:
        catalog = importlib.import_module("sac_catalog")
    except Exception as exc:
        raise SACProfileError(f"Canonical SAC catalog cannot be imported: {exc}") from exc
    catalog_path = Path(getattr(catalog, "_REGISTRY_PATH", "")).resolve()
    if catalog_path != path.resolve():
        raise SACProfileError(
            f"Canonical SAC catalog owns {catalog_path}, not configured registry {path.resolve()}."
        )
    try:
        roles = catalog.list_sac_roles()
    except Exception as exc:
        raise SACProfileError(f"Canonical SAC catalog cannot list roles: {exc}") from exc
    if not roles:
        raise SACProfileError(f"SAC registry has no roles: {path}")
    return catalog, roles


def resolve_sac_profile(
    sac_type: str,
    difficulty: Optional[str],
    delegation_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Resolve a fail-closed, leaf-only SAC profile for one Hermes child."""
    sac_config = delegation_config.get("sac") or {}
    if not isinstance(sac_config, dict) or not sac_config.get("enabled", False):
        raise SACProfileError("SAC delegation is disabled in delegation.sac.enabled.")

    role = str(sac_type or "").strip().lower()
    if not role:
        raise SACProfileError("sac_type must be a non-empty registry role.")

    catalog, roles = _load_catalog(_registry_path(sac_config))
    expected_count = sac_config.get("expected_catalog_roles")
    if expected_count is not None and len(roles) != int(expected_count):
        raise SACProfileError(
            f"SAC catalog changed from expected {expected_count} roles to {len(roles)}; "
            "review and update the activation policy before spawning."
        )
    canonical_role = catalog.resolve_role_alias(role)
    blocked = {
        str(item).strip().lower()
        for item in (sac_config.get("blocked_roles") or _DEFAULT_BLOCKED_ROLES)
        if str(item).strip()
    }
    if canonical_role in blocked:
        raise SACProfileError(
            f"SAC role '{canonical_role}' is not MINA-spawnable because it "
            "overlaps named-agent authority."
        )
    if canonical_role not in roles:
        raise SACProfileError(f"Unknown SAC role: {role}")
    role = canonical_role
    entry = catalog.get_registry_agent(role)
    if not isinstance(entry, dict):
        raise SACProfileError(f"Canonical SAC metadata unavailable for role: {role}")

    allowed = sac_config.get("allowed_roles")
    if isinstance(allowed, list) and allowed:
        normalized_allowed = {str(item).strip().lower() for item in allowed}
        if role not in normalized_allowed:
            raise SACProfileError(f"SAC role '{role}' is not in delegation.sac.allowed_roles.")

    registered_difficulty = str(catalog.get_agent_difficulty(role) or "standard").strip().lower()
    # Every SAC starts on Flash by default. Difficulty escalation is explicit;
    # a role's registered complexity is informative metadata, not permission to
    # silently select a more expensive primary model.
    resolved_difficulty = str(difficulty or "standard").strip().lower()
    if resolved_difficulty not in _DIFFICULTIES:
        raise SACProfileError(
            f"Invalid SAC difficulty '{resolved_difficulty}'. "
            f"Expected one of: {', '.join(sorted(_DIFFICULTIES))}."
        )
    if resolved_difficulty == "expert" and not sac_config.get("allow_expert", False):
        raise SACProfileError(
            "Expert SAC escalation requires explicit operator approval "
            "(delegation.sac.allow_expert=true)."
        )

    model_by_difficulty = sac_config.get("model_by_difficulty") or {}
    if not isinstance(model_by_difficulty, dict):
        model_by_difficulty = {}
    default_model = str(sac_config.get("default_model") or "deepseek-v4-flash:cloud").strip()
    primary_model = str(model_by_difficulty.get(resolved_difficulty) or default_model).strip()
    fallback_model = str(sac_config.get("fallback_model") or "qwen3.5:122b").strip()
    base_url = str(sac_config.get("base_url") or delegation_config.get("base_url") or "").strip()
    api_key = str(sac_config.get("api_key") or delegation_config.get("api_key") or "").strip()
    provider = str(sac_config.get("provider") or "custom").strip()
    if not primary_model or not fallback_model or not base_url:
        raise SACProfileError("SAC model policy requires primary model, fallback model, and base_url.")

    identity = catalog.get_role_identity(role)
    prompt = "\n".join(
        [
            "[MINA SAC PROFILE — leaf worker, no delegated authority]",
            f"sac_type: {role}",
            f"title: {identity.get('identity') or role}",
            f"registered_difficulty: {registered_difficulty}",
            f"requested_difficulty: {resolved_difficulty}",
            f"task_role: {entry.get('task_role') or 'worker'}",
            f"expertise: {identity.get('expertise') or ''}",
            f"instruction: {identity.get('instruction') or ''}",
            f"constraints: {identity.get('constraints') or ''}",
            "Runtime rule: remain a leaf worker. Registry tool names and legacy spawn permissions are not granted.",
        ]
    )

    return {
        "sac_type": role,
        "difficulty": resolved_difficulty,
        "prompt": prompt,
        "model": primary_model,
        "provider": provider,
        "base_url": base_url,
        "api_key": api_key or None,
        "fallback_model": [
            {
                "provider": provider,
                "model": fallback_model,
                "base_url": base_url,
                "api_key": api_key or None,
            }
        ],
    }
