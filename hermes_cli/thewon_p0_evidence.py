"""Read-only verifier for a TheWon P0 candidate delivery receipt.

Candidate evidence supplies only immutable identity claims.  Durable inputs are
resolved exclusively by a verifier-owned, sealed configuration; no candidate
path can select a SQLite database or JSONL projection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote


CONFIG_SCHEMA = "thewon-p0-trusted-verifier-config-v1"
CANDIDATE_SCHEMA = "thewon-p0-candidate-evidence-v1"
TRUSTED_CONFIG_PATH = Path("/etc/hermes/thewon-p0-verifier-config.json")
REQUIRED_MUTATION_TARGETS = (
    "canonical_source",
    "runtime",
    "slack",
    "vault",
    "canvas",
    "container",
    "service",
    "secret",
    "restart",
)
PROHIBITED_CANDIDATE_STORAGE_KEYS = frozenset(
    {
        "receipt_db",
        "receipt_db_path",
        "durable_db_path",
        "durable_receipt_db",
        "sqlite_path",
        "agent_projection",
        "agent_projection_path",
        "central_projection",
        "central_projection_path",
    }
)
P0_CONTRACT_FIELDS = (
    "event_id",
    "run_id",
    "agent_id",
    "channel_id",
    "parent_ts",
    "response_ts",
    "payload_sha256",
)


class EvidenceVerificationError(ValueError):
    """Raised when a receipt cannot be independently verified."""


@dataclass(frozen=True)
class SealedArtifact:
    path: Path
    sha256: str


@dataclass(frozen=True)
class TrustedVerifierConfig:
    base_commit: str
    allowed_paths: tuple[str, ...]
    scope_sha256: str
    expected_contract: Mapping[str, str]
    receipt_db: SealedArtifact
    agent_projection: SealedArtifact
    central_projection: SealedArtifact


@dataclass(frozen=True)
class VerificationReport:
    event_id: str
    run_id: str
    receipt_state: str
    base_commit: str
    sealed_snapshot_verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "run_id": self.run_id,
            "receipt_state": self.receipt_state,
            "base_commit": self.base_commit,
            "sealed_snapshot_verified": self.sealed_snapshot_verified,
        }


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceVerificationError(f"{label} must be an object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceVerificationError(f"{label} must be a non-empty string")
    return value


def _require_sha256(value: Any, label: str) -> str:
    digest = _require_string(value, label)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise EvidenceVerificationError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _require_string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise EvidenceVerificationError(f"{label} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise EvidenceVerificationError(f"{label} must not contain duplicate paths")
    return tuple(value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"cannot read {label}: {exc}") from exc
    return _require_mapping(value, label)


def _parse_sealed_artifact(value: Any, label: str) -> SealedArtifact:
    mapping = _require_mapping(value, label)
    path_value = _require_string(mapping.get("path"), f"{label}.path")
    path = Path(path_value)
    if not path.is_absolute():
        raise EvidenceVerificationError(f"{label}.path must be absolute")
    return SealedArtifact(path=path, sha256=_require_sha256(mapping.get("sha256"), f"{label}.sha256"))


def _parse_expected_contract(value: Any) -> Mapping[str, str]:
    contract = _require_mapping(value, "trusted P0 contract")
    parsed: dict[str, str] = {}
    for field in P0_CONTRACT_FIELDS:
        require = _require_sha256 if field == "payload_sha256" else _require_string
        parsed[field] = require(contract.get(field), f"trusted P0 contract.{field}")
    return parsed


def load_trusted_verifier_config(path: str | Path) -> TrustedVerifierConfig:
    """Load the verifier-side trust anchor.

    This function intentionally does not accept candidate evidence.  The caller
    is responsible for obtaining this config from the verifier-controlled
    location or sealed snapshot process.
    """
    config = _load_json(Path(path), "trusted verifier config")
    if config.get("schema") != CONFIG_SCHEMA:
        raise EvidenceVerificationError("trusted verifier config schema is invalid")

    authority = _require_mapping(config.get("authority"), "trusted authority")
    base_commit = _require_string(authority.get("base_commit"), "trusted authority.base_commit")
    allowed_paths = _require_string_list(authority.get("allowed_paths"), "trusted authority.allowed_paths")
    scope_sha256 = _require_sha256(authority.get("scope_sha256"), "trusted authority.scope_sha256")
    actual_scope_sha256 = _sha256_bytes(_canonical_json(list(allowed_paths)).encode("utf-8"))
    if scope_sha256 != actual_scope_sha256:
        raise EvidenceVerificationError("trusted authority scope hash mismatch")

    snapshot = _require_mapping(config.get("sealed_snapshot"), "sealed snapshot")
    return TrustedVerifierConfig(
        base_commit=base_commit,
        allowed_paths=allowed_paths,
        scope_sha256=scope_sha256,
        expected_contract=_parse_expected_contract(config.get("expected_contract")),
        receipt_db=_parse_sealed_artifact(snapshot.get("receipt_db"), "sealed snapshot.receipt_db"),
        agent_projection=_parse_sealed_artifact(
            snapshot.get("agent_projection"), "sealed snapshot.agent_projection"
        ),
        central_projection=_parse_sealed_artifact(
            snapshot.get("central_projection"), "sealed snapshot.central_projection"
        ),
    )


def _verify_sealed_artifact(artifact: SealedArtifact, label: str) -> bytes:
    if artifact.path.is_symlink() or not artifact.path.is_file():
        raise EvidenceVerificationError(f"sealed snapshot artifact unavailable: {label}")
    try:
        content = artifact.path.read_bytes()
    except OSError as exc:
        raise EvidenceVerificationError(f"sealed snapshot artifact unavailable: {label}") from exc
    if _sha256_bytes(content) != artifact.sha256:
        raise EvidenceVerificationError(f"sealed snapshot hash mismatch: {label}")
    return content


def _assert_artifact_unchanged(artifact: SealedArtifact, label: str) -> None:
    _verify_sealed_artifact(artifact, label)


def _find_prohibited_storage_key(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in PROHIBITED_CANDIDATE_STORAGE_KEYS:
                return key
            found = _find_prohibited_storage_key(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_prohibited_storage_key(nested)
            if found:
                return found
    return None


def _verify_candidate_controls(candidate: Mapping[str, Any], config: TrustedVerifierConfig) -> None:
    if candidate.get("schema") != CANDIDATE_SCHEMA:
        raise EvidenceVerificationError("candidate evidence schema is invalid")

    prohibited_key = _find_prohibited_storage_key(candidate)
    if prohibited_key:
        raise EvidenceVerificationError(f"candidate-supplied storage path is prohibited: {prohibited_key}")

    lease = _require_mapping(candidate.get("lease"), "candidate lease")
    if lease.get("mode") != "candidate_only":
        raise EvidenceVerificationError("candidate lease must remain candidate_only")
    if lease.get("base_commit") != config.base_commit:
        raise EvidenceVerificationError("candidate lease base_commit does not match trusted authority")
    candidate_paths = _require_string_list(lease.get("allowed_paths"), "candidate lease.allowed_paths")
    if candidate_paths != config.allowed_paths:
        raise EvidenceVerificationError("candidate lease paths do not match trusted authority")
    if lease.get("scope_sha256") != config.scope_sha256:
        raise EvidenceVerificationError("candidate lease scope hash does not match trusted authority")

    boundary = _require_mapping(candidate.get("mutation_boundary"), "mutation boundary")
    for target in REQUIRED_MUTATION_TARGETS:
        if boundary.get(target) != "unchanged":
            raise EvidenceVerificationError(f"mutation boundary requires {target}=unchanged")

    workflow = _require_mapping(candidate.get("workflow"), "workflow")
    if workflow.get("stage") != "candidate":
        raise EvidenceVerificationError("workflow stage must remain candidate")
    if workflow.get("gatekeeper") != "not_requested":
        raise EvidenceVerificationError("Gatekeeper must remain not_requested")
    if workflow.get("live_mutation") != "not_requested":
        raise EvidenceVerificationError("live mutation must remain not_requested")

    mina_terminal = _require_mapping(candidate.get("mina_terminal"), "MINA terminal")
    if mina_terminal.get("status") != "not_requested":
        raise EvidenceVerificationError("MINA terminal status must remain not_requested")
    if mina_terminal.get("finalization") != "not_requested":
        raise EvidenceVerificationError("MINA finalization must remain not_requested")


def _verify_expected_contract(candidate: Mapping[str, Any], config: TrustedVerifierConfig) -> None:
    for field in P0_CONTRACT_FIELDS:
        require = _require_sha256 if field == "payload_sha256" else _require_string
        candidate_value = require(candidate.get(field), f"candidate {field}")
        if candidate_value != config.expected_contract[field]:
            raise EvidenceVerificationError(f"candidate {field} does not match trusted P0 contract")


def _read_durable_row(config: TrustedVerifierConfig, event_id: str) -> Mapping[str, Any]:
    _verify_sealed_artifact(config.receipt_db, "receipt_db")
    uri = f"file:{quote(str(config.receipt_db.path))}?mode=ro&immutable=1"
    try:
        with sqlite3.connect(uri, uri=True) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT event_id, agent_id, payload_sha256, row_json, state, delivered_at
                FROM durable_receipts
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        raise EvidenceVerificationError(f"trusted receipt DB cannot be read: {exc}") from exc
    finally:
        _assert_artifact_unchanged(config.receipt_db, "receipt_db")

    if row is None:
        raise EvidenceVerificationError(f"trusted receipt DB has no event_id {event_id!r}")
    if row["state"] != "delivered" or not row["delivered_at"]:
        raise EvidenceVerificationError("durable receipt state must be delivered")
    try:
        row_json = json.loads(row["row_json"], object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError("durable row_json is not valid JSON") from exc
    row_json = _require_mapping(row_json, "durable row_json")
    if _canonical_json(row_json) != row["row_json"]:
        raise EvidenceVerificationError("durable row_json is not canonical")
    return {
        "event_id": row["event_id"],
        "agent_id": row["agent_id"],
        "payload_sha256": row["payload_sha256"],
        "row_json": row_json,
        "state": row["state"],
    }


def _assert_row_contract(durable: Mapping[str, Any], candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    row_json = _require_mapping(durable["row_json"], "durable row_json")
    field_bindings = {
        "event_id": "id",
        "run_id": "run_id",
        "agent_id": "agent_id",
        "channel_id": "channel_id",
        "parent_ts": "parent_ts",
        "response_ts": "response_ts",
        "payload_sha256": "durable_payload_sha256",
    }
    for candidate_key, row_key in field_bindings.items():
        require = _require_sha256 if candidate_key == "payload_sha256" else _require_string
        candidate_value = require(candidate.get(candidate_key), f"candidate {candidate_key}")
        row_value = require(row_json.get(row_key), f"durable row_json.{row_key}")
        if row_value != candidate_value:
            raise EvidenceVerificationError(f"durable row_json {row_key} does not bind candidate {candidate_key}")

    if durable["event_id"] != candidate["event_id"]:
        raise EvidenceVerificationError("durable event_id does not match candidate event_id")
    if durable["agent_id"] != candidate["agent_id"]:
        raise EvidenceVerificationError("durable agent_id does not match candidate agent_id")
    if _require_sha256(durable["payload_sha256"], "durable payload_sha256") != candidate["payload_sha256"]:
        raise EvidenceVerificationError("durable payload_sha256 does not match candidate payload_sha256")
    return row_json


def _load_jsonl_projection(artifact: SealedArtifact, label: str) -> list[Mapping[str, Any]]:
    content = _verify_sealed_artifact(artifact, label)
    records: list[Mapping[str, Any]] = []
    try:
        for line_number, line in enumerate(content.decode("utf-8").splitlines(), start=1):
            if not line:
                continue
            parsed = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            records.append(_require_mapping(parsed, f"{label} line {line_number}"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"{label} is not valid JSONL") from exc
    finally:
        _assert_artifact_unchanged(artifact, label)
    return records


def _assert_projection_binding(
    artifact: SealedArtifact,
    label: str,
    event_id: str,
    expected_row: Mapping[str, Any],
) -> None:
    records = _load_jsonl_projection(artifact, label)
    matching_events = [record for record in records if record.get("id") == event_id]
    if len(matching_events) != 1:
        raise EvidenceVerificationError(f"{label} must contain exactly one matching event")
    if matching_events[0] != expected_row:
        raise EvidenceVerificationError(f"{label} does not exactly match durable row_json")

    response_ts = expected_row["response_ts"]
    for record in records:
        if record.get("id") != event_id and record.get("response_ts") == response_ts:
            raise EvidenceVerificationError(f"{label} reuses response_ts from another event")


def verify_candidate_evidence(
    candidate_evidence: Mapping[str, Any],
    trusted_config: TrustedVerifierConfig,
) -> VerificationReport:
    """Verify one candidate receipt without reading candidate-selected storage."""
    candidate = _require_mapping(candidate_evidence, "candidate evidence")
    _verify_candidate_controls(candidate, trusted_config)
    _verify_expected_contract(candidate, trusted_config)
    event_id = _require_string(candidate.get("event_id"), "candidate event_id")
    durable = _read_durable_row(trusted_config, event_id)
    row_json = _assert_row_contract(durable, candidate)
    _assert_projection_binding(trusted_config.agent_projection, "agent projection", event_id, row_json)
    _assert_projection_binding(trusted_config.central_projection, "central projection", event_id, row_json)
    return VerificationReport(
        event_id=event_id,
        run_id=_require_string(candidate.get("run_id"), "candidate run_id"),
        receipt_state="delivered",
        base_commit=trusted_config.base_commit,
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify a TheWon P0 candidate receipt")
    parser.add_argument("candidate_evidence", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        candidate = _load_json(args.candidate_evidence, "candidate evidence")
        config = load_trusted_verifier_config(TRUSTED_CONFIG_PATH)
        report = verify_candidate_evidence(candidate, config)
    except EvidenceVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(_canonical_json(report.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
