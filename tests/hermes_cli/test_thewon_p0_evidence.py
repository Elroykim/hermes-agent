from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from hermes_cli.thewon_p0_evidence import (
    EvidenceVerificationError,
    load_trusted_verifier_config,
    verify_candidate_evidence,
)


BASE_COMMIT = "af37881b93a393cfe0ee24666709af0fcbda6109"
ALLOWED_PATHS = [
    "docs/thewon/p0/r9-evidence-plane-scope-20260811.json",
    "hermes_cli/thewon_p0_evidence.py",
    "tests/hermes_cli/test_thewon_p0_evidence.py",
]


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(_canonical_json(value) + "\n", encoding="utf-8")


def _scope_sha256(paths: list[str]) -> str:
    return hashlib.sha256(_canonical_json(paths).encode("ascii")).hexdigest()


def _row(
    *,
    event_id: str = "evt-r9",
    run_id: str = "run-r9",
    parent_ts: str = "1710000000.000100",
    response_ts: str = "1710000001.000200",
) -> dict[str, str]:
    payload_sha256 = hashlib.sha256(b"r9-payload").hexdigest()
    return {
        "id": event_id,
        "run_id": run_id,
        "agent_id": "MINA",
        "channel_id": "C-R9",
        "parent_ts": parent_ts,
        "response_ts": response_ts,
        "durable_payload_sha256": payload_sha256,
    }


def _write_receipt_db(path: Path, row: dict[str, str]) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE durable_receipts (
                event_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                row_json TEXT NOT NULL,
                state TEXT NOT NULL,
                delivered_at TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO durable_receipts
            (event_id, agent_id, payload_sha256, row_json, state, delivered_at)
            VALUES (?, ?, ?, ?, 'delivered', ?)
            """,
            (
                row["id"],
                row["agent_id"],
                row["durable_payload_sha256"],
                _canonical_json(row),
                "2026-08-11T00:00:00+00:00",
            ),
        )


def _candidate_evidence(row: dict[str, str]) -> dict[str, object]:
    return {
        "schema": "thewon-p0-candidate-evidence-v1",
        "event_id": row["id"],
        "run_id": row["run_id"],
        "agent_id": row["agent_id"],
        "channel_id": row["channel_id"],
        "parent_ts": row["parent_ts"],
        "response_ts": row["response_ts"],
        "payload_sha256": row["durable_payload_sha256"],
        "lease": {
            "mode": "candidate_only",
            "base_commit": BASE_COMMIT,
            "allowed_paths": ALLOWED_PATHS,
            "scope_sha256": _scope_sha256(ALLOWED_PATHS),
        },
        "mutation_boundary": {
            "canonical_source": "unchanged",
            "runtime": "unchanged",
            "slack": "unchanged",
            "vault": "unchanged",
            "canvas": "unchanged",
            "container": "unchanged",
            "service": "unchanged",
            "secret": "unchanged",
            "restart": "unchanged",
        },
        "workflow": {
            "stage": "candidate",
            "gatekeeper": "not_requested",
            "live_mutation": "not_requested",
        },
        "mina_terminal": {
            "status": "not_requested",
            "finalization": "not_requested",
        },
    }


def _expected_contract(row: dict[str, str]) -> dict[str, str]:
    return {
        "event_id": row["id"],
        "run_id": row["run_id"],
        "agent_id": row["agent_id"],
        "channel_id": row["channel_id"],
        "parent_ts": row["parent_ts"],
        "response_ts": row["response_ts"],
        "payload_sha256": row["durable_payload_sha256"],
    }


def _trusted_config(
    tmp_path: Path,
    row: dict[str, str],
    *,
    expected_row: dict[str, str] | None = None,
) -> Path:
    receipt_db = tmp_path / "sealed-receipts.sqlite3"
    agent_projection = tmp_path / "sealed-agent.jsonl"
    central_projection = tmp_path / "sealed-central.jsonl"
    _write_receipt_db(receipt_db, row)
    agent_projection.write_text(_canonical_json(row) + "\n", encoding="utf-8")
    central_projection.write_text(_canonical_json(row) + "\n", encoding="utf-8")

    config_path = tmp_path / "trusted-verifier-config.json"
    _write_json(
        config_path,
        {
            "schema": "thewon-p0-trusted-verifier-config-v1",
            "authority": {
                "base_commit": BASE_COMMIT,
                "allowed_paths": ALLOWED_PATHS,
                "scope_sha256": _scope_sha256(ALLOWED_PATHS),
            },
            "expected_contract": _expected_contract(expected_row or row),
            "sealed_snapshot": {
                "receipt_db": {"path": str(receipt_db), "sha256": _sha256(receipt_db)},
                "agent_projection": {"path": str(agent_projection), "sha256": _sha256(agent_projection)},
                "central_projection": {"path": str(central_projection), "sha256": _sha256(central_projection)},
            },
        },
    )
    return config_path


def _verify(tmp_path: Path, candidate_evidence: dict[str, object]):
    row = _row()
    config_path = _trusted_config(tmp_path, row)
    return verify_candidate_evidence(
        candidate_evidence,
        load_trusted_verifier_config(config_path),
    )


def test_accepts_only_a_sealed_durable_row_and_matching_projections(tmp_path):
    row = _row()

    report = _verify(tmp_path, _candidate_evidence(row))

    assert report.event_id == "evt-r9"
    assert report.run_id == "run-r9"
    assert report.receipt_state == "delivered"


def test_rejects_a_candidate_supplied_sqlite_path_even_when_trusted_receipt_is_valid(tmp_path):
    evidence = _candidate_evidence(_row())
    evidence["receipt_db_path"] = str(tmp_path / "attacker-controlled.sqlite3")

    with pytest.raises(EvidenceVerificationError, match="candidate-supplied storage path"):
        _verify(tmp_path, evidence)


def test_rejects_old_event_run_reuse_from_the_sealed_receipt(tmp_path):
    old_row = _row(event_id="evt-old", run_id="run-old")
    config_path = _trusted_config(tmp_path, old_row, expected_row=_row())

    with pytest.raises(EvidenceVerificationError, match="trusted P0 contract"):
        verify_candidate_evidence(
            _candidate_evidence(old_row),
            load_trusted_verifier_config(config_path),
        )


@pytest.mark.parametrize(
    ("field", "old_value"),
    [
        ("parent_ts", "1710000000.999999"),
        ("response_ts", "1710000001.999999"),
    ],
)
def test_rejects_wrong_terminal_identifiers_in_canonical_row_json(tmp_path, field, old_value):
    current_row = _row()
    trusted_row = dict(current_row)
    trusted_row[field] = old_value
    config_path = _trusted_config(tmp_path, trusted_row, expected_row=current_row)

    with pytest.raises(EvidenceVerificationError, match=f"durable row_json {field}"):
        verify_candidate_evidence(
            _candidate_evidence(current_row),
            load_trusted_verifier_config(config_path),
        )


def test_rejects_old_projection_or_foreign_response_reuse(tmp_path):
    row = _row()
    config_path = _trusted_config(tmp_path, row)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    central_projection = Path(config["sealed_snapshot"]["central_projection"]["path"])
    stale_projection = dict(row)
    stale_projection["response_ts"] = "1710000001.999999"
    central_projection.write_text(_canonical_json(stale_projection) + "\n", encoding="utf-8")
    config["sealed_snapshot"]["central_projection"]["sha256"] = _sha256(central_projection)
    _write_json(config_path, config)

    with pytest.raises(EvidenceVerificationError, match="central projection"):
        verify_candidate_evidence(
            _candidate_evidence(row),
            load_trusted_verifier_config(config_path),
        )


def test_fails_closed_when_the_sealed_snapshot_hash_does_not_match(tmp_path):
    row = _row()
    config_path = _trusted_config(tmp_path, row)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["sealed_snapshot"]["receipt_db"]["sha256"] = "0" * 64
    _write_json(config_path, config)

    with pytest.raises(EvidenceVerificationError, match="sealed snapshot hash mismatch"):
        verify_candidate_evidence(
            _candidate_evidence(row),
            load_trusted_verifier_config(config_path),
        )


def test_fails_closed_when_the_sealed_snapshot_proof_is_unavailable(tmp_path):
    config_path = _trusted_config(tmp_path, _row())
    config = json.loads(config_path.read_text(encoding="utf-8"))
    del config["sealed_snapshot"]["receipt_db"]
    _write_json(config_path, config)

    with pytest.raises(EvidenceVerificationError, match="sealed snapshot.receipt_db"):
        load_trusted_verifier_config(config_path)


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("lease", "mode", "shared", "candidate_only"),
        ("mutation_boundary", "runtime", "changed", "runtime=unchanged"),
        ("workflow", "gatekeeper", "requested", "Gatekeeper"),
        ("mina_terminal", "finalization", "requested", "MINA finalization"),
    ],
)
def test_preserves_candidate_only_lease_boundary_workflow_and_mina_controls(
    tmp_path,
    section,
    field,
    value,
    message,
):
    evidence = _candidate_evidence(_row())
    evidence[section][field] = value

    with pytest.raises(EvidenceVerificationError, match=message):
        _verify(tmp_path, evidence)
