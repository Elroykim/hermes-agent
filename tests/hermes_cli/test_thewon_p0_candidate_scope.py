from __future__ import annotations

from datetime import datetime, timezone

import pytest

from hermes_cli.thewon_p0_candidate_scope import CandidateScopeError, LeaseClaim, validate_lease_claim, verify_candidate_scope


PATHS = ("docs/thewon/p0/evidence-ledger.json", "hermes_cli/thewon_p0_evidence.py")


def _candidate(resources=PATHS):
    return {"declared_paths": list(PATHS), "ledger": {"mutation_boundary": list(resources), "acquired_resources": list(resources), "released_resources": list(resources)}}


def test_scope_requires_actual_manifest_and_all_lease_sets_to_match():
    assert verify_candidate_scope(actual_paths=PATHS, candidate=_candidate()) == set(PATHS)
    with pytest.raises(CandidateScopeError):
        verify_candidate_scope(actual_paths=PATHS, candidate=_candidate(PATHS[1:]))


def test_lease_rejects_base_drift_and_concurrent_writer():
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    requested = LeaseClaim("r7", "a" * 40, PATHS, "2026-08-12T00:00:00Z")
    with pytest.raises(CandidateScopeError):
        validate_lease_claim(expected_base_sha="b" * 40, requested=requested, active=(), now=now)
    with pytest.raises(CandidateScopeError):
        validate_lease_claim(expected_base_sha="a" * 40, requested=requested, active=(LeaseClaim("r6", "a" * 40, (PATHS[0],), "2026-08-12T00:00:00Z"),), now=now)
