from __future__ import annotations

import pytest

from datetime import datetime, timezone

from hermes_cli.thewon_p0_candidate_scope import CandidateScopeError, LeaseClaim, validate_lease_claim, verify_candidate_scope


PATHS = ("docs/thewon/p0/evidence-ledger.json", "hermes_cli/thewon_p0_evidence.py")


def _candidate(**overrides):
    candidate = {
        "declared_paths": list(PATHS),
        "ledger": {"mutation_boundary": list(PATHS), "acquired_resources": list(PATHS), "released_resources": list(PATHS)},
    }
    candidate.update(overrides)
    return candidate


def test_scope_requires_exact_equal_sets_including_ledger():
    assert verify_candidate_scope(actual_paths=PATHS, candidate=_candidate()) == set(PATHS)


@pytest.mark.parametrize("candidate", [
    _candidate(ledger={"mutation_boundary": list(PATHS), "acquired_resources": [PATHS[1]], "released_resources": list(PATHS)}),
    _candidate(declared_paths=[PATHS[0]]),
    _candidate(ledger={"mutation_boundary": ["docs/thewon/p0/*"], "acquired_resources": list(PATHS), "released_resources": list(PATHS)}),
])
def test_scope_rejects_omitted_ledger_path_or_glob(candidate):
    with pytest.raises(CandidateScopeError):
        verify_candidate_scope(actual_paths=PATHS, candidate=candidate)


def test_lease_rejects_base_sha_drift_and_concurrent_resource_writer():
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    active = LeaseClaim("held", "a" * 40, (PATHS[0],), "2026-08-12T00:00:00Z")
    requested = LeaseClaim("new", "a" * 40, (PATHS[0],), "2026-08-12T00:00:00Z")
    with pytest.raises(CandidateScopeError, match="already held"):
        validate_lease_claim(expected_base_sha="a" * 40, requested=requested, active=[active], now=now)
    with pytest.raises(CandidateScopeError, match="base SHA drift"):
        validate_lease_claim(expected_base_sha="b" * 40, requested=requested, active=[], now=now)


def test_expired_claim_does_not_block_a_new_writer():
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    active = LeaseClaim("expired", "a" * 40, (PATHS[0],), "2026-08-10T00:00:00Z")
    requested = LeaseClaim("new", "a" * 40, (PATHS[0],), "2026-08-12T00:00:00Z")
    validate_lease_claim(expected_base_sha="a" * 40, requested=requested, active=[active], now=now)
