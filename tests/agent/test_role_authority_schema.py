"""Contract tests for dormant, pure BAC authority artifacts A/B/C/D."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.role_authority_schema import (
    AuthoritySchemaError,
    GateDecision,
    ParsedAuthorityArtifact,
    TrustRoot,
    evaluate_nv_fd_read,
    parse_activation_pointer,
    parse_journal_record,
    parse_task_contract,
    parse_task_envelope,
)


A_SCHEMA = "thewon-bac-role-activation-pointer/v1"
B_SCHEMA = "thewon-bac-role-activation-journal-record/v1"
C_SCHEMA = "thewon-bac-authenticated-task-envelope/v1"
D_SCHEMA = "thewon-bac-parsed-task-contract/v1"
SIGNATURE_DOMAIN = "thewon-bac-ed25519-signature/v1"
ROUTE = "hermes:nv:fd-bound-read:v1"
PATH = "/Users/elroy/Documents/Codex/2026-08-02/llm-wiki/source.md"
WALL_NOW = "2026-08-04T00:00:10Z"


def _c14n(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _raw(value) -> bytes:
    return _c14n(value) + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _domain_bytes(domain: str, payload: bytes) -> bytes:
    encoded = domain.encode("utf-8")
    return hashlib.sha256(len(encoded).to_bytes(4, "big") + encoded + payload).digest()


def _domain(domain: str, payload: bytes) -> str:
    return _domain_bytes(domain, payload).hex()


def _refresh_contract(contract):
    contract["contract_sha256"] = _domain(
        D_SCHEMA,
        _c14n({key: value for key, value in contract.items() if key != "contract_sha256"}),
    )
    return contract


def _signature_preimage(schema: str, payload: dict) -> bytes:
    return _domain_bytes(
        SIGNATURE_DOMAIN,
        schema.encode("utf-8") + b"\x00" + _c14n(payload),
    )


def _authority(label: str, epoch: int):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    root = TrustRoot(
        trust_root_id=f"thewon:test-{label}-root/v1",
        key_id=f"thewon:test-{label}-key/v1",
        epoch=epoch,
        public_key_base64=base64.b64encode(public_key).decode("ascii"),
        fingerprint_sha256=_sha(public_key),
    )
    return private_key, root


def _root_pin(root):
    return {
        "trust_root_id": root.trust_root_id,
        "key_id": root.key_id,
        "epoch": root.epoch,
        "fingerprint_sha256": root.fingerprint_sha256,
    }


def _signed(private_key, trust_root, payload):
    return {
        "payload": copy.deepcopy(payload),
        "signature": {
            "algorithm": "ed25519",
            "canonicalization": "thewon-json-c14n/v1",
            "trust_root_id": trust_root.trust_root_id,
            "key_id": trust_root.key_id,
            "value_base64": base64.b64encode(
                private_key.sign(_signature_preimage(payload["schema_version"], payload))
            ).decode("ascii"),
        },
    }


def _case(
    *,
    generation: int = 1,
    previous_pointer_sha256=None,
    sequence: int = 1,
    previous_record_sha256=None,
):
    authorities = {
        "activation": _authority("activation", 3),
        "journal": _authority("journal", 4),
        "task-envelope": _authority("task-envelope", 5),
    }
    keys = {name: value[0] for name, value in authorities.items()}
    roots = {name: value[1] for name, value in authorities.items()}
    shas = {
        name: _sha(name.encode())
        for name in (
            "identity",
            "projection",
            "bundle-file",
            "bundle-internal",
            "scope-file",
            "scope-internal",
            "projection-row",
            "bundle-row",
            "runtime",
            "target",
            "approval",
            "review",
            "rollback",
            "executor",
            "rt-policy",
            "source-bytes",
        )
    }
    source_request = {"path": PATH, "offset": 1, "limit": 20}
    goal = "Read the approved LLM Wiki source without mutation."
    contract = {
        "schema_version": D_SCHEMA,
        "parser_version": "thewon:nv-task-parser/v1",
        "logical_task_id": "logical:nv-read/0001",
        "user_goal": goal,
        "user_goal_sha256": _domain("thewon-bac-user-goal/v1", goal.encode()),
        "source_bindings": [{"path": PATH, "sha256": shas["source-bytes"]}],
        "source_request": source_request,
        "source_request_sha256": _domain(
            "thewon-bac-source-request/v1", _c14n(source_request)
        ),
        "expected_source_sha256": shas["source-bytes"],
        "source_digest_domain": "EXACT_FD_BYTES",
        "allowed_read_set": [PATH],
        "allowed_write_set": [],
        "mutation_class": "read_only",
        "producer_agent_code": "NV",
        "independent_reviewer_agent_code": "GV-REVIEWER",
        "activation_authority": "Elroy",
        "capability_id": "read_scoped_sources",
        "operation_class": "read_scoped",
        "resource": "domain:llm-wiki",
        "tool_identifier": "read_file",
        "role_scope": "knowledge_source_read_only_canary",
        "validation_commands": ["verify exact source digest"],
        "negative_tests": ["deny writes"],
        "rollback": "none_read_only",
        "stop_conditions": ["authority mismatch"],
        "contract_expires_at_wall": "2026-08-04T00:08:00Z",
        "contract_sha256": "",
    }
    contract["contract_sha256"] = _domain(
        D_SCHEMA,
        _c14n({key: value for key, value in contract.items() if key != "contract_sha256"}),
    )
    contract_raw = _raw(contract)

    journal_payload = {
        "schema_version": B_SCHEMA,
        "journal_id": "journal:nv-read/0001",
        "sequence": sequence,
        "previous_record_sha256": previous_record_sha256,
        "activation_id": "activation:nv-read/0001",
        "state": "COMMITTED",
        "generation": generation,
        "role_bundle_file_sha256": shas["bundle-file"],
        "role_bundle_internal_sha256": shas["bundle-internal"],
        "scope_evidence_file_sha256": shas["scope-file"],
        "scope_evidence_internal_sha256": shas["scope-internal"],
        "activated_role_codes": ["NV"],
        "target_set_sha256": shas["target"],
        "approval_receipt_file_sha256": shas["approval"],
        "independent_review_file_sha256": shas["review"],
        "rollback_manifest_file_sha256": shas["rollback"],
        "executor_file_sha256": shas["executor"],
        "written_at_wall": "2026-08-03T23:59:59Z",
    }
    journal = _signed(keys["journal"], roots["journal"], journal_payload)
    journal_raw = _raw(journal)

    pointer_payload = {
        "schema_version": A_SCHEMA,
        "state": "active",
        "activation_class": "canary",
        "scope_mode": "explicit_allowlist",
        "generation": generation,
        "previous_pointer_sha256": previous_pointer_sha256,
        "activation_id": journal_payload["activation_id"],
        "activation_journal_head_file_sha256": _sha(journal_raw),
        "allowed_rt_issuer_policy_sha256": shas["rt-policy"],
        "identity_authority_file_sha256": shas["identity"],
        "role_projection_file_sha256": shas["projection"],
        "role_bundle_file_sha256": shas["bundle-file"],
        "role_bundle_internal_sha256": shas["bundle-internal"],
        "scope_evidence_file_sha256": shas["scope-file"],
        "scope_evidence_internal_sha256": shas["scope-internal"],
        "activated_roles": [{
            "agent_code": "NV",
            "role_projection_row_sha256": shas["projection-row"],
            "role_bundle_row_sha256": shas["bundle-row"],
            "runtime_attestation_sha256": shas["runtime"],
            "route_ids": [ROUTE],
        }],
        "activated_at_wall": "2026-08-04T00:00:00Z",
        "expires_at_wall": "2026-08-04T00:10:00Z",
    }
    pointer = _signed(keys["activation"], roots["activation"], pointer_payload)
    pointer_raw = _raw(pointer)

    backend = {
        "kind": "local",
        "task_id": "task:nv-read/0001",
        "instance_token": "instance:nv-read/0001",
    }
    envelope_payload = {
        "schema_version": C_SCHEMA,
        "envelope_id": "envelope:nv-read/0001",
        "parent_request_id": "request:parent/0001",
        "route_id": ROUTE,
        "authority_required": True,
        "issuer_agent_code": "MINA",
        "agent_code": "NV",
        "session_id": "session:nv-read/0001",
        "logical_task_id": contract["logical_task_id"],
        "turn_id": "turn:nv-read/0001",
        "backend_identity_sha256": _domain(
            "thewon-bac-backend-identity/v1", _c14n(backend)
        ),
        "active_pointer_file_sha256": _sha(pointer_raw),
        "activation_journal_head_file_sha256": _sha(journal_raw),
        "activation_generation": generation,
        "task_contract_file_sha256": _sha(contract_raw),
        "tool_identifier": "read_file",
        "normalized_args": source_request,
        "normalized_args_sha256": _domain(
            "thewon-bac-normalized-args/v1", _c14n(source_request)
        ),
        "nonce": "nonce:nv-read/0001",
        "issued_at_wall": "2026-08-04T00:00:05Z",
        "not_before_wall": "2026-08-04T00:00:05Z",
        "expires_at_wall": "2026-08-04T00:05:00Z",
    }
    envelope = _signed(
        keys["task-envelope"], roots["task-envelope"], envelope_payload
    )
    checkpoint = {
        "last_pointer_generation": 0,
        "last_pointer_file_sha256": None,
        "last_journal_sequence": 0,
        "last_journal_head_file_sha256": None,
        "ra_root": _root_pin(roots["activation"]),
        "rj_root": _root_pin(roots["journal"]),
        "rt_root": _root_pin(roots["task-envelope"]),
        "operator_pinned_genesis_pointer_sha256": _sha(pointer_raw),
        "operator_minimum_generation": 1,
    }
    return {
        "keys": keys,
        "roots": roots,
        "pointer": pointer,
        "journal": journal,
        "contract": contract,
        "envelope": envelope,
        "backend": backend,
        "checkpoint": checkpoint,
        "rt_policy_sha256": shas["rt-policy"],
    }


def _resign(case, artifact, authority):
    return _signed(
        case["keys"][authority], case["roots"][authority], artifact["payload"]
    )


def _parse(case, *, pointer=None, journal=None, contract=None, envelope=None, roots=None):
    roots = roots or case["roots"]
    return (
        parse_activation_pointer(_raw(pointer or case["pointer"]), roots["activation"]),
        parse_journal_record(_raw(journal or case["journal"]), roots["journal"]),
        parse_task_contract(_raw(contract or case["contract"])),
        parse_task_envelope(
            _raw(envelope or case["envelope"]), roots["task-envelope"]
        ),
    )


def _evaluate(case, *, parsed=None, checkpoint=None, policy=None, backend=None,
              session="session:nv-read/0001", turn="turn:nv-read/0001",
              wall_now=WALL_NOW):
    return evaluate_nv_fd_read(
        *(parsed or _parse(case)),
        checkpoint if checkpoint is not None else case["checkpoint"],
        policy or case["rt_policy_sha256"],
        case["backend"] if backend is None else backend,
        session,
        turn,
        wall_now,
    )


def _assert_structural(decision):
    assert decision == GateDecision(
        decision="STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE",
        reasons=("BACKEND_ATTESTATION_REQUIRED", "NONCE_ATOMIC_CONSUME_REQUIRED"),
        consume_key_candidate=decision.consume_key_candidate,
        execute_authority=False,
        rb_complete=False,
        route_metadata_wiring_complete=False,
    )
    assert len(decision.consume_key_candidate) == 64


def test_design_shape_is_one_way_and_contains_no_serialized_monotonic_or_rb_claim():
    case = _case()
    a = case["pointer"]["payload"]
    b = case["journal"]["payload"]
    c = case["envelope"]["payload"]
    assert set(case["pointer"]) == {"payload", "signature"}
    assert set(case["journal"]) == {"payload", "signature"}
    assert set(case["envelope"]) == {"payload", "signature"}
    assert "pointer_file_sha256" not in b
    assert "previous_pointer_sha256" not in b
    assert a["activation_journal_head_file_sha256"] == _sha(_raw(case["journal"]))
    assert c["active_pointer_file_sha256"] == _sha(_raw(case["pointer"]))
    assert c["activation_journal_head_file_sha256"] == _sha(_raw(case["journal"]))
    assert c["task_contract_file_sha256"] == _sha(_raw(case["contract"]))
    assert not any("monotonic" in key for key in c)
    assert not any("verified" in key or "attestation" in key for key in case["backend"])


def test_positive_is_structural_only_and_never_execution_authority():
    case = _case()
    decision = _evaluate(case)
    _assert_structural(decision)


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "decision": "ALLOW",
            "reasons": ("SCOPED_NV_FD_READ_READY",),
            "execute_authority": True,
            "rb_complete": True,
            "route_metadata_wiring_complete": True,
        },
        {"decision": "READY", "reasons": ("SCOPED_NV_FD_READ_READY",)},
        {
            "decision": "STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE",
            "reasons": (
                "BACKEND_ATTESTATION_REQUIRED",
                "NONCE_ATOMIC_CONSUME_REQUIRED",
            ),
            "consume_key_candidate": "f" * 64,
            "execute_authority": True,
        },
        {
            "decision": "STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE",
            "reasons": ("SCOPED_NV_FD_READ_READY",),
            "consume_key_candidate": "f" * 64,
        },
        {
            "decision": "STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE",
            "reasons": (
                "BACKEND_ATTESTATION_REQUIRED",
                "NONCE_ATOMIC_CONSUME_REQUIRED",
            ),
        },
        {
            "decision": "DENY",
            "reasons": ("STRICT_SCHEMA_INVALID",),
            "consume_key_candidate": "f" * 64,
        },
        {"decision": "DENY", "reasons": ("CALLER_INVENTED_REASON",)},
        {
            "decision": "DENY",
            "reasons": ("STRICT_SCHEMA_INVALID",),
            "rb_complete": True,
        },
    ],
)
def test_gate_decision_constructor_cannot_forge_authority(kwargs):
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        GateDecision(**kwargs)


def test_three_independent_verified_roots_and_epochs_are_preserved():
    case = _case()
    pointer, journal, _, envelope = _parse(case)
    signed = (pointer, journal, envelope)
    assert len({item.verified_root_fingerprint_sha256 for item in signed}) == 3
    assert len({item.verified_trust_root_id for item in signed}) == 3
    assert len({item.verified_key_id for item in signed}) == 3
    assert tuple(item.verified_root_epoch for item in signed) == (3, 4, 5)


def test_ra_rj_rt_epochs_must_also_be_pairwise_distinct():
    case = _case()
    original = case["roots"]["task-envelope"]
    epoch_alias = TrustRoot(
        trust_root_id=original.trust_root_id,
        key_id=original.key_id,
        epoch=4,
        public_key_base64=original.public_key_base64,
        fingerprint_sha256=original.fingerprint_sha256,
    )
    roots = {**case["roots"], "task-envelope": epoch_alias}
    parsed = _parse(case, roots=roots)
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint["rt_root"] = _root_pin(epoch_alias)
    assert _evaluate(case, parsed=parsed, checkpoint=checkpoint).reasons == (
        "TRUST_ROOT_OR_SIGNATURE_INVALID",
    )


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("activation", "journal"),
        ("activation", "task-envelope"),
        ("journal", "task-envelope"),
    ],
)
def test_every_ra_rj_rt_fingerprint_alias_pair_is_denied(source, target):
    case = _case()
    source_root = case["roots"][source]
    original_target = case["roots"][target]
    alias = TrustRoot(
        trust_root_id=original_target.trust_root_id,
        key_id=original_target.key_id,
        epoch=original_target.epoch,
        public_key_base64=source_root.public_key_base64,
        fingerprint_sha256=source_root.fingerprint_sha256,
    )
    artifact_name = {
        "activation": "pointer",
        "journal": "journal",
        "task-envelope": "envelope",
    }[target]
    forged = _signed(
        case["keys"][source], alias, case[artifact_name]["payload"]
    )
    roots = {**case["roots"], target: alias}
    parsed = _parse(case, roots=roots, **{artifact_name: forged})
    assert _evaluate(case, parsed=parsed).reasons == (
        "TRUST_ROOT_OR_SIGNATURE_INVALID",
    )


@pytest.mark.parametrize("authority", ["activation", "journal", "task-envelope"])
@pytest.mark.parametrize("mode", ["rekey", "epoch_rollback"])
def test_checkpoint_pins_each_root_identity_key_epoch_and_fingerprint(authority, mode):
    case = _case()
    old = case["roots"][authority]
    if mode == "rekey":
        key, replacement = _authority(f"{authority}-replacement", old.epoch + 1)
    else:
        key = case["keys"][authority]
        replacement = TrustRoot(
            old.trust_root_id,
            old.key_id,
            old.epoch - 1,
            old.public_key_base64,
            old.fingerprint_sha256,
        )
    artifact_name = {
        "activation": "pointer",
        "journal": "journal",
        "task-envelope": "envelope",
    }[authority]
    artifact = _signed(key, replacement, case[artifact_name]["payload"])
    roots = {**case["roots"], authority: replacement}
    parsed = _parse(case, roots=roots, **{artifact_name: artifact})
    assert _evaluate(case, parsed=parsed).reasons == (
        "TRUST_ROOT_OR_SIGNATURE_INVALID",
    )


def test_unauthorized_rt_issuer_policy_is_denied():
    case = _case()
    assert _evaluate(case, policy="f" * 64).reasons == (
        "TRUST_ROOT_OR_SIGNATURE_INVALID",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "bom",
        "duplicate",
        "float",
        "nonfinite",
        "bool_int",
        "key_order",
        "escape",
        "no_lf",
        "extra_lf",
    ],
)
def test_canonical_json_vectors_fail_closed(mutation):
    case = _case()
    value = copy.deepcopy(case["pointer"])
    if mutation == "bom":
        raw = b"\xef\xbb\xbf" + _raw(value)
    elif mutation == "duplicate":
        raw = _raw(value).replace(b'{"payload":', b'{"payload":{},"payload":', 1)
    elif mutation == "float":
        value["payload"]["generation"] = 1.0
        raw = _raw(value)
    elif mutation == "nonfinite":
        raw = _raw(value).replace(b'"generation":1', b'"generation":NaN')
    elif mutation == "bool_int":
        value["payload"]["generation"] = True
        value = _resign(case, value, "activation")
        raw = _raw(value)
    elif mutation == "key_order":
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    elif mutation == "escape":
        raw = _raw(value).replace(b'"active"', b'"\u0061ctive"')
    elif mutation == "no_lf":
        raw = _c14n(value)
    else:
        raw = _raw(value) + b"\n"
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parse_activation_pointer(raw, case["roots"]["activation"])


@pytest.mark.parametrize("payload", [[], None, "not-an-object", True])
@pytest.mark.parametrize(
    ("parser", "authority"),
    [
        (parse_activation_pointer, "activation"),
        (parse_journal_record, "journal"),
        (parse_task_envelope, "task-envelope"),
    ],
)
def test_a_b_c_malformed_payload_types_raise_schema_error(
    parser, authority, payload
):
    case = _case()
    raw = _raw({"payload": payload, "signature": {}})
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parser(raw, case["roots"][authority])


def test_raw_artifact_size_is_bounded_before_json_parse():
    case = _case()
    raw = b" " * ((1024 * 1024) + 1)
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parse_activation_pointer(raw, case["roots"]["activation"])


def test_oversized_integer_digit_count_converges_to_schema_error():
    case = _case()
    raw = _raw(case["pointer"]).replace(
        b'"generation":1', b'"generation":' + (b"9" * 5000)
    )
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parse_activation_pointer(raw, case["roots"]["activation"])


def test_deeply_nested_json_converges_to_schema_error():
    case = _case()
    raw = (
        b'{"payload":'
        + (b"[" * 2000)
        + (b"]" * 2000)
        + b',"signature":{}}\n'
    )
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parse_activation_pointer(raw, case["roots"]["activation"])


@pytest.mark.parametrize(
    ("artifact", "authority", "field"),
    [
        ("pointer", "activation", "allow"),
        ("journal", "journal", "nonce_consumed"),
        ("envelope", "task-envelope", "backend_attestation_verified"),
        ("envelope", "task-envelope", "ready_to_execute"),
    ],
)
def test_signed_allow_ready_rb_and_nonce_claims_are_unknown_fields(
    artifact, authority, field
):
    case = _case()
    value = copy.deepcopy(case[artifact])
    value["payload"][field] = True
    value = _resign(case, value, authority)
    parser = {
        "pointer": parse_activation_pointer,
        "journal": parse_journal_record,
        "envelope": parse_task_envelope,
    }[artifact]
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parser(_raw(value), case["roots"][authority])


@pytest.mark.parametrize(
    ("artifact", "authority", "field", "mutation"),
    [
        ("journal", "journal", "sequence", "bool"),
        ("journal", "journal", "sequence", "overflow"),
        ("envelope", "task-envelope", "activation_generation", "bool"),
        ("envelope", "task-envelope", "activation_generation", "overflow"),
        ("contract", None, "offset", "bool"),
        ("contract", None, "limit", "overflow"),
    ],
)
def test_b_c_d_bool_as_int_and_u64_overflow_are_denied(
    artifact, authority, field, mutation
):
    case = _case()
    value = copy.deepcopy(case[artifact])
    replacement = True if mutation == "bool" else 1 << 63
    if artifact == "contract":
        value["source_request"][field] = replacement
        raw = _raw(value)
        parser_args = ()
        parser = parse_task_contract
    else:
        value["payload"][field] = replacement
        value = _resign(case, value, authority)
        raw = _raw(value)
        parser_args = (case["roots"][authority],)
        parser = parse_journal_record if artifact == "journal" else parse_task_envelope
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parser(raw, *parser_args)


@pytest.mark.parametrize("artifact", ["journal", "envelope", "contract"])
def test_b_c_d_missing_fields_are_denied(artifact):
    case = _case()
    value = copy.deepcopy(case[artifact])
    if artifact == "contract":
        value.pop("parser_version")
        with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
            parse_task_contract(_raw(value))
        return
    authority = "journal" if artifact == "journal" else "task-envelope"
    value["payload"].pop("schema_version")
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parser = parse_journal_record if artifact == "journal" else parse_task_envelope
        parser(_raw(value), case["roots"][authority])


@pytest.mark.parametrize("artifact", ["journal", "envelope", "contract"])
def test_b_c_d_nested_duplicate_keys_are_denied(artifact):
    case = _case()
    raw = _raw(case[artifact])
    if artifact == "journal":
        raw = raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1')
        parser = parse_journal_record
        args = (case["roots"]["journal"],)
    elif artifact == "envelope":
        raw = raw.replace(b'"limit":20', b'"limit":20,"limit":20')
        parser = parse_task_envelope
        args = (case["roots"]["task-envelope"],)
    else:
        raw = raw.replace(b'"limit":20', b'"limit":20,"limit":20')
        parser = parse_task_contract
        args = ()
    with pytest.raises(AuthoritySchemaError, match="STRICT_SCHEMA_INVALID"):
        parser(raw, *args)


def test_signature_preimage_has_independent_domain_oracle_and_verifies():
    case = _case()
    payload = case["pointer"]["payload"]
    domain = SIGNATURE_DOMAIN.encode()
    material = payload["schema_version"].encode() + b"\x00" + _c14n(payload)
    oracle = hashlib.sha256(len(domain).to_bytes(4, "big") + domain + material).digest()
    assert oracle == _signature_preimage(A_SCHEMA, payload)
    parse_activation_pointer(_raw(case["pointer"]), case["roots"]["activation"])


@pytest.mark.parametrize("mutation", ["signature", "root", "key", "fingerprint"])
def test_signature_and_out_of_band_root_mismatch_is_denied(mutation):
    case = _case()
    value = copy.deepcopy(case["pointer"])
    root = case["roots"]["activation"]
    if mutation == "signature":
        value["signature"]["value_base64"] = base64.b64encode(b"x" * 64).decode()
    elif mutation == "root":
        value["signature"]["trust_root_id"] = "thewon:wrong-root/v1"
    elif mutation == "key":
        value["signature"]["key_id"] = "thewon:wrong-key/v1"
    else:
        with pytest.raises(AuthoritySchemaError, match="TRUST_ROOT_OR_SIGNATURE_INVALID"):
            TrustRoot(
                root.trust_root_id,
                root.key_id,
                root.epoch,
                root.public_key_base64,
                "f" * 64,
            )
        return
    with pytest.raises(AuthoritySchemaError, match="TRUST_ROOT_OR_SIGNATURE_INVALID"):
        parse_activation_pointer(_raw(value), root)


def test_legacy_pointer_is_explicitly_nonauthoritative():
    case = _case()
    value = copy.deepcopy(case["pointer"])
    value["payload"]["schema_version"] = "thewon-bac-role-activation-pointer/legacy"
    with pytest.raises(AuthoritySchemaError, match="LEGACY_POINTER_NONAUTHORITATIVE"):
        parse_activation_pointer(_raw(value), case["roots"]["activation"])


@pytest.mark.parametrize(
    ("artifact", "field", "value", "reason"),
    [
        ("pointer", "activated_roles", [], "ROLE_NOT_ACTIVATED"),
        (
            "pointer",
            "activation_journal_head_file_sha256",
            "0" * 64,
            "ACTIVATED_ROLE_EVIDENCE_INVALID",
        ),
        (
            "pointer",
            "activated_roles",
            [{
                "agent_code": "NV",
                "role_projection_row_sha256": "1" * 64,
                "role_bundle_row_sha256": "2" * 64,
                "runtime_attestation_sha256": "3" * 64,
                "route_ids": ["hermes:nv:wrong-route/v1"],
            }],
            "ROUTE_NOT_ACTIVATED",
        ),
        ("envelope", "authority_required", False, "AUTHORITY_REQUIRED"),
        ("contract", "allowed_write_set", [PATH], "WRITE_AUTHORITY_FORBIDDEN"),
    ],
)
def test_required_schema_denials(artifact, field, value, reason):
    case = _case()
    document = copy.deepcopy(case[artifact])
    if artifact == "contract":
        document[field] = value
        parser = parse_task_contract
        root = None
    else:
        document["payload"][field] = value
        authority = "activation" if artifact == "pointer" else "task-envelope"
        document = _resign(case, document, authority)
        parser = parse_activation_pointer if artifact == "pointer" else parse_task_envelope
        root = case["roots"][authority]
    with pytest.raises(AuthoritySchemaError, match=reason):
        if root is None:
            parser(_raw(document))
        else:
            parser(_raw(document), root)


def test_pointer_checkpoint_fork_gap_rollback_and_epoch_rollback_are_denied():
    case = _case()
    base = copy.deepcopy(case["checkpoint"])
    mutations = []
    fork = copy.deepcopy(base)
    fork.update(last_pointer_generation=1, last_pointer_file_sha256="f" * 64)
    mutations.append(fork)
    gap = copy.deepcopy(base)
    gap["last_pointer_generation"] = 2
    gap["last_pointer_file_sha256"] = "f" * 64
    mutations.append(gap)
    minimum = copy.deepcopy(base)
    minimum["operator_minimum_generation"] = 2
    mutations.append(minimum)
    for checkpoint in mutations:
        assert _evaluate(case, checkpoint=checkpoint).reasons == (
            "POINTER_ROLLBACK_OR_FORK",
        )


def test_checkpoint_dynamic_mapping_is_snapshotted_once():
    case = _case()

    class FlippingCheckpoint(dict):
        def __init__(self, source):
            super().__init__(source)
            self.minimum_reads = 0

        def __getitem__(self, key):
            if key == "operator_minimum_generation":
                self.minimum_reads += 1
                return 2 if self.minimum_reads == 1 else 1
            return super().__getitem__(key)

    checkpoint = FlippingCheckpoint(case["checkpoint"])
    decision = _evaluate(case, checkpoint=checkpoint)
    assert decision.reasons == ("POINTER_ROLLBACK_OR_FORK",)
    assert checkpoint.minimum_reads == 1


@pytest.mark.parametrize("mutation", ["top_level", "nested_root"])
def test_checkpoint_original_mutation_after_snapshot_cannot_change_gate(
    monkeypatch, mutation
):
    case = _case()
    checkpoint = copy.deepcopy(case["checkpoint"])
    module = sys.modules["agent.role_authority_schema"]
    original_checkpoint = module._checkpoint

    def snapshot_then_mutate(source):
        snapshot = original_checkpoint(source)
        if mutation == "top_level":
            source["operator_minimum_generation"] = 2
        else:
            source["ra_root"]["fingerprint_sha256"] = "f" * 64
        return snapshot

    monkeypatch.setattr(module, "_checkpoint", snapshot_then_mutate)
    _assert_structural(_evaluate(case, checkpoint=checkpoint))


def test_malformed_checkpoint_snapshot_exception_converges_to_deny():
    case = _case()

    class ExplodingCheckpoint(dict):
        def __getitem__(self, key):
            if key == "last_pointer_generation":
                raise RuntimeError("caller-owned checkpoint exploded")
            return super().__getitem__(key)

    decision = _evaluate(case, checkpoint=ExplodingCheckpoint(case["checkpoint"]))
    assert decision.decision == "DENY"
    assert decision.reasons == ("STRICT_SCHEMA_INVALID",)


def test_exact_same_checkpoint_reread_is_allowed_but_journal_fork_is_not():
    case = _case()
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(case["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(case["journal"])),
    )
    _assert_structural(_evaluate(case, checkpoint=checkpoint))
    checkpoint["last_journal_head_file_sha256"] = "f" * 64
    assert _evaluate(case, checkpoint=checkpoint).reasons == (
        "ACTIVATION_JOURNAL_INVALID",
    )


def test_next_generation_requires_exact_previous_pointer_and_journal_head():
    first = _case()
    second = _case(
        generation=2,
        previous_pointer_sha256=_sha(_raw(first["pointer"])),
        sequence=2,
        previous_record_sha256=_sha(_raw(first["journal"])),
    )
    checkpoint = copy.deepcopy(second["checkpoint"])
    checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
        operator_pinned_genesis_pointer_sha256=_sha(_raw(first["pointer"])),
    )
    _assert_structural(_evaluate(second, checkpoint=checkpoint))
    bad = copy.deepcopy(checkpoint)
    bad["last_journal_head_file_sha256"] = "f" * 64
    assert _evaluate(second, checkpoint=bad).reasons == (
        "ACTIVATION_JOURNAL_INVALID",
    )


def test_forward_generation_gap_and_missing_previous_pointer_are_denied():
    first = _case()
    checkpoint = copy.deepcopy(first["checkpoint"])
    checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
    )
    gap = _case(
        generation=3,
        previous_pointer_sha256=_sha(_raw(first["pointer"])),
        sequence=2,
        previous_record_sha256=_sha(_raw(first["journal"])),
    )
    gap_checkpoint = copy.deepcopy(gap["checkpoint"])
    gap_checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
        operator_pinned_genesis_pointer_sha256=_sha(_raw(first["pointer"])),
    )
    assert _evaluate(gap, checkpoint=gap_checkpoint).reasons == (
        "POINTER_ROLLBACK_OR_FORK",
    )
    missing = _case(
        generation=2,
        previous_pointer_sha256=None,
        sequence=2,
        previous_record_sha256=_sha(_raw(first["journal"])),
    )
    missing_checkpoint = copy.deepcopy(missing["checkpoint"])
    missing_checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
        operator_pinned_genesis_pointer_sha256=_sha(_raw(first["pointer"])),
    )
    assert _evaluate(missing, checkpoint=missing_checkpoint).reasons == (
        "POINTER_ROLLBACK_OR_FORK",
    )


def test_forward_journal_missing_previous_and_same_sequence_fork_are_denied():
    first = _case()
    checkpoint = copy.deepcopy(first["checkpoint"])
    checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
    )
    missing = _case(
        generation=2,
        previous_pointer_sha256=_sha(_raw(first["pointer"])),
        sequence=2,
        previous_record_sha256=None,
    )
    missing_checkpoint = copy.deepcopy(missing["checkpoint"])
    missing_checkpoint.update(
        last_pointer_generation=1,
        last_pointer_file_sha256=_sha(_raw(first["pointer"])),
        last_journal_sequence=1,
        last_journal_head_file_sha256=_sha(_raw(first["journal"])),
        operator_pinned_genesis_pointer_sha256=_sha(_raw(first["pointer"])),
    )
    assert _evaluate(missing, checkpoint=missing_checkpoint).reasons == (
        "ACTIVATION_JOURNAL_INVALID",
    )

    forked_journal = copy.deepcopy(first["journal"])
    forked_journal["payload"]["target_set_sha256"] = "f" * 64
    forked_journal = _resign(first, forked_journal, "journal")
    pointer = copy.deepcopy(first["pointer"])
    pointer["payload"]["activation_journal_head_file_sha256"] = _sha(
        _raw(forked_journal)
    )
    pointer = _resign(first, pointer, "activation")
    envelope = copy.deepcopy(first["envelope"])
    envelope["payload"]["activation_journal_head_file_sha256"] = _sha(
        _raw(forked_journal)
    )
    envelope["payload"]["active_pointer_file_sha256"] = _sha(_raw(pointer))
    envelope = _resign(first, envelope, "task-envelope")
    parsed = _parse(
        first, pointer=pointer, journal=forked_journal, envelope=envelope
    )
    same_pointer_checkpoint = copy.deepcopy(checkpoint)
    same_pointer_checkpoint["last_pointer_file_sha256"] = _sha(_raw(pointer))
    assert _evaluate(
        first, parsed=parsed, checkpoint=same_pointer_checkpoint
    ).reasons == ("ACTIVATION_JOURNAL_INVALID",)


@pytest.mark.parametrize(
    ("artifact", "field"),
    [
        ("pointer", "activation_id"),
        ("journal", "generation"),
        ("pointer", "role_bundle_file_sha256"),
    ],
)
def test_a_b_cross_swaps_are_denied(artifact, field):
    case = _case()
    document = copy.deepcopy(case[artifact])
    document["payload"][field] = 2 if field == "generation" else "f" * 64
    if field == "activation_id":
        document["payload"][field] = "activation:other/0001"
    authority = "activation" if artifact == "pointer" else "journal"
    document = _resign(case, document, authority)
    pointer = document if artifact == "pointer" else copy.deepcopy(case["pointer"])
    journal = document if artifact == "journal" else case["journal"]
    if artifact == "journal":
        pointer["payload"]["activation_journal_head_file_sha256"] = _sha(
            _raw(journal)
        )
        pointer = _resign(case, pointer, "activation")
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["active_pointer_file_sha256"] = _sha(_raw(pointer))
    envelope["payload"]["activation_journal_head_file_sha256"] = _sha(
        _raw(journal)
    )
    envelope = _resign(case, envelope, "task-envelope")
    parsed = _parse(
        case, pointer=pointer, journal=journal, envelope=envelope
    )
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint["operator_pinned_genesis_pointer_sha256"] = _sha(_raw(pointer))
    assert _evaluate(case, parsed=parsed, checkpoint=checkpoint).reasons == (
        "ACTIVATION_JOURNAL_INVALID",
    )


def test_direct_parsed_artifact_constructor_has_no_parser_provenance():
    case = _case()
    parsed = _parse(case)
    forged = tuple(
        ParsedAuthorityArtifact(
            schema_version=item.schema_version,
            value=copy.deepcopy(item.value),
            raw=item.raw,
            file_sha256=item.file_sha256,
            verified_trust_root_id=item.verified_trust_root_id,
            verified_key_id=item.verified_key_id,
            verified_root_epoch=item.verified_root_epoch,
            verified_root_fingerprint_sha256=item.verified_root_fingerprint_sha256,
            verified_public_key_base64=item.verified_public_key_base64,
        )
        for item in parsed
    )
    assert _evaluate(case, parsed=forged).reasons == ("STRICT_SCHEMA_INVALID",)


def test_direct_constructor_cannot_forge_invalid_a_c_signatures_and_metadata():
    case = _case()
    pointer, journal, contract, envelope = _parse(case)
    forged_pointer_value = copy.deepcopy(pointer.value)
    forged_pointer_value["signature"]["value_base64"] = base64.b64encode(
        b"x" * 64
    ).decode("ascii")
    forged_pointer_raw = _raw(forged_pointer_value)
    forged_pointer = ParsedAuthorityArtifact(
        schema_version=A_SCHEMA,
        value=forged_pointer_value,
        raw=forged_pointer_raw,
        file_sha256=_sha(forged_pointer_raw),
        verified_trust_root_id=pointer.verified_trust_root_id,
        verified_key_id=pointer.verified_key_id,
        verified_root_epoch=pointer.verified_root_epoch,
        verified_root_fingerprint_sha256=pointer.verified_root_fingerprint_sha256,
        verified_public_key_base64=pointer.verified_public_key_base64,
    )
    forged_envelope_value = copy.deepcopy(envelope.value)
    forged_envelope_value["payload"]["active_pointer_file_sha256"] = _sha(
        forged_pointer_raw
    )
    forged_envelope_value["signature"]["value_base64"] = base64.b64encode(
        b"y" * 64
    ).decode("ascii")
    forged_envelope_raw = _raw(forged_envelope_value)
    forged_envelope = ParsedAuthorityArtifact(
        schema_version=C_SCHEMA,
        value=forged_envelope_value,
        raw=forged_envelope_raw,
        file_sha256=_sha(forged_envelope_raw),
        verified_trust_root_id=envelope.verified_trust_root_id,
        verified_key_id=envelope.verified_key_id,
        verified_root_epoch=envelope.verified_root_epoch,
        verified_root_fingerprint_sha256=envelope.verified_root_fingerprint_sha256,
        verified_public_key_base64=envelope.verified_public_key_base64,
    )
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint["operator_pinned_genesis_pointer_sha256"] = _sha(forged_pointer_raw)
    assert _evaluate(
        case,
        parsed=(forged_pointer, journal, contract, forged_envelope),
        checkpoint=checkpoint,
    ).reasons == ("STRICT_SCHEMA_INVALID",)


def test_module_sentinel_cannot_bypass_cryptographic_reverification():
    case = _case()
    pointer, journal, contract, envelope = _parse(case)
    module = sys.modules["agent.role_authority_schema"]

    forged_a_value = copy.deepcopy(pointer.value)
    forged_a_value["signature"]["value_base64"] = base64.b64encode(
        b"x" * 64
    ).decode("ascii")
    forged_a_raw = _raw(forged_a_value)
    forged_a = ParsedAuthorityArtifact(
        schema_version=A_SCHEMA,
        value=forged_a_value,
        raw=forged_a_raw,
        file_sha256=_sha(forged_a_raw),
        verified_trust_root_id=pointer.verified_trust_root_id,
        verified_key_id=pointer.verified_key_id,
        verified_root_epoch=pointer.verified_root_epoch,
        verified_root_fingerprint_sha256=pointer.verified_root_fingerprint_sha256,
        verified_public_key_base64=pointer.verified_public_key_base64,
        _parser_provenance=module._PARSER_PROVENANCE,
    )
    forged_c_value = copy.deepcopy(envelope.value)
    forged_c_value["payload"]["active_pointer_file_sha256"] = _sha(forged_a_raw)
    forged_c_value["signature"]["value_base64"] = base64.b64encode(
        b"y" * 64
    ).decode("ascii")
    forged_c_raw = _raw(forged_c_value)
    forged_c = ParsedAuthorityArtifact(
        schema_version=C_SCHEMA,
        value=forged_c_value,
        raw=forged_c_raw,
        file_sha256=_sha(forged_c_raw),
        verified_trust_root_id=envelope.verified_trust_root_id,
        verified_key_id=envelope.verified_key_id,
        verified_root_epoch=envelope.verified_root_epoch,
        verified_root_fingerprint_sha256=envelope.verified_root_fingerprint_sha256,
        verified_public_key_base64=envelope.verified_public_key_base64,
        _parser_provenance=module._PARSER_PROVENANCE,
    )
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint["operator_pinned_genesis_pointer_sha256"] = _sha(forged_a_raw)
    assert _evaluate(
        case,
        parsed=(forged_a, journal, contract, forged_c),
        checkpoint=checkpoint,
    ).reasons == ("TRUST_ROOT_OR_SIGNATURE_INVALID",)


def test_signed_payload_mutation_after_verify_cannot_change_gate_input(monkeypatch):
    case = _case()
    parsed = _parse(case)
    envelope = parsed[3]
    attacker_backend = {**case["backend"], "instance_token": "instance:attacker/0001"}
    attacker_digest = _domain(
        "thewon-bac-backend-identity/v1", _c14n(attacker_backend)
    )
    module = sys.modules["agent.role_authority_schema"]
    original_verify = module._verify_signature

    def mutate_after_c_verify(wrapper, schema, root):
        original_verify(wrapper, schema, root)
        if schema == C_SCHEMA:
            envelope.value["payload"]["backend_identity_sha256"] = attacker_digest

    monkeypatch.setattr(module, "_verify_signature", mutate_after_c_verify)
    decision = _evaluate(case, parsed=parsed, backend=attacker_backend)
    assert decision.decision == "DENY"
    assert decision.reasons == ("BACKEND_BINDING_MISMATCH",)


@pytest.mark.parametrize("binding", ["session", "turn"])
def test_session_and_turn_bindings_are_exact(binding):
    case = _case()
    kwargs = {binding: f"{binding}:wrong/0001"}
    assert _evaluate(case, **kwargs).reasons == ("TURN_BINDING_MISMATCH",)


def test_backend_digest_is_structural_only_and_rb_boolean_claim_is_rejected():
    case = _case()
    backend = copy.deepcopy(case["backend"])
    backend["instance_token"] = "instance:wrong/0001"
    assert _evaluate(case, backend=backend).reasons == ("BACKEND_BINDING_MISMATCH",)
    backend = {**case["backend"], "backend_attestation_verified": True}
    assert _evaluate(case, backend=backend).reasons == ("UNPROVABLE_AUTHORITY",)


def test_backend_kind_is_exact_local_even_when_envelope_digest_matches():
    case = _case()
    backend = {**case["backend"], "kind": "docker"}
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["backend_identity_sha256"] = _domain(
        "thewon-bac-backend-identity/v1", _c14n(backend)
    )
    envelope = _resign(case, envelope, "task-envelope")
    parsed = _parse(case, envelope=envelope)
    assert _evaluate(case, parsed=parsed, backend=backend).reasons == (
        "BACKEND_BINDING_MISMATCH",
    )


def test_exact_request_digest_source_binding_and_contract_file_hash_are_bound():
    case = _case()
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["normalized_args"]["offset"] = 2
    envelope = _resign(case, envelope, "task-envelope")
    with pytest.raises(AuthoritySchemaError, match="NORMALIZED_ARGS_MISMATCH"):
        parse_task_envelope(_raw(envelope), case["roots"]["task-envelope"])

    contract = copy.deepcopy(case["contract"])
    contract["expected_source_sha256"] = "f" * 64
    with pytest.raises(AuthoritySchemaError, match="NORMALIZED_ARGS_MISMATCH"):
        parse_task_contract(_raw(contract))

    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["task_contract_file_sha256"] = "f" * 64
    envelope = _resign(case, envelope, "task-envelope")
    assert _evaluate(case, parsed=_parse(case, envelope=envelope)).reasons == (
        "NORMALIZED_ARGS_MISMATCH",
    )


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("active_pointer_file_sha256", "ACTIVATION_JOURNAL_INVALID"),
        ("activation_journal_head_file_sha256", "ACTIVATION_JOURNAL_INVALID"),
        ("activation_generation", "ACTIVATION_JOURNAL_INVALID"),
        ("task_contract_file_sha256", "NORMALIZED_ARGS_MISMATCH"),
    ],
)
def test_each_c_authority_edge_is_independently_bound(field, reason):
    case = _case()
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"][field] = 2 if field == "activation_generation" else "f" * 64
    envelope = _resign(case, envelope, "task-envelope")
    assert _evaluate(case, parsed=_parse(case, envelope=envelope)).reasons == (reason,)


def test_d_request_binding_read_set_and_c_args_drift_are_independent():
    case = _case()

    request_drift = copy.deepcopy(case["contract"])
    request_drift["source_request"]["offset"] = 2
    request_drift["source_request_sha256"] = _domain(
        "thewon-bac-source-request/v1", _c14n(request_drift["source_request"])
    )
    _refresh_contract(request_drift)
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["task_contract_file_sha256"] = _sha(_raw(request_drift))
    envelope = _resign(case, envelope, "task-envelope")
    parsed = _parse(case, contract=request_drift, envelope=envelope)
    assert _evaluate(case, parsed=parsed).reasons == ("NORMALIZED_ARGS_MISMATCH",)

    binding_drift = copy.deepcopy(case["contract"])
    binding_drift["source_bindings"][0]["sha256"] = "f" * 64
    with pytest.raises(AuthoritySchemaError, match="NORMALIZED_ARGS_MISMATCH"):
        parse_task_contract(_raw(binding_drift))

    read_drift = copy.deepcopy(case["contract"])
    read_drift["allowed_read_set"] = [
        "/Users/elroy/Documents/Codex/2026-08-02/llm-wiki/other.md"
    ]
    with pytest.raises(AuthoritySchemaError, match="NORMALIZED_ARGS_MISMATCH"):
        parse_task_contract(_raw(read_drift))

    args_drift = copy.deepcopy(case["envelope"])
    args_drift["payload"]["normalized_args"]["offset"] = 2
    args_drift["payload"]["normalized_args_sha256"] = _domain(
        "thewon-bac-normalized-args/v1",
        _c14n(args_drift["payload"]["normalized_args"]),
    )
    args_drift = _resign(case, args_drift, "task-envelope")
    assert _evaluate(case, parsed=_parse(case, envelope=args_drift)).reasons == (
        "NORMALIZED_ARGS_MISMATCH",
    )


def test_one_shot_contract_rejects_any_additional_source_or_read_path():
    case = _case()
    other = "/Users/elroy/Documents/Codex/2026-08-02/llm-wiki/other.md"
    contract = copy.deepcopy(case["contract"])
    contract["source_bindings"].append({"path": other, "sha256": "f" * 64})
    contract["allowed_read_set"].append(other)
    contract["source_bindings"].sort(key=lambda item: item["path"])
    contract["allowed_read_set"].sort()
    _refresh_contract(contract)
    with pytest.raises(AuthoritySchemaError, match="NORMALIZED_ARGS_MISMATCH"):
        parse_task_contract(_raw(contract))


def test_journal_activation_envelope_wall_order_is_exact():
    case = _case()
    journal = copy.deepcopy(case["journal"])
    journal["payload"]["written_at_wall"] = "2026-08-04T00:00:01Z"
    journal = _resign(case, journal, "journal")
    pointer = copy.deepcopy(case["pointer"])
    pointer["payload"]["activation_journal_head_file_sha256"] = _sha(_raw(journal))
    pointer = _resign(case, pointer, "activation")
    envelope = copy.deepcopy(case["envelope"])
    envelope["payload"]["activation_journal_head_file_sha256"] = _sha(_raw(journal))
    envelope["payload"]["active_pointer_file_sha256"] = _sha(_raw(pointer))
    envelope = _resign(case, envelope, "task-envelope")
    parsed = _parse(case, pointer=pointer, journal=journal, envelope=envelope)
    checkpoint = copy.deepcopy(case["checkpoint"])
    checkpoint["operator_pinned_genesis_pointer_sha256"] = _sha(_raw(pointer))
    assert _evaluate(case, parsed=parsed, checkpoint=checkpoint).reasons == (
        "TURN_DEADLINE_INVALID",
    )


def test_expected_source_digest_is_whole_fd_while_args_only_bind_render_range():
    case = _case()
    contract = case["contract"]
    assert contract["source_digest_domain"] == "EXACT_FD_BYTES"
    assert contract["expected_source_sha256"] == contract["source_bindings"][0]["sha256"]
    assert contract["source_request"] == {"path": PATH, "offset": 1, "limit": 20}


@pytest.mark.parametrize("wall", ["2026-08-04T00:00:04Z", "2026-08-04T00:05:00Z"])
def test_signed_wall_window_is_fresh_and_monotonic_is_loader_only(wall):
    assert _evaluate(_case(), wall_now=wall).reasons == ("TURN_DEADLINE_INVALID",)


def test_domain_digest_has_independent_literal_oracle():
    domain = b"thewon-bac-user-goal/v1"
    goal = b"Read the approved LLM Wiki source without mutation."
    oracle = hashlib.sha256(len(domain).to_bytes(4, "big") + domain + goal).hexdigest()
    assert _case()["contract"]["user_goal_sha256"] == oracle


def test_parser_reload_has_no_production_import_or_registry_side_effect():
    module = sys.modules["agent.role_authority_schema"]
    before = set(sys.modules)
    importlib.reload(module)
    added = set(sys.modules) - before
    assert not any(name.startswith("tools.") for name in added)
    assert not any(name in added for name in ("run_agent", "agent.tool_executor"))
