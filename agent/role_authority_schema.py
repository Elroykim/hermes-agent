"""Pure dormant A/B/C/D authority contracts for one NV FD-read canary.

The module performs no I/O, clock reads, nonce access, backend attestation,
ContextVar installation, activation, or dispatch.  A successful evaluation is
only structural evidence awaiting a trusted backend witness and atomic nonce
consumption.  It is never execution authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


A_SCHEMA = "thewon-bac-role-activation-pointer/v1"
B_SCHEMA = "thewon-bac-role-activation-journal-record/v1"
C_SCHEMA = "thewon-bac-authenticated-task-envelope/v1"
D_SCHEMA = "thewon-bac-parsed-task-contract/v1"
SIGNATURE_DOMAIN = "thewon-bac-ed25519-signature/v1"
NV_ROUTE = "hermes:nv:fd-bound-read:v1"
PARSER_VERSION = "thewon:nv-task-parser/v1"
MAX_U64 = (1 << 63) - 1
MAX_RAW_ARTIFACT_BYTES = 1024 * 1024

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TS = re.compile(
    r"^(?:[0-9]{4})-(?:[0-9]{2})-(?:[0-9]{2})T"
    r"(?:[0-9]{2}):(?:[0-9]{2}):(?:[0-9]{2})(?:\.[0-9]{1,9})?Z$"
)
_WRAPPER_FIELDS = {"payload", "signature"}
_SIGNATURE_FIELDS = {
    "algorithm",
    "canonicalization",
    "trust_root_id",
    "key_id",
    "value_base64",
}
_A_FIELDS = {
    "schema_version",
    "state",
    "activation_class",
    "scope_mode",
    "generation",
    "previous_pointer_sha256",
    "activation_id",
    "activation_journal_head_file_sha256",
    "allowed_rt_issuer_policy_sha256",
    "identity_authority_file_sha256",
    "role_projection_file_sha256",
    "role_bundle_file_sha256",
    "role_bundle_internal_sha256",
    "scope_evidence_file_sha256",
    "scope_evidence_internal_sha256",
    "activated_roles",
    "activated_at_wall",
    "expires_at_wall",
}
_A_ROLE_FIELDS = {
    "agent_code",
    "role_projection_row_sha256",
    "role_bundle_row_sha256",
    "runtime_attestation_sha256",
    "route_ids",
}
_B_FIELDS = {
    "schema_version",
    "journal_id",
    "sequence",
    "previous_record_sha256",
    "activation_id",
    "state",
    "generation",
    "role_bundle_file_sha256",
    "role_bundle_internal_sha256",
    "scope_evidence_file_sha256",
    "scope_evidence_internal_sha256",
    "activated_role_codes",
    "target_set_sha256",
    "approval_receipt_file_sha256",
    "independent_review_file_sha256",
    "rollback_manifest_file_sha256",
    "executor_file_sha256",
    "written_at_wall",
}
_C_FIELDS = {
    "schema_version",
    "envelope_id",
    "parent_request_id",
    "route_id",
    "authority_required",
    "issuer_agent_code",
    "agent_code",
    "session_id",
    "logical_task_id",
    "turn_id",
    "backend_identity_sha256",
    "active_pointer_file_sha256",
    "activation_journal_head_file_sha256",
    "activation_generation",
    "task_contract_file_sha256",
    "tool_identifier",
    "normalized_args",
    "normalized_args_sha256",
    "nonce",
    "issued_at_wall",
    "not_before_wall",
    "expires_at_wall",
}
_D_FIELDS = {
    "schema_version",
    "parser_version",
    "logical_task_id",
    "user_goal",
    "user_goal_sha256",
    "source_bindings",
    "source_request",
    "source_request_sha256",
    "expected_source_sha256",
    "source_digest_domain",
    "allowed_read_set",
    "allowed_write_set",
    "mutation_class",
    "producer_agent_code",
    "independent_reviewer_agent_code",
    "activation_authority",
    "capability_id",
    "operation_class",
    "resource",
    "tool_identifier",
    "role_scope",
    "validation_commands",
    "negative_tests",
    "rollback",
    "stop_conditions",
    "contract_expires_at_wall",
    "contract_sha256",
}
_CHECKPOINT_FIELDS = {
    "last_pointer_generation",
    "last_pointer_file_sha256",
    "last_journal_sequence",
    "last_journal_head_file_sha256",
    "ra_root",
    "rj_root",
    "rt_root",
    "operator_pinned_genesis_pointer_sha256",
    "operator_minimum_generation",
}
_ROOT_PIN_FIELDS = {"trust_root_id", "key_id", "epoch", "fingerprint_sha256"}
_PARSER_PROVENANCE = object()
_STRUCTURAL_DECISION = "STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE"
_STRUCTURAL_REASONS = (
    "BACKEND_ATTESTATION_REQUIRED",
    "NONCE_ATOMIC_CONSUME_REQUIRED",
)
_DENY_REASONS = {
    "ACTIVATION_JOURNAL_INVALID",
    "AUTHORITY_REQUIRED",
    "BACKEND_BINDING_MISMATCH",
    "NORMALIZED_ARGS_MISMATCH",
    "POINTER_ROLLBACK_OR_FORK",
    "ROLE_NOT_ACTIVATED",
    "ROUTE_NOT_ACTIVATED",
    "STRICT_SCHEMA_INVALID",
    "TRUST_ROOT_OR_SIGNATURE_INVALID",
    "TURN_BINDING_MISMATCH",
    "TURN_DEADLINE_INVALID",
    "UNPROVABLE_AUTHORITY",
    "WRITE_AUTHORITY_FORBIDDEN",
}


class AuthoritySchemaError(ValueError):
    """Fail-closed parser error carrying one stable reason code."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class TrustRoot:
    """Out-of-band testable trust-root description; embedded keys are ignored."""

    trust_root_id: str
    key_id: str
    epoch: int
    public_key_base64: str
    fingerprint_sha256: str

    def __post_init__(self) -> None:
        try:
            _require_id(self.trust_root_id)
            _require_id(self.key_id)
            _u64(self.epoch, positive=True)
            key = _decode_base64(self.public_key_base64, size=32)
            _require_sha(self.fingerprint_sha256)
            if hashlib.sha256(key).hexdigest() != self.fingerprint_sha256:
                raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
        except AuthoritySchemaError as exc:
            if exc.reason == "TRUST_ROOT_OR_SIGNATURE_INVALID":
                raise
            raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID") from exc
        except Exception as exc:
            raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID") from exc


@dataclass(frozen=True, slots=True)
class ParsedAuthorityArtifact:
    schema_version: str
    value: Mapping[str, Any]
    raw: bytes
    file_sha256: str
    verified_trust_root_id: str = ""
    verified_key_id: str = ""
    verified_root_epoch: int = 0
    verified_root_fingerprint_sha256: str = ""
    verified_public_key_base64: str = ""
    _parser_provenance: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True)
class GateDecision:
    decision: str
    reasons: tuple[str, ...]
    consume_key_candidate: str = ""
    execute_authority: bool = False
    rb_complete: bool = False
    route_metadata_wiring_complete: bool = False

    def __post_init__(self) -> None:
        if (
            self.execute_authority is not False
            or self.rb_complete is not False
            or self.route_metadata_wiring_complete is not False
            or not isinstance(self.reasons, tuple)
        ):
            raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
        if self.decision == "DENY":
            if (
                len(self.reasons) != 1
                or self.reasons[0] not in _DENY_REASONS
                or self.consume_key_candidate != ""
            ):
                raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
            return
        if self.decision != _STRUCTURAL_DECISION:
            raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
        if self.reasons != _STRUCTURAL_REASONS:
            raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
        try:
            _require_sha(self.consume_key_candidate)
        except AuthoritySchemaError as exc:
            raise AuthoritySchemaError("STRICT_SCHEMA_INVALID") from exc


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID") from exc


def _domain_bytes(domain: str, payload: bytes) -> bytes:
    encoded = domain.encode("utf-8")
    return hashlib.sha256(
        len(encoded).to_bytes(4, "big") + encoded + payload
    ).digest()


def _domain(domain: str, payload: bytes) -> str:
    return _domain_bytes(domain, payload).hex()


def _strict_json(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RAW_ARTIFACT_BYTES:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
            result[key] = value
        return result

    def invalid_number(_value: str) -> None:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_float=invalid_number,
            parse_constant=invalid_number,
        )
    except AuthoritySchemaError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID") from exc
    if not isinstance(value, dict) or _canonical(value) + b"\n" != raw:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return value


def _exact(
    value: Mapping[str, Any],
    fields: set[str],
    reason: str = "STRICT_SCHEMA_INVALID",
) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthoritySchemaError(reason)


def _require_id(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return value


def _require_sha(value: Any, *, reason: str = "STRICT_SCHEMA_INVALID") -> str:
    if (
        not isinstance(value, str)
        or _SHA.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise AuthoritySchemaError(reason)
    return value


def _optional_sha(value: Any) -> str | None:
    return None if value is None else _require_sha(value)


def _u64(value: Any, *, positive: bool = False) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < (1 if positive else 0)
        or value > MAX_U64
    ):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return value


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or _TS.fullmatch(value) is None:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return parsed.astimezone(timezone.utc)


def _decode_base64(value: Any, *, size: int) -> bytes:
    if not isinstance(value, str):
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
    return decoded


def _canonical_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or "\x00" in value
        or "~" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value or str(path) != value:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return value


def _source_request(value: Any) -> Mapping[str, Any]:
    _exact(value, {"path", "offset", "limit"})
    _canonical_path(value["path"])
    _u64(value["offset"], positive=True)
    _u64(value["limit"], positive=True)
    return value


def _nonempty_strings(value: Any) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str)
            or not item
            or item.strip() != item
            or "\x00" in item
            for item in value
        )
    ):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")


def _signature_preimage(schema: str, payload: Mapping[str, Any]) -> bytes:
    return _domain_bytes(
        SIGNATURE_DOMAIN,
        schema.encode("utf-8") + b"\x00" + _canonical(payload),
    )


def _wrapper_payload(wrapper: dict[str, Any]) -> Mapping[str, Any]:
    _exact(wrapper, _WRAPPER_FIELDS)
    payload = wrapper["payload"]
    if not isinstance(payload, dict):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return payload


def _verify_signature(
    wrapper: dict[str, Any],
    schema: str,
    trust_root: TrustRoot,
) -> None:
    payload = wrapper["payload"]
    signature = wrapper["signature"]
    if not isinstance(trust_root, TrustRoot):
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_FIELDS:
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
    if (
        signature.get("algorithm") != "ed25519"
        or signature.get("canonicalization") != "thewon-json-c14n/v1"
        or signature.get("trust_root_id") != trust_root.trust_root_id
        or signature.get("key_id") != trust_root.key_id
    ):
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID")
    signed = _decode_base64(signature.get("value_base64"), size=64)
    public = _decode_base64(trust_root.public_key_base64, size=32)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signed, _signature_preimage(schema, payload)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthoritySchemaError("TRUST_ROOT_OR_SIGNATURE_INVALID") from exc


def _artifact(
    schema: str,
    value: dict[str, Any],
    raw: bytes,
    verified_root: TrustRoot | None = None,
) -> ParsedAuthorityArtifact:
    return ParsedAuthorityArtifact(
        schema_version=schema,
        value=value,
        raw=raw,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        verified_trust_root_id=(
            verified_root.trust_root_id if verified_root is not None else ""
        ),
        verified_key_id=verified_root.key_id if verified_root is not None else "",
        verified_root_epoch=verified_root.epoch if verified_root is not None else 0,
        verified_root_fingerprint_sha256=(
            verified_root.fingerprint_sha256 if verified_root is not None else ""
        ),
        verified_public_key_base64=(
            verified_root.public_key_base64 if verified_root is not None else ""
        ),
        _parser_provenance=_PARSER_PROVENANCE,
    )


def parse_activation_pointer(raw: bytes, ra: TrustRoot) -> ParsedAuthorityArtifact:
    wrapper = _strict_json(raw)
    payload = _wrapper_payload(wrapper)
    raw_schema = payload.get("schema_version")
    if raw_schema != A_SCHEMA:
        if isinstance(raw_schema, str) and "activation-pointer" in raw_schema:
            raise AuthoritySchemaError("LEGACY_POINTER_NONAUTHORITATIVE")
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _verify_signature(wrapper, A_SCHEMA, ra)
    _exact(payload, _A_FIELDS)
    if (
        payload["state"] != "active"
        or payload["activation_class"] != "canary"
        or payload["scope_mode"] != "explicit_allowlist"
    ):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _u64(payload["generation"], positive=True)
    _optional_sha(payload["previous_pointer_sha256"])
    _require_id(payload["activation_id"])
    _require_sha(
        payload["activation_journal_head_file_sha256"],
        reason="ACTIVATED_ROLE_EVIDENCE_INVALID",
    )
    for field in (
        "allowed_rt_issuer_policy_sha256",
        "identity_authority_file_sha256",
        "role_projection_file_sha256",
        "role_bundle_file_sha256",
        "role_bundle_internal_sha256",
        "scope_evidence_file_sha256",
        "scope_evidence_internal_sha256",
    ):
        _require_sha(payload[field])
    roles = payload["activated_roles"]
    if not isinstance(roles, list) or len(roles) != 1:
        raise AuthoritySchemaError("ROLE_NOT_ACTIVATED")
    role = roles[0]
    _exact(role, _A_ROLE_FIELDS, "ACTIVATED_ROLE_EVIDENCE_INVALID")
    if role.get("agent_code") != "NV":
        raise AuthoritySchemaError("ROLE_NOT_ACTIVATED")
    for field in (
        "role_projection_row_sha256",
        "role_bundle_row_sha256",
        "runtime_attestation_sha256",
    ):
        _require_sha(role.get(field), reason="ACTIVATED_ROLE_EVIDENCE_INVALID")
    if role.get("route_ids") != [NV_ROUTE]:
        raise AuthoritySchemaError("ROUTE_NOT_ACTIVATED")
    if _instant(payload["activated_at_wall"]) >= _instant(payload["expires_at_wall"]):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return _artifact(A_SCHEMA, wrapper, raw, ra)


def parse_journal_record(raw: bytes, rj: TrustRoot) -> ParsedAuthorityArtifact:
    wrapper = _strict_json(raw)
    payload = _wrapper_payload(wrapper)
    if payload.get("schema_version") != B_SCHEMA:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _verify_signature(wrapper, B_SCHEMA, rj)
    _exact(payload, _B_FIELDS)
    _require_id(payload["journal_id"])
    _u64(payload["sequence"], positive=True)
    _optional_sha(payload["previous_record_sha256"])
    _require_id(payload["activation_id"])
    if payload["state"] != "COMMITTED":
        raise AuthoritySchemaError("ACTIVATION_JOURNAL_INVALID")
    _u64(payload["generation"], positive=True)
    for field in (
        "role_bundle_file_sha256",
        "role_bundle_internal_sha256",
        "scope_evidence_file_sha256",
        "scope_evidence_internal_sha256",
        "target_set_sha256",
        "approval_receipt_file_sha256",
        "independent_review_file_sha256",
        "rollback_manifest_file_sha256",
        "executor_file_sha256",
    ):
        _require_sha(payload[field])
    if payload["activated_role_codes"] != ["NV"]:
        raise AuthoritySchemaError("ROLE_NOT_ACTIVATED")
    _instant(payload["written_at_wall"])
    return _artifact(B_SCHEMA, wrapper, raw, rj)


def parse_task_envelope(raw: bytes, rt: TrustRoot) -> ParsedAuthorityArtifact:
    wrapper = _strict_json(raw)
    payload = _wrapper_payload(wrapper)
    if payload.get("schema_version") != C_SCHEMA:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _verify_signature(wrapper, C_SCHEMA, rt)
    _exact(payload, _C_FIELDS)
    for field in (
        "envelope_id",
        "parent_request_id",
        "session_id",
        "logical_task_id",
        "turn_id",
        "nonce",
    ):
        _require_id(payload[field])
    if payload["route_id"] != NV_ROUTE:
        raise AuthoritySchemaError("ROUTE_NOT_ACTIVATED")
    if payload["authority_required"] is not True:
        raise AuthoritySchemaError("AUTHORITY_REQUIRED")
    if payload["issuer_agent_code"] != "MINA" or payload["agent_code"] != "NV":
        raise AuthoritySchemaError("ROLE_NOT_ACTIVATED")
    for field in (
        "backend_identity_sha256",
        "active_pointer_file_sha256",
        "activation_journal_head_file_sha256",
        "task_contract_file_sha256",
        "normalized_args_sha256",
    ):
        _require_sha(payload[field])
    _u64(payload["activation_generation"], positive=True)
    if payload["tool_identifier"] != "read_file":
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    request = _source_request(payload["normalized_args"])
    if _domain("thewon-bac-normalized-args/v1", _canonical(request)) != payload[
        "normalized_args_sha256"
    ]:
        raise AuthoritySchemaError("NORMALIZED_ARGS_MISMATCH")
    issued = _instant(payload["issued_at_wall"])
    not_before = _instant(payload["not_before_wall"])
    expires = _instant(payload["expires_at_wall"])
    if not issued <= not_before < expires:
        raise AuthoritySchemaError("TURN_DEADLINE_INVALID")
    return _artifact(C_SCHEMA, wrapper, raw, rt)


def parse_task_contract(raw: bytes) -> ParsedAuthorityArtifact:
    """Parse D; expected source SHA covers exact whole-FD bytes.

    ``source_request.offset`` and ``limit`` authorize only the rendered range;
    they never change the full-object digest domain.
    """
    value = _strict_json(raw)
    if value.get("schema_version") != D_SCHEMA:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _exact(value, _D_FIELDS)
    if value["parser_version"] != PARSER_VERSION:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _require_id(value["logical_task_id"])
    goal = value["user_goal"]
    if not isinstance(goal, str) or not goal or goal.strip() != goal or "\x00" in goal:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    _require_sha(value["user_goal_sha256"])
    if _domain("thewon-bac-user-goal/v1", goal.encode("utf-8")) != value[
        "user_goal_sha256"
    ]:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")

    bindings = value["source_bindings"]
    if not isinstance(bindings, list) or not bindings:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    binding_paths: list[str] = []
    source_map: dict[str, str] = {}
    for binding in bindings:
        _exact(binding, {"path", "sha256"})
        path = _canonical_path(binding["path"])
        digest = _require_sha(binding["sha256"])
        binding_paths.append(path)
        source_map[path] = digest
    if binding_paths != sorted(set(binding_paths)):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")

    request = _source_request(value["source_request"])
    _require_sha(value["source_request_sha256"])
    if _domain("thewon-bac-source-request/v1", _canonical(request)) != value[
        "source_request_sha256"
    ]:
        raise AuthoritySchemaError("NORMALIZED_ARGS_MISMATCH")
    expected = _require_sha(value["expected_source_sha256"])
    if (
        value["source_digest_domain"] != "EXACT_FD_BYTES"
        or source_map.get(request["path"]) != expected
    ):
        raise AuthoritySchemaError("NORMALIZED_ARGS_MISMATCH")

    read_set = value["allowed_read_set"]
    if not isinstance(read_set, list) or not read_set:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    canonical_reads = [_canonical_path(path) for path in read_set]
    if canonical_reads != sorted(set(canonical_reads)):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    if binding_paths != [request["path"]] or canonical_reads != [request["path"]]:
        raise AuthoritySchemaError("NORMALIZED_ARGS_MISMATCH")
    if request["path"] not in canonical_reads:
        raise AuthoritySchemaError("NORMALIZED_ARGS_MISMATCH")
    if value["allowed_write_set"] != [] or value["mutation_class"] != "read_only":
        raise AuthoritySchemaError("WRITE_AUTHORITY_FORBIDDEN")
    if value["producer_agent_code"] != "NV":
        raise AuthoritySchemaError("ROLE_NOT_ACTIVATED")
    reviewer = _require_id(value["independent_reviewer_agent_code"])
    if reviewer in {"NV", "MINA"}:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    exact_values = {
        "activation_authority": "Elroy",
        "capability_id": "read_scoped_sources",
        "operation_class": "read_scoped",
        "resource": "domain:llm-wiki",
        "tool_identifier": "read_file",
        "role_scope": "knowledge_source_read_only_canary",
        "rollback": "none_read_only",
    }
    if any(value[field] != expected for field, expected in exact_values.items()):
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    for field in ("validation_commands", "negative_tests", "stop_conditions"):
        _nonempty_strings(value[field])
    _instant(value["contract_expires_at_wall"])
    _require_sha(value["contract_sha256"])
    material = {key: item for key, item in value.items() if key != "contract_sha256"}
    if _domain(D_SCHEMA, _canonical(material)) != value["contract_sha256"]:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    return _artifact(D_SCHEMA, value, raw)


def _deny(reason: str) -> GateDecision:
    return GateDecision(decision="DENY", reasons=(reason,))


def _artifact_integrity(item: ParsedAuthorityArtifact) -> bool:
    return (
        item._parser_provenance is _PARSER_PROVENANCE
        and isinstance(item.raw, bytes)
        and hashlib.sha256(item.raw).hexdigest() == item.file_sha256
        and _canonical(item.value) + b"\n" == item.raw
    )


def _validate_checkpoint_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    _exact(value, _CHECKPOINT_FIELDS)
    _u64(value["last_pointer_generation"])
    _optional_sha(value["last_pointer_file_sha256"])
    _u64(value["last_journal_sequence"])
    _optional_sha(value["last_journal_head_file_sha256"])
    for field in ("ra_root", "rj_root", "rt_root"):
        pin = value[field]
        _exact(pin, _ROOT_PIN_FIELDS)
        _require_id(pin["trust_root_id"])
        _require_id(pin["key_id"])
        _u64(pin["epoch"], positive=True)
        _require_sha(pin["fingerprint_sha256"])
    _require_sha(value["operator_pinned_genesis_pointer_sha256"])
    _u64(value["operator_minimum_generation"], positive=True)
    if (value["last_pointer_generation"] == 0) != (
        value["last_pointer_file_sha256"] is None
    ):
        raise AuthoritySchemaError("POINTER_ROLLBACK_OR_FORK")
    if (value["last_journal_sequence"] == 0) != (
        value["last_journal_head_file_sha256"] is None
    ):
        raise AuthoritySchemaError("ACTIVATION_JOURNAL_INVALID")
    return value


def _checkpoint(value: Any) -> Mapping[str, Any]:
    """Capture caller-owned checkpoint data once into bounded plain JSON."""
    if not isinstance(value, dict) or set(dict.keys(value)) != _CHECKPOINT_FIELDS:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
    captured: dict[str, Any] = {}
    try:
        for key in sorted(_CHECKPOINT_FIELDS):
            item = value[key]
            if key not in {"ra_root", "rj_root", "rt_root"}:
                captured[key] = item
                continue
            if not isinstance(item, dict) or set(dict.keys(item)) != _ROOT_PIN_FIELDS:
                raise AuthoritySchemaError("STRICT_SCHEMA_INVALID")
            captured[key] = {
                root_key: item[root_key]
                for root_key in sorted(_ROOT_PIN_FIELDS)
            }
        _validate_checkpoint_snapshot(captured)
        raw = _canonical(captured) + b"\n"
        snapshot = _strict_json(raw)
        return _validate_checkpoint_snapshot(snapshot)
    except AuthoritySchemaError:
        raise
    except Exception as exc:
        raise AuthoritySchemaError("STRICT_SCHEMA_INVALID") from exc


def evaluate_nv_fd_read(
    pointer: ParsedAuthorityArtifact,
    journal: ParsedAuthorityArtifact,
    contract: ParsedAuthorityArtifact,
    envelope: ParsedAuthorityArtifact,
    authority_checkpoint: Mapping[str, Any],
    trusted_rt_issuer_policy_sha256: str,
    live_backend_identity: Mapping[str, Any],
    live_session_id: str,
    live_turn_id: str,
    wall_now: str,
) -> GateDecision:
    """Return structural evidence only; never backend or execution authority.

    Route metadata wiring, an RB-signed backend witness, a process-local
    monotonic deadline, checkpoint CAS, and atomic nonce consumption all remain
    trusted-loader work outside this dormant module.
    """
    artifacts = (pointer, journal, contract, envelope)
    if (
        any(not isinstance(item, ParsedAuthorityArtifact) for item in artifacts)
        or tuple(item.schema_version for item in artifacts)
        != (A_SCHEMA, B_SCHEMA, D_SCHEMA, C_SCHEMA)
    ):
        return _deny("STRICT_SCHEMA_INVALID")
    try:
        if not all(_artifact_integrity(item) for item in artifacts):
            return _deny("STRICT_SCHEMA_INVALID")
        signed_inputs = (pointer, journal, envelope)
        roots = tuple(
            TrustRoot(
                trust_root_id=item.verified_trust_root_id,
                key_id=item.verified_key_id,
                epoch=item.verified_root_epoch,
                public_key_base64=item.verified_public_key_base64,
                fingerprint_sha256=item.verified_root_fingerprint_sha256,
            )
            for item in signed_inputs
        )
        pointer_local = parse_activation_pointer(pointer.raw, roots[0])
        journal_local = parse_journal_record(journal.raw, roots[1])
        contract_local = parse_task_contract(contract.raw)
        envelope_local = parse_task_envelope(envelope.raw, roots[2])
        fresh_artifacts = (
            pointer_local,
            journal_local,
            contract_local,
            envelope_local,
        )
        if tuple(item.file_sha256 for item in fresh_artifacts) != tuple(
            item.file_sha256 for item in artifacts
        ):
            return _deny("STRICT_SCHEMA_INVALID")
        pointer, journal, contract, envelope = fresh_artifacts
        signed = (pointer, journal, envelope)
        fingerprints = tuple(
            item.verified_root_fingerprint_sha256 for item in signed
        )
        root_ids = tuple(item.verified_trust_root_id for item in signed)
        key_ids = tuple(item.verified_key_id for item in signed)
        epochs = tuple(item.verified_root_epoch for item in signed)
        if (
            any(not item for item in fingerprints + root_ids + key_ids)
            or len(set(fingerprints)) != 3
            or len(set(root_ids)) != 3
            or len(set(key_ids)) != 3
            or len(set(epochs)) != 3
        ):
            return _deny("TRUST_ROOT_OR_SIGNATURE_INVALID")

        a = pointer.value["payload"]
        b = journal.value["payload"]
        d = contract.value
        c = envelope.value["payload"]

        checkpoint = _checkpoint(authority_checkpoint)
        observed_root_pins = (
            {
                "trust_root_id": item.verified_trust_root_id,
                "key_id": item.verified_key_id,
                "epoch": item.verified_root_epoch,
                "fingerprint_sha256": item.verified_root_fingerprint_sha256,
            }
            for item in signed
        )
        if tuple(observed_root_pins) != (
            checkpoint["ra_root"],
            checkpoint["rj_root"],
            checkpoint["rt_root"],
        ):
            return _deny("TRUST_ROOT_OR_SIGNATURE_INVALID")
        if (
            _require_sha(trusted_rt_issuer_policy_sha256)
            != a["allowed_rt_issuer_policy_sha256"]
        ):
            return _deny("TRUST_ROOT_OR_SIGNATURE_INVALID")

        last_generation = checkpoint["last_pointer_generation"]
        last_pointer_sha = checkpoint["last_pointer_file_sha256"]
        if a["generation"] < checkpoint["operator_minimum_generation"]:
            return _deny("POINTER_ROLLBACK_OR_FORK")
        if last_generation == 0:
            pointer_chain_ok = (
                a["generation"] == 1
                and a["previous_pointer_sha256"] is None
                and pointer.file_sha256
                == checkpoint["operator_pinned_genesis_pointer_sha256"]
            )
        elif a["generation"] == last_generation:
            pointer_chain_ok = pointer.file_sha256 == last_pointer_sha
        else:
            pointer_chain_ok = (
                a["generation"] == last_generation + 1
                and a["previous_pointer_sha256"] == last_pointer_sha
            )
        if not pointer_chain_ok:
            return _deny("POINTER_ROLLBACK_OR_FORK")

        last_sequence = checkpoint["last_journal_sequence"]
        last_journal_sha = checkpoint["last_journal_head_file_sha256"]
        if last_sequence == 0:
            journal_chain_ok = (
                b["sequence"] == 1 and b["previous_record_sha256"] is None
            )
        elif b["sequence"] == last_sequence:
            journal_chain_ok = journal.file_sha256 == last_journal_sha
        else:
            journal_chain_ok = (
                b["sequence"] == last_sequence + 1
                and b["previous_record_sha256"] == last_journal_sha
            )
        if not journal_chain_ok:
            return _deny("ACTIVATION_JOURNAL_INVALID")

        if (
            a["activation_journal_head_file_sha256"] != journal.file_sha256
            or a["activation_id"] != b["activation_id"]
            or a["generation"] != b["generation"]
            or a["role_bundle_file_sha256"] != b["role_bundle_file_sha256"]
            or a["role_bundle_internal_sha256"] != b["role_bundle_internal_sha256"]
            or a["scope_evidence_file_sha256"] != b["scope_evidence_file_sha256"]
            or a["scope_evidence_internal_sha256"]
            != b["scope_evidence_internal_sha256"]
            or b["activated_role_codes"] != ["NV"]
        ):
            return _deny("ACTIVATION_JOURNAL_INVALID")

        role = a["activated_roles"][0]
        if role["agent_code"] != "NV" or c["agent_code"] != "NV" or d[
            "producer_agent_code"
        ] != "NV":
            return _deny("ROLE_NOT_ACTIVATED")
        if c["route_id"] not in role["route_ids"]:
            return _deny("ROUTE_NOT_ACTIVATED")
        if c["authority_required"] is not True:
            return _deny("AUTHORITY_REQUIRED")
        if (
            c["active_pointer_file_sha256"] != pointer.file_sha256
            or c["activation_journal_head_file_sha256"] != journal.file_sha256
            or c["activation_generation"] != a["generation"]
        ):
            return _deny("ACTIVATION_JOURNAL_INVALID")
        if c["task_contract_file_sha256"] != contract.file_sha256:
            return _deny("NORMALIZED_ARGS_MISMATCH")
        if c["logical_task_id"] != d["logical_task_id"]:
            return _deny("TURN_BINDING_MISMATCH")
        if c["normalized_args"] != d["source_request"]:
            return _deny("NORMALIZED_ARGS_MISMATCH")
        if c["tool_identifier"] != "read_file" or d["tool_identifier"] != "read_file":
            return _deny("STRICT_SCHEMA_INVALID")
        if (
            d["capability_id"] != "read_scoped_sources"
            or d["operation_class"] != "read_scoped"
            or d["resource"] != "domain:llm-wiki"
        ):
            return _deny("STRICT_SCHEMA_INVALID")
        if d["allowed_write_set"] != [] or d["mutation_class"] != "read_only":
            return _deny("WRITE_AUTHORITY_FORBIDDEN")
        if c["session_id"] != _require_id(live_session_id) or c[
            "turn_id"
        ] != _require_id(live_turn_id):
            return _deny("TURN_BINDING_MISMATCH")

        if not isinstance(live_backend_identity, dict) or set(
            live_backend_identity
        ) != {"kind", "task_id", "instance_token"}:
            return _deny("UNPROVABLE_AUTHORITY")
        backend = dict(live_backend_identity)
        if backend["kind"] != "local":
            return _deny("BACKEND_BINDING_MISMATCH")
        _require_id(backend["task_id"])
        _require_id(backend["instance_token"])
        if _domain(
            "thewon-bac-backend-identity/v1", _canonical(backend)
        ) != c["backend_identity_sha256"]:
            return _deny("BACKEND_BINDING_MISMATCH")

        now = _instant(wall_now)
        if not (
            _instant(b["written_at_wall"])
            <= _instant(a["activated_at_wall"])
            <= _instant(c["issued_at_wall"])
            <= _instant(c["not_before_wall"])
            <= now
            < _instant(c["expires_at_wall"])
            <= _instant(d["contract_expires_at_wall"])
            <= _instant(a["expires_at_wall"])
        ):
            return _deny("TURN_DEADLINE_INVALID")

        consume_material = {
            "nonce": c["nonce"],
            "envelope_id": c["envelope_id"],
            "active_pointer_file_sha256": pointer.file_sha256,
            "activation_journal_head_file_sha256": journal.file_sha256,
            "task_contract_file_sha256": contract.file_sha256,
        }
        return GateDecision(
            decision="STRUCTURALLY_VERIFIED_AWAITING_BACKEND_AND_NONCE",
            reasons=(
                "BACKEND_ATTESTATION_REQUIRED",
                "NONCE_ATOMIC_CONSUME_REQUIRED",
            ),
            consume_key_candidate=_domain(
                "thewon-bac-nonce-consume-key-candidate/v1",
                _canonical(consume_material),
            ),
        )
    except AuthoritySchemaError as exc:
        return _deny(exc.reason)
    except Exception:
        return _deny("STRICT_SCHEMA_INVALID")


__all__ = [
    "AuthoritySchemaError",
    "GateDecision",
    "ParsedAuthorityArtifact",
    "TrustRoot",
    "evaluate_nv_fd_read",
    "parse_activation_pointer",
    "parse_journal_record",
    "parse_task_contract",
    "parse_task_envelope",
]
