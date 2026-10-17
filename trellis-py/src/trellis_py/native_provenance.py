"""Offline checks for original native WOS provenance records.

Python counterpart of `trellis-verify-wos/src/native_provenance.rs` and of
`wos_events::NativeProvenanceEvent::from_dcbor_slice`: the wrapped record must
sit inside the owning JSON/CBOR subset (signed 64-bit integers, finite floats,
depth 128, text keys, no tags or byte strings, unambiguous maps), carry a valid
record TypeID, and validate against the WOS-owned schema. The schema ships as
package data (`schemas/`); a test pins it byte-for-byte to
`work-spec/schemas/wos-native-provenance-event.schema.json`. A missing or
unusable schema or format checker refuses every record, as Rust does.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from importlib import resources
from typing import Any

import cbor2
from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

from trellis_py import verify as core
from trellis_py._cbor_strict import reject_duplicate_canonical_map_keys

SCHEMA_FILE = "wos-native-provenance-event.schema.json"
EVENT_TYPE = "wos.provenance.recorded"
_MAX_DEPTH = 128
_I64 = (-(2**63), 2**63 - 1)

_CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"
_RECORD_FAMILIES = {"prov", "gov", "ai", "assurance"}
_TENANT = re.compile(r"[a-z]([a-z0-9-]{0,61}[a-z0-9])?")
_VENDOR_LABEL = re.compile(r"[a-z][a-z0-9]*")


def is_valid_record_type_id(value: Any) -> bool:
    """Port of `stack_common_typeid::is_valid_record_type_id` (tenant_family_uuidv7)."""
    if not isinstance(value, str):
        return False
    parts = value.split("_")
    if len(parts) != 3:
        return False
    tenant, family, tail = parts
    if not _TENANT.fullmatch(tenant) or not _is_record_family(family):
        return False
    if len(tail) != 26 or any(c not in _CROCKFORD for c in tail):
        return False
    number = 0
    for c in tail:
        number = (number << 5) | _CROCKFORD.index(c)
    if number >> 128:  # two unused high bits of the 130-bit encoding
        return False
    raw = number.to_bytes(16, "big")
    return raw[6] >> 4 == 7 and raw[8] >> 6 == 0b10


def _is_record_family(family: str) -> bool:
    if family in _RECORD_FAMILIES:
        return True
    if not family.startswith("x-"):
        return False
    labels = family[2:].split("-")
    return len(labels) >= 2 and all(_VENDOR_LABEL.fullmatch(label) for label in labels)


def _ecma_pattern(validator, pattern, instance, schema):
    """JSON Schema `pattern` with ECMA `$` (end of text); Python's also matches before a final newline."""
    if validator.is_type(instance, "string") and not re.search(
        re.sub(r"\$$", r"\\Z", pattern), instance
    ):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_Validator = validators.extend(Draft202012Validator, {"pattern": _ecma_pattern})


@lru_cache(maxsize=1)
def _validator() -> Any:
    """The schema validator, or the reason this verifier cannot admit native records."""
    from rfc3339_validator import validate_rfc3339

    checker = FormatChecker()
    checker.checks("wos-record-typeid")(is_valid_record_type_id)
    # The library check accepts a trailing newline; RFC 3339 text does not.
    checker.checks("date-time")(
        lambda value: not isinstance(value, str)
        or (value.isascii() and not value.endswith("\n") and validate_rfc3339(value))
    )
    # `FormatChecker` silently skips formats it does not know: both must be active.
    missing = {"date-time", "wos-record-typeid"} - set(checker.checkers)
    if missing:
        raise RuntimeError(f"format checker lacks {sorted(missing)}")
    schema = json.loads(resources.files("trellis_py").joinpath("schemas", SCHEMA_FILE).read_text("utf-8"))
    _Validator.check_schema(schema)
    return _Validator(schema, format_checker=checker)


def _in_subset(value: Any, depth: int) -> bool:
    """Owning JSON/CBOR subset: text keys, no tags/bytes/undefined, i64, finite non-negative-zero floats."""
    if depth > _MAX_DEPTH:
        return False
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return _I64[0] <= value <= _I64[1]
    if isinstance(value, float):
        return math.isfinite(value) and not (value == 0.0 and math.copysign(1.0, value) < 0)
    if isinstance(value, list):
        return all(_in_subset(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _in_subset(v, depth + 1) for k, v in value.items())
    return False


def parse_native_record(payload: bytes) -> dict[str, Any]:
    """The validated original record of a wrapped native payload.

    Raises :class:`trellis_py.verify.VerifyError` for anything Rust refuses
    (`NativeProvenanceEvent::from_dcbor_slice`).
    """
    try:
        reject_duplicate_canonical_map_keys(payload)
        wrapper = cbor2.loads(payload)
    except Exception as exc:  # noqa: BLE001  (CborStrictError or a CBOR decode error)
        raise core.VerifyError("invalid native provenance CBOR") from exc
    if not _in_subset(wrapper, 0):
        raise core.VerifyError("native provenance value outside the owning subset")
    record = wrapper.get("record") if isinstance(wrapper, dict) else None
    if not isinstance(record, dict):
        raise core.VerifyError("record must be an object")
    if not isinstance(record.get("recordKind"), str):
        raise core.VerifyError("native provenance requires an explicit recognized recordKind")
    if not is_valid_record_type_id(record.get("id")):
        raise core.VerifyError("native provenance record identifier is invalid")
    try:
        _validator().validate(wrapper)
    except Exception as exc:  # noqa: BLE001
        # Report the failure class, never an original answer or diagnostic value.
        raise core.VerifyError(f"invalid native provenance payload: {type(exc).__name__}") from exc
    return record
