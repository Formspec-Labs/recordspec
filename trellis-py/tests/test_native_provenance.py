"""Native provenance records: the WOS-owned schema, TypeID and subset rules."""

from __future__ import annotations

import copy
from importlib import resources
from pathlib import Path

import cbor2
import pytest

from trellis_py import native_provenance, verify, verify_wos
from trellis_py.native_provenance import is_valid_record_type_id, parse_native_record

SOURCE_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "work-spec"
    / "schemas"
    / native_provenance.SCHEMA_FILE
)
VALID_ID = "acme_prov_01m53cmbc2e1grcyzxcehx4232"
RECORD = {
    "id": VALID_ID,
    "recordKind": "taskCreated",
    "timestamp": "2026-10-13T00:00:00Z",
    "auditLayer": "facts",
    "definitionVersion": "1",
    "data": {"taskId": "task"},
}


def _payload(record: dict) -> bytes:
    return cbor2.dumps({"record": record})


def _mutated(**changes) -> dict:
    record = copy.deepcopy(RECORD)
    for key, value in changes.items():
        if value is ...:
            del record[key]
        else:
            record[key] = value
    return record


def test_packaged_schema_is_byte_identical_to_the_owning_schema():
    packaged = resources.files("trellis_py").joinpath("schemas", native_provenance.SCHEMA_FILE)
    if not SOURCE_SCHEMA.exists():
        pytest.skip("standalone checkout: work-spec is not a sibling")
    assert packaged.read_bytes() == SOURCE_SCHEMA.read_bytes()


def test_format_checker_enforces_both_schema_formats():
    # `FormatChecker` silently skips unknown formats; construction asserts both.
    assert native_provenance._validator().format_checker.checkers.keys() >= {
        "date-time",
        "wos-record-typeid",
    }
    with pytest.raises(verify.VerifyError):
        parse_native_record(_payload(_mutated(timestamp="not-a-time")))


def test_a_valid_record_is_returned_unchanged():
    assert parse_native_record(_payload(RECORD)) == RECORD


@pytest.mark.parametrize(
    "record",
    [
        _mutated(timestamp=...),
        _mutated(auditLayer=...),
        _mutated(definitionVersion=...),
        _mutated(id="invalid"),
        _mutated(id=VALID_ID + "\n"),
        _mutated(id=VALID_ID.replace("prov", "other")),
        _mutated(id="acme_prov_" + "8" + VALID_ID[-25:]),
        _mutated(id="Acme_prov_" + VALID_ID[-26:]),
        _mutated(recordKind="futureUnknownKind"),
        _mutated(recordKind="caseCreated"),
        _mutated(unrecognizedStructuralField="must not disappear"),
        _mutated(timestamp="2026-10-13T00:00:00Z\n"),
        _mutated(data={"n": 2**63}),
        _mutated(data={"n": -(2**63) - 1}),
        _mutated(data={"n": float("nan")}),
        _mutated(data={"n": float("inf")}),
        _mutated(data={"n": -0.0}),
        _mutated(data={"n": b"bytes"}),
        _mutated(data={"n": cbor2.CBORTag(0, "2026-10-13T00:00:00Z")}),
        _mutated(data={1: "non-text key"}),
        _mutated(actorId={"wrong": "type"}),
    ],
)
def test_records_outside_the_owning_rules_are_refused(record):
    with pytest.raises(verify.VerifyError):
        parse_native_record(_payload(record))


def test_wrapper_and_encoding_rules():
    for payload in (
        cbor2.dumps(None),
        cbor2.dumps({}),
        cbor2.dumps({"record": None}),
        cbor2.dumps({"record": RECORD, "extra": True}),
        b"\xff",
        _payload(RECORD) + b"\x00",
        bytes.fromhex("a2") + cbor2.dumps("record") + cbor2.dumps(RECORD) + cbor2.dumps("record") + cbor2.dumps(RECORD),
    ):
        with pytest.raises(verify.VerifyError):
            parse_native_record(payload)


def test_depth_is_bounded():
    deep: object = None
    for _ in range(130):
        deep = [deep]
    with pytest.raises(verify.VerifyError):
        parse_native_record(_payload(_mutated(data={"deep": deep})))


def test_the_integer_range_is_signed_64_bit_inclusive():
    for edge in (2**63 - 1, -(2**63)):
        parse_native_record(_payload(_mutated(data={"n": edge})))


def test_record_type_id_rules():
    assert is_valid_record_type_id(VALID_ID)
    assert is_valid_record_type_id(VALID_ID.replace("prov", "x-acme-ledger"))
    assert not is_valid_record_type_id(VALID_ID.replace("prov", "x-acme"))
    assert not is_valid_record_type_id(VALID_ID.replace("prov", "case"))
    assert not is_valid_record_type_id(VALID_ID.replace("acme", "1acme"))
    assert not is_valid_record_type_id(VALID_ID.upper())
    assert not is_valid_record_type_id(None)
    # UUID version must be 7 and the variant RFC 4122.
    assert not is_valid_record_type_id("acme_prov_" + "0" * 26)


def test_a_missing_schema_refuses_every_record(monkeypatch):
    native_provenance._validator.cache_clear()
    monkeypatch.setattr(native_provenance, "SCHEMA_FILE", "absent.schema.json")
    try:
        with pytest.raises(verify.VerifyError):
            parse_native_record(_payload(RECORD))
    finally:
        native_provenance._validator.cache_clear()


def test_the_strict_and_publication_phases_both_report_invalid_native_records():
    vectors = sorted(VECTORS.glob("03[789]-source-content-publication-native-provenance-*"))
    assert len(vectors) == 3
    for directory in vectors:
        export_zip = (directory / "input-export.zip").read_bytes()
        publication = verify_wos.verify_source_content_publication(export_zip)
        strict = verify_wos.verify_export_zip(export_zip)
        for report in (publication.report, strict):
            assert "native_provenance_invalid" in [f.kind for f in report.wos_findings]
            assert not report.integrity_verified


VECTORS = Path(__file__).resolve().parents[2] / "fixtures" / "vectors" / "verify"
