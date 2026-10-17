"""Source-content publication (ADR 0163): catalog readers, exact joins, phase selection.

End-to-end cross-runtime parity is asserted by `trellis_py.conformance` against
`verify/028..036`; these tests cover the readers, the joins and the report API
on the same committed bytes.
"""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import cbor2
import pytest

from trellis_py import native_provenance, source_content, verify, verify_wos
from trellis_py._cbor_canonical import encode_canonical_cbor_value

VECTORS = Path(__file__).resolve().parents[2] / "fixtures" / "vectors" / "verify"


def _zip(directory: str) -> bytes:
    return (VECTORS / directory / "input-export.zip").read_bytes()


PROTECTED_INTAKE = _zip("028-source-content-publication-protected-intake")
TASK_AND_ORIGINAL = _zip("033-source-content-publication-task-and-original")


def _catalog(export_zip: bytes, member: str) -> list[dict]:
    return cbor2.loads(verify.parse_export_zip(export_zip)[member])


TASK_ROW = _catalog(TASK_AND_ORIGINAL, "062-signature-affirmations.cbor")[0]
ORIGINAL_ROW = _catalog(TASK_AND_ORIGINAL, "063-intake-handoffs.cbor")[0]


def _encoded(value) -> bytes:
    return encode_canonical_cbor_value(value)


# --- phase selection and report ----------------------------------------------------


def test_publication_admits_what_the_strict_phase_refuses():
    publication = verify_wos.verify_source_content_publication(PROTECTED_INTAKE)
    strict = verify_wos.verify_export_zip(PROTECTED_INTAKE)
    assert publication.publication_admitted
    assert publication.findings == []
    assert publication.blocking_reasons == []
    assert not strict.integrity_verified
    assert [f.kind for f in strict.wos_findings] == ["protected_response_unavailable"]


def test_publication_report_exposes_substrate_findings_and_blocking_reasons():
    publication = verify_wos.verify_source_content_publication(
        _zip("030-source-content-publication-binding-mismatch")
    )
    assert not publication.publication_admitted
    assert publication.substrate.integrity_verified
    assert [f.kind for f in publication.findings] == ["protected_response_native_binding_mismatch"]
    assert publication.blocking_reasons[0] == "domain_admissibility"
    assert publication.blocking_reasons[1].startswith("protected_response_native_binding_mismatch: ")


def test_publication_keeps_substrate_and_catalog_failures_of_the_strict_phase():
    tampered = _zip("014-export-006-signature-row-mismatch")
    ordinary = verify_wos.verify_export_zip(tampered)
    publication = verify_wos.verify_source_content_publication(tampered)
    assert not publication.publication_admitted
    assert publication.substrate == ordinary.trellis
    assert publication.findings == ordinary.wos_findings


def test_publication_rejects_an_unreadable_archive():
    publication = verify_wos.verify_source_content_publication(b"not a ZIP")
    assert not publication.publication_admitted
    assert not publication.substrate.structure_verified


def test_task_bundle_is_admitted_only_by_the_publication_phase():
    assert verify_wos.verify_source_content_publication(TASK_AND_ORIGINAL).publication_admitted
    strict = verify_wos.verify_export_zip(TASK_AND_ORIGINAL)
    assert [f.kind for f in strict.wos_findings] == [
        "source_task_content_unavailable",
        "protected_response_unavailable",
    ]


# --- protected Response locator ----------------------------------------------------


def _locator() -> dict:
    return copy.deepcopy(ORIGINAL_ROW["protected_response"])


def test_locator_accepts_the_closed_shape():
    parsed = source_content.parse_protected_response(_locator())
    assert parsed["response_id"] == ORIGINAL_ROW["protected_response"]["response_id"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(extra=1),
        lambda m: m.pop("key_bag"),
        lambda m: m.update(version=2),
        lambda m: m.update(version=True),
        lambda m: m.update(original_byte_length=0),
        lambda m: m.update(original_byte_length=1_048_577),
        lambda m: m.update(nonce=b"\x00" * 11),
        lambda m: m.update(context_key=b""),
        lambda m: m.update(context_key=b"\x00" * 65),
        lambda m: m.update(response_id=" "),
        lambda m: m.update(response_hash="md5:00"),
        lambda m: m.update(key_bag=[]),
        lambda m: m.update(content_hash=b"\x00" * 31),
    ],
    ids=[
        "unknown-field", "missing-field", "version", "bool-version", "empty", "oversized",
        "nonce", "short-context-key", "long-context-key", "blank-id", "hash-prefix",
        "key-bag-shape", "digest-size",
    ],
)
def test_locator_refuses_anything_outside_the_closed_shape(mutate):
    value = _locator()
    mutate(value)
    with pytest.raises(verify.VerifyError):
        source_content.parse_protected_response(value)


# --- Source task rows --------------------------------------------------------------


def _task() -> dict:
    return copy.deepcopy(TASK_ROW)


def test_task_row_accepts_the_closed_mixed_family_shape():
    task = source_content.parse_source_task(_task())
    assert task["family"] == "mixed-v2"
    assert task["task_proof"]["protected_package"]["family"] == "mixed-v2"


def _drop_original(row):
    del row["task_proof"]["original_selection_hash"]


def _local_family_with_original(row):
    row["family"] = "native-local-v3"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(extra=1),
        lambda r: r.update(kind="other"),
        lambda r: r.update(family="future-v9"),
        lambda r: r.update(signed_payload_digest_algorithm="sha-512"),
        lambda r: r.update(task_id=" "),
        lambda r: r.update(task_ref="a\x00b"),
        lambda r: r.update(response_id="foreign"),
        lambda r: r.update(canonical_event_hash=b"\x00" * 32),
        lambda r: r["task_proof"].update(admission="selfAdmitted"),
        lambda r: r["task_proof"].update(extra=1),
        lambda r: r["task_proof"]["protected_package"].update(family="native-v1"),
        lambda r: r["task_proof"]["protected_package"].update(witness_sha256=b"\x00" * 32),
        lambda r: r["task_proof"]["protected_package"].update(source_binding_hash=b"\x00" * 32),
        lambda r: r["task_proof"]["protected_package"]["key_bag"].update(entries=[]),
        lambda r: r["task_proof"]["protected_package"]["key_bag"]["entries"][0].update(suite=2),
        _drop_original,
        _local_family_with_original,
    ],
    ids=[
        "unknown-field", "kind", "family", "digest-algorithm", "blank-text", "control-char",
        "response-binding", "anchor-binding", "admission", "proof-unknown-field",
        "package-family", "package-witness", "package-binding", "package-empty-wraps",
        "package-wrap-suite", "mixed-needs-original", "local-forbids-original",
    ],
)
def test_task_row_refuses_anything_outside_the_closed_exact_shape(mutate):
    row = _task()
    mutate(row)
    with pytest.raises(verify.VerifyError):
        source_content.parse_source_task(row)


def test_signature_catalog_splits_legacy_rows_from_task_rows():
    legacy, tasks = source_content.read_signature_catalog(_encoded([TASK_ROW]))
    assert legacy == [] and len(tasks) == 1
    with pytest.raises(verify.VerifyError):
        source_content.read_signature_catalog(_encoded([{"canonical_event_hash": b"\x00" * 32}]))


def test_catalogs_refuse_duplicate_map_keys_anywhere():
    # 0xa2: a map of two pairs sharing the key "a".
    ambiguous = bytes.fromhex("81a2616101616102")
    with pytest.raises(verify.VerifyError):
        source_content.read_signature_catalog(ambiguous)
    with pytest.raises(verify.VerifyError):
        source_content.read_intake_catalog(ambiguous)


def test_catalogs_are_bounded():
    with pytest.raises(verify.VerifyError):
        source_content.read_signature_catalog(b"\x00" * (source_content.MAX_CATALOG_BYTES + 1))
    rows = [_task() for _ in range(source_content.MAX_ROWS + 1)]
    with pytest.raises(verify.VerifyError):
        source_content.read_signature_catalog(_encoded(rows))


# --- intake rows and the original-context join ------------------------------------


def test_intake_row_carries_exactly_one_response_content_form():
    inline = {**ORIGINAL_ROW, "response_bytes": b"{}"}
    for row in (inline, {k: v for k, v in ORIGINAL_ROW.items() if k != "protected_response"}):
        with pytest.raises(verify.VerifyError):
            source_content.read_intake_catalog(_encoded([row]))
    [entry] = source_content.read_intake_catalog(_encoded([ORIGINAL_ROW]))
    assert entry["response_bytes"] is None and entry["protected_response"] is not None


def test_original_context_proof_is_closed_and_bounded():
    proof = ORIGINAL_ROW["original_context_proof"]
    assert source_content.parse_original_context_proof(copy.deepcopy(proof))
    for broken in (
        {**proof, "extra": 1},
        {k: v for k, v in proof.items() if k != "context_instance"},
        {**proof, "context_instance": " "},
        {**proof, "package_record_hash": b"\x00" * 31},
    ):
        with pytest.raises(verify.VerifyError):
            source_content.parse_original_context_proof(broken)


def test_original_context_proof_requires_a_protected_original():
    inline = {
        "intake_event_hash": ORIGINAL_ROW["intake_event_hash"],
        "case_created_event_hash": ORIGINAL_ROW["case_created_event_hash"],
        "handoff": ORIGINAL_ROW["handoff"],
        "response_bytes": b"{}",
        "original_context_proof": ORIGINAL_ROW["original_context_proof"],
    }
    entries = source_content.read_intake_catalog(_encoded([inline]))
    with pytest.raises(verify.VerifyError):
        source_content.protected_originals(b"", entries)


def test_original_context_join_names_the_failing_association():
    [original] = source_content.protected_originals(
        b"", source_content.read_intake_catalog(_encoded([ORIGINAL_ROW]))
    )
    task = source_content.parse_source_task(_task())
    assert source_content.original_context_error(original, [task]) is None
    assert source_content.original_context_error(original, []) == "original context task absent"
    assert "ambiguous" in source_content.original_context_error(original, [task, task])
    foreign = copy.deepcopy(original)
    foreign["original_context_proof"]["package_record_hash"] = b"\x00" * 32
    assert "differs" in source_content.original_context_error(foreign, [task])
    task["task_proof"]["protected_package"] = None
    assert "package absent" in source_content.original_context_error(original, [task])


# --- exact native task join --------------------------------------------------------


def _native(event_hash: bytes, record: dict) -> SimpleNamespace:
    return SimpleNamespace(
        event_type=native_provenance.EVENT_TYPE,
        canonical_event_hash=event_hash,
        payload_ref_inline=cbor2.dumps({"record": record}),
        payload_ref_external=False,
    )


_CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"


def _typeid(n: int) -> str:
    """A valid `acme_prov_<uuidv7>` record TypeID, distinct per `n`."""
    raw = bytearray(n.to_bytes(6, "big") + b"\x70\x00\x80" + b"\x00" * 7)
    number = int.from_bytes(raw, "big")
    tail = "".join(_CROCKFORD[(number >> (5 * i)) & 31] for i in reversed(range(26)))
    return f"acme_prov_{tail}"


def _stamped(record: dict) -> dict:
    return {**record, "timestamp": "2026-10-13T00:00:00Z", "auditLayer": "facts", "definitionVersion": "1"}


def _records(task: dict) -> tuple[dict, dict]:
    created, completed = _bare_records(task)
    return _stamped(created), _stamped(completed)


def _bare_records(task: dict) -> tuple[dict, dict]:
    created = {
        "id": task["task_created_record_id"],
        "recordKind": "taskCreated",
        "data": {
            "taskId": task["task_id"],
            "details": {"taskRef": task["task_ref"], "assignedActor": task["actor_ref"]},
        },
    }
    completed = {
        "id": task["task_completed_record_id"],
        "recordKind": "taskCompleted",
        "actorId": task["actor_ref"],
        "data": {"taskId": task["task_id"], "details": {"artifactId": task["artifact_id"]}},
    }
    return created, completed


def _join_error(task: dict, events: list) -> str | None:
    return source_content.native_join_error(task, source_content.native_task_index(events, {}))


def _joined_events(task: dict, created: dict, completed: dict) -> list:
    return [
        _native(task["task_created_event_hash"], created),
        _native(task["canonical_event_hash"], completed),
    ]


def test_native_join_is_exact():
    task = source_content.parse_source_task(_task())
    created, completed = _records(task)
    assert _join_error(task, _joined_events(task, created, completed)) is None


def test_native_join_refuses_each_inexact_association():
    task = source_content.parse_source_task(_task())
    created, completed = _records(task)

    def case(mutate):
        c, d = copy.deepcopy(created), copy.deepcopy(completed)
        mutate(c, d)
        return _join_error(task, _joined_events(task, c, d))

    assert case(lambda c, d: c["data"]["details"].update(taskRef="other")) is not None
    assert case(lambda c, d: d.update(actorId="someone-else")) is not None
    assert case(lambda c, d: d["data"]["details"].update(artifactId="other")) is not None
    assert case(lambda c, d: c["data"]["details"].update(assignedActor="someone-else")) is not None
    assert case(lambda c, d: c["data"]["details"].update(assignedActor=None)) is not None
    assert case(lambda c, d: c.update(id=_typeid(1))) is not None
    assert _join_error(task, list(reversed(_joined_events(task, created, completed)))) is not None


def test_native_join_refuses_a_second_creation_or_completion_of_the_same_task():
    task = source_content.parse_source_task(_task())
    created, completed = _records(task)
    events = _joined_events(task, created, completed)
    assert _join_error(task, events + [_native(b"\x01" * 32, created)]) is not None
    assert _join_error(task, events + [_native(b"\x02" * 32, completed)]) is not None


def test_native_join_ignores_other_tasks_but_not_unreadable_records():
    task = source_content.parse_source_task(_task())
    created, completed = _records(task)
    other = copy.deepcopy(created)
    other["data"]["taskId"] = "another-task"
    events = _joined_events(task, created, completed)
    assert _join_error(task, [_native(b"\x03" * 32, other)] + events) is None
    broken = SimpleNamespace(
        event_type=native_provenance.EVENT_TYPE,
        canonical_event_hash=b"\x04" * 32,
        payload_ref_inline=cbor2.dumps({"record": {"id": b"bytes-are-outside-the-subset"}}),
        payload_ref_external=False,
    )
    assert _join_error(task, [broken] + events) == "invalid native task record"


# --- text bounds and legacy rows follow Rust ---------------------------------------


def test_text_bounds_count_utf8_bytes():
    locator = _locator()
    locator["response_id"] = "é" * 512  # 1024 bytes
    source_content.parse_protected_response(locator)
    locator["response_id"] = "é" * 513  # 1026 bytes, 513 characters
    with pytest.raises(verify.VerifyError):
        source_content.parse_protected_response(locator)
    task = _task()
    task["task_id"] = "é" * 2049  # 4098 bytes
    with pytest.raises(verify.VerifyError):
        source_content.parse_source_task(task)


def test_blank_uses_the_unicode_white_space_rust_trims():
    locator = _locator()
    locator["response_ref"] = "\u3000\u00a0"
    with pytest.raises(verify.VerifyError):
        source_content.parse_protected_response(locator)


LEGACY_ROW = _catalog(
    _zip("014-export-006-signature-row-mismatch"), "062-signature-affirmations.cbor"
)[0]


def _legacy_error(**changes) -> bool:
    row = {**copy.deepcopy(LEGACY_ROW), **changes}
    for key in [k for k, v in row.items() if v is ...]:
        del row[key]
    try:
        source_content.read_signature_catalog(cbor2.dumps([row]))
    except verify.VerifyError:
        return True
    return False


def test_legacy_rows_are_read_as_rust_reads_them():
    assert not _legacy_error()
    assert _legacy_error(signing_intent=5)  # optional text is text or null, never coerced
    assert _legacy_error(signing_intent=[])
    assert not _legacy_error(signing_intent=None)
    assert _legacy_error(formspec_response_ref=...)  # no alias for the response ref
    assert _legacy_error(source_response_ref=LEGACY_ROW["formspec_response_ref"], formspec_response_ref=...)
    assert _legacy_error(consent_reference={"n": float("nan")})  # must re-encode canonically
    assert _legacy_error(identity_binding={"n": -0.0})
