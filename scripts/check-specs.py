#!/usr/bin/env python3
"""Lint normalized Trellis specification documents."""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path


ROOT = Path(os.environ.get("TRELLIS_LINT_ROOT", Path(__file__).resolve().parents[1]))
REAL_ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "specs"
FIXTURES = ROOT / "fixtures" / "vectors"
DECLARATIONS = ROOT / "fixtures" / "declarations"

TOP_LEVEL_SPECS = [
    SPECS / "trellis-agreement.md",
    SPECS / "trellis-core.md",
    SPECS / "trellis-operational-companion.md",
    SPECS / "wos-trellis-verification.md",
    SPECS / "trellis-requirements-matrix.md",
    SPECS / "cross-reference-map.md",
    SPECS / "README.md",
]

FORBIDDEN_PATTERNS = [
    (re.compile(r"signature field zeroed", re.IGNORECASE), "custom signature zero-fill prose"),
    (re.compile(r"zeroed to (?:a )?fixed-length", re.IGNORECASE), "custom signature zero-fill prose"),
    (re.compile(r"JSON Canonicalization Scheme|RFC 8785", re.IGNORECASE), "JCS canonicalization reference"),
    (re.compile(r"Trellis Core v0\.1"), "stale Core version"),
    (re.compile(r"Trellis Operational Companion v0\.1|Operational Companion v0\.1"), "stale Companion version"),
    (re.compile(r"\bforthcoming\b", re.IGNORECASE), "forthcoming companion language"),
    (re.compile(r"three spec documents", re.IGNORECASE), "old document-count language"),
    (re.compile(r"specs/(?:core|trust|export|projection|operations|forms|workflow|assurance)/"), "unarchived superseded spec path"),
]

PROFILE_ALLOWED_CONTEXT = re.compile(
    r"Profile A/B/C|Profile [A-F]|Profile-Namespace|Profile\" namespace|"
    r"Canonical CBOR profile|CBOR profile|encoding profile|signature profile|signing profile|"
    r"Core profile|Offline profile|Reader-Held profile|Delegated-Compute profile|"
    r"Disclosure profile|User-Held profile|Respondent-History profile|"
    r"legacy .*Profile|formerly \"Profile|renamed \"Conformance Classes\"|not profiles|profile\" letter|profile letter|"
    r"profile identifier",
    re.IGNORECASE,
)

PHASE_1_INVARIANTS = set(range(1, 16))  # #1..#15

GENERATOR_ALLOWED_IMPORTS = set(sys.stdlib_module_names) | {"cryptography", "cbor2"}

# Recognized vector operation directories under fixtures/vectors/. Wave-1
# extends the original four ops with `projection` and `shred` to support
# O-3 projection conformance vectors.
VECTOR_OPS = ("append", "verify", "export", "tamper", "projection", "shred")

# Normative `tamper_kind` values per Core §19.1 and domain validator specs.
# Every `tamper` vector's `[expected.report].tamper_kind` MUST be one of these.
# New Core categories MUST land in Core §19.1 first. Domain categories MUST
# land in their domain validator spec first. Existing WOS values remain here
# while fixture manifests still use the single `tamper_kind` field.
TAMPER_KIND_ENUM = frozenset({
    "signature_invalid",
    "hash_mismatch",
    "prev_hash_break",
    "event_truncation",
    "event_reorder",
    "timestamp_order_violation",          # ADR 0069 D-3.
    "rescission_terminality_violation",   # WOS-TV-002; legacy TR-CORE-171.
    "clock_calendar_mismatch",            # WOS-TV-003; legacy TR-CORE-173.
    "legacy_timestamp_format",            # ADR 0069 D-2.1 — bare uint rejected at decode.
    "timestamp_nanos_out_of_range",       # ADR 0069 D-2.1 — nanos component exceeds CDDL bound.
    "head_checkpoint_digest_mismatch",
    "malformed_cose",
    "scope_mismatch",
    "registry_digest_mismatch",
    "state_continuity_mismatch",
    "attestation_insufficient",
    "posture_declaration_digest_mismatch",
    "attachment_manifest_digest_mismatch",
    "signature_catalog_digest_mismatch",  # WOS-TV-004.
    "intake_handoff_catalog_digest_mismatch",  # WOS-TV-007.
    "key_class_mismatch",                # Core §8.7.3 step 4 (ADR 0006).
    "key_entry_attributes_shape_mismatch",   # Core §8.7.2 (ADR 0006).
    # Append idempotency (Core §6.1 / §17 / §19.1; invariant #13). Verifier
    # detection of structural reject + same-key/different-payload conflict.
    # Fixtures: tamper/035 + tamper/036.
    "idempotency_key_length_invalid",        # Core §6.1 / §17.2 / §17.5; TR-CORE-158.
    "idempotency_key_payload_mismatch",      # Core §17.3 clause 3 / §17.5 (verifier-side); TR-CORE-160.
    # Erasure-evidence (Core §19.1 / §19 step 6b; ADR 0005). Phase-1
    # reserved enum values; corpus vectors land in the ADR 0005 execution
    # train (TODO item #3). The corpus is a subset of the enum (see
    # `test_enum_matches_corpus`), so reserved-without-fixture is allowed.
    "erasure_key_class_registry_mismatch",
    "erasure_key_class_payload_conflict",
    "erasure_destroyed_at_after_host",
    "erasure_destroyed_at_conflict",
    "post_erasure_use",
    "post_erasure_wrap",
    "erasure_evidence_catalog_digest_mismatch",
    # Erasure-evidence optional-catalog localization labels (Core §19.1 /
    # §19 step 6b optional manifest catalog; ADR 0005 §"Export manifest
    # catalog"). Emitted by `verify_erasure_evidence_catalog` for the
    # non-digest failure surface; reserved per the corpus-subset rule.
    "erasure_evidence_catalog_invalid",
    "erasure_evidence_catalog_duplicate_event",
    "erasure_evidence_catalog_event_unresolved",
    "erasure_evidence_catalog_event_type_mismatch",
    "erasure_evidence_catalog_mismatch",
    # Certificate-of-completion (Core §19.1 / §19 step 6c; ADR 0007). Phase-1
    # reserved enum values; corpus vectors land in the ADR 0007 execution
    # train (TODO item #4). The corpus is a subset of the enum, so
    # reserved-without-fixture is allowed.
    "certificate_chain_summary_mismatch",
    "certificate_covered_claim_unknown",
    "certificate_enum_extension_unknown",
    "certificate_id_collision",
    "presentation_artifact_attachment_missing",
    "presentation_artifact_content_mismatch",
    "signing_event_unresolved",
    "signing_event_timestamp_mismatch",
    "response_ref_mismatch",
    "malformed_response_digest",  # TR-CORE-175; tamper/052 (review F2 fail-closed).
    "certificate_catalog_digest_mismatch",
    # Certificate-of-completion optional-catalog localization labels
    # (Core §19.1 / §19 step 6c optional manifest catalog; ADR 0007 §"Export
    # manifest catalog"). Emitted by `verify_certificate_catalog` for the
    # non-digest failure surface; reserved per the corpus-subset rule.
    "certificate_catalog_invalid",
    "certificate_catalog_duplicate_event",
    "certificate_catalog_event_unresolved",
    "certificate_catalog_event_type_mismatch",
    "certificate_catalog_mismatch",
    # User-content-attestation primitive (Core §19.1 / §19 step 6d; ADR 0010).
    # Phase-1 reserved enum values; corpus vectors land alongside the ADR 0010
    # train (`append/036..039` + `tamper/028..034`), with rotation-grace
    # boundary coverage added at `tamper/043`. The corpus is a subset of the
    # enum, so reserved-without-fixture is allowed.
    "user_content_attestation_timestamp_mismatch",
    "user_content_attestation_intent_malformed",
    "user_content_attestation_chain_position_mismatch",
    "user_content_attestation_identity_required",
    "user_content_attestation_identity_unresolved",
    "user_content_attestation_identity_subject_mismatch",
    "user_content_attestation_identity_temporal_inversion",
    "user_content_attestation_signature_invalid",
    "user_content_attestation_key_not_active",
    "user_content_attestation_id_collision",
    "user_content_attestation_operator_in_user_slot",
    "interop_sidecar_phase_1_locked",  # ADR 0008 Phase-1 lock-off (3 still-locked kinds).
    # Interop-sidecar dispatched-verifier failure surfaces (Core §19.1 / §18.3a;
    # ADR 0008 §"Phase-1 verifier obligation"). Wave 25 activates the
    # `c2pa-manifest@v1` kind: path-(b) digest-binds only, no `source_ref`
    # resolution. Fixtures: tamper/037..040 + tamper/044 (5 of 6 —
    # `interop_sidecar_path_invalid` is Rust unit-test-only: predicate +
    # `verify_interop_sidecars` dispatch). The corpus is a subset of the
    # enum, so reserved-without-fixture is allowed (R13 corpus-subset rule).
    "interop_sidecar_content_mismatch",          # TR-CORE-163; tamper/037.
    "interop_sidecar_kind_unknown",              # TR-CORE-164; tamper/038.
    "interop_sidecar_unlisted_file",             # TR-CORE-165; tamper/039.
    "interop_sidecar_derivation_version_unknown",# TR-CORE-166; tamper/040.
    "interop_sidecar_path_invalid",              # TR-CORE-167; trellis-verify unit tests (no tamper ZIP).
    "interop_sidecar_missing",                   # TR-CORE-168; tamper/044.
    # Supersession graph (Core §19 step 6e; ADR 0066). Runtime verifier
    # coverage lands with the TR-CORE-170 export/tamper vectors.
    "supersession_graph_unbound",
    "supersession_graph_invalid",
    "supersession_graph_head_mismatch",
    "supersession_graph_linkage_mismatch",
    "supersession_graph_cycle",
    "supersession_predecessor_checkpoint_mismatch",
})


def parse_invariants_cell(cell: str) -> set[int]:
    """Parse an Invariant-column cell. Handles '#5', '#1, #4', '1', '—'/'-' → empty."""
    result: set[int] = set()
    for m in re.finditer(r"#?(\d+)", cell):
        result.add(int(m.group(1)))
    return result


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def relpath(path: Path) -> Path:
    """Return a display path relative to ROOT when possible."""
    try:
        return path.relative_to(ROOT)
    except ValueError:
        return path


def line_for(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def core_headings() -> dict[int, str]:
    headings: dict[int, str] = {}
    heading_pattern = re.compile(r"^## ([0-9]+)\.?\s+(.+)$", re.MULTILINE)
    for match in heading_pattern.finditer(read(SPECS / "trellis-core.md")):
        headings[int(match.group(1))] = match.group(2).strip()
    return headings


def companion_headings() -> dict[int, str]:
    """Mirror of core_headings() for trellis-operational-companion.md.

    Phase-1 Companion numbers `## N. Title` headings from §5 through §29.
    Higher-numbered Phase-2+ sections, when added, will slot in naturally.
    Appendix headings (`## A.N`) use alphabetic prefixes and are handled by
    companion_cddl_blocks() separately.
    """
    headings: dict[int, str] = {}
    heading_pattern = re.compile(r"^## ([0-9]+)\.?\s+(.+)$", re.MULTILINE)
    for match in heading_pattern.finditer(read(SPECS / "trellis-operational-companion.md")):
        headings[int(match.group(1))] = match.group(2).strip()
    return headings


def matrix_ids() -> list[str]:
    text = read(SPECS / "trellis-requirements-matrix.md")
    return re.findall(r"^\| (TR-(?:CORE|OP)-[0-9]{3}) \|", text, re.MULTILINE)


def tr_core_ids() -> list[str]:
    """Subset of matrix_ids() restricted to core-scope rows."""
    return [row_id for row_id in matrix_ids() if row_id.startswith("TR-CORE-")]


def tr_op_ids() -> list[str]:
    """Subset of matrix_ids() restricted to operational-scope rows."""
    return [row_id for row_id in matrix_ids() if row_id.startswith("TR-OP-")]


def matrix_rows() -> list[dict]:
    """Return parsed matrix rows.

    Matrix columns: Scope | Invariant | Requirement | Rationale | Verification | Legacy | Notes.
    `requirement`, `rationale`, and `notes` are exposed so spec-cross-ref row
    resolution (R6) can scan them for `Core §N` / `Companion §N` citations.
    """
    text = read(SPECS / "trellis-requirements-matrix.md")
    row_pattern = re.compile(r"^\| (TR-(?:CORE|OP)-[0-9]{3}) \|(.+)$", re.MULTILINE)
    rows = []
    for m in row_pattern.finditer(text):
        row_id = m.group(1)
        cells = [c.strip() for c in m.group(2).split("|")]
        rows.append({
            "id": row_id,
            "invariant": cells[1] if len(cells) > 1 else "—",
            "requirement": cells[2] if len(cells) > 2 else "",
            "rationale": cells[3] if len(cells) > 3 else "",
            "verification": cells[4] if len(cells) > 4 else "",
            "notes": cells[6] if len(cells) > 6 else "",
        })
    return rows


def testable_row_ids() -> set[str]:
    """Return IDs of matrix rows where Verification contains 'test-vector'."""
    return {r["id"] for r in matrix_rows() if "test-vector" in r["verification"]}


def projection_rebuild_drill_row_ids() -> set[str]:
    """Return TR-OP rows where Verification contains 'projection-rebuild-drill'."""
    return {
        r["id"]
        for r in matrix_rows()
        if r["id"].startswith("TR-OP-")
        and "projection-rebuild-drill" in r["verification"]
    }


def vector_manifests() -> list[tuple[Path, dict]]:
    """Return (manifest_path, parsed_toml) for every vector manifest under fixtures/vectors/."""
    import tomllib

    manifests = []
    if not FIXTURES.exists():
        return manifests
    for op_dir in VECTOR_OPS:
        op_path = FIXTURES / op_dir
        if not op_path.exists():
            continue
        for vector_dir in sorted(op_path.iterdir()):
            if not vector_dir.is_dir():
                continue
            manifest_path = vector_dir / "manifest.toml"
            if not manifest_path.exists():
                continue
            with manifest_path.open("rb") as f:
                manifests.append((manifest_path, tomllib.load(f)))
    return manifests


def manifest_op_from_path(manifest_path: Path) -> str | None:
    """Return the fixtures/vectors/<op>/ segment for a manifest path."""
    try:
        rel = manifest_path.parent.relative_to(FIXTURES)
    except ValueError:
        return None
    if not rel.parts:
        return None
    return rel.parts[0]


def derived_sections_for_tr_core(row_ids: list[str]) -> set[str]:
    """Scan Core prose to find which §N heading each TR-CORE-XXX anchor lives under."""
    core_text = read(SPECS / "trellis-core.md")
    # Matches headings like "## 6. Event Format" or "## §6 Event Format" or "### 6.2 Foo"
    heading_pattern = re.compile(r"^(#{2,3})\s+(?:§\s*)?([0-9]+(?:\.[0-9]+)*)\.?\s+(.+)$", re.MULTILINE)
    sections: list[tuple[int, str]] = []
    for m in heading_pattern.finditer(core_text):
        sections.append((m.start(), f"§{m.group(2)}"))
    derived: set[str] = set()
    for row_id in row_ids:
        anchor = core_text.find(row_id)
        if anchor == -1:
            continue
        current_section = None
        for start, label in sections:
            if start <= anchor:
                current_section = label
            else:
                break
        if current_section:
            derived.add(current_section)
    return derived


def derived_companion_sections_for_tr_op(
    row_ids: list[str], *, text: str | None = None
) -> set[str]:
    """Mirror of derived_sections_for_tr_core over the Operational Companion.

    Scans Companion prose to find which §N heading each TR-OP-XXX anchor
    lives under. Used by the declared-coverage round-trip rule (R5).

    `text` is exposed for tests that want to pass a synthetic companion
    document; real callers pass None and we read the canonical file.
    """
    companion_text = text if text is not None else read(SPECS / "trellis-operational-companion.md")
    # Strip the traceability appendix before scanning: it lists every TR-OP row
    # by ID, so leaving it in would make every TR-OP resolve to that appendix's
    # heading (drowning the real prose anchor). We tolerate label-text drift in
    # the appendix title — as long as the appendix still starts with a top-level
    # `## <letter>. Traceability` heading we'll find it.
    traceability_appendix = re.search(
        r"^## [A-Z]\.\s+Traceability\b", companion_text, re.MULTILINE
    )
    if traceability_appendix:
        companion_text = companion_text[: traceability_appendix.start()]
    heading_pattern = re.compile(
        r"^(#{2,4})\s+(?:§\s*)?([0-9]+(?:\.[0-9]+)*|[A-Z]\.[0-9]+(?:\.[0-9]+)*)\.?\s+(.+)$",
        re.MULTILINE,
    )
    sections: list[tuple[int, str]] = []
    for m in heading_pattern.finditer(companion_text):
        sections.append((m.start(), f"§{m.group(2)}"))
    derived: set[str] = set()
    for row_id in row_ids:
        for anchor in (m.start() for m in re.finditer(re.escape(row_id), companion_text)):
            current_section = None
            for start, label in sections:
                if start <= anchor:
                    current_section = label
                else:
                    break
            if current_section:
                derived.add(current_section)
    return derived


def derived_invariants_for_tr_core(row_ids: list[str]) -> set[int]:
    """Return the set of invariant numbers declared for the given TR-CORE rows in the matrix."""
    derived: set[int] = set()
    row_id_set = set(row_ids)
    for r in matrix_rows():
        if r["id"] in row_id_set:
            derived.update(parse_invariants_cell(r["invariant"]))
    return derived


def load_allowlist(
    path: Path,
    errors: list[str],
    *,
    int_field: str | None = None,
    str_field: str | None = None,
) -> dict[str, set]:
    """Generic TOML allowlist loader.

    One code path handles both `_pending-invariants.toml` (int list + str
    list) and `_pending-projection-drills.toml` (str list only). Missing
    file → empty sets, no error. Malformed TOML → single clean lint error,
    empty sets. Wrong element type → per-entry error, offending entry
    skipped.

    Callers pick which fields to extract by naming them. Returns a dict
    keyed by whichever of `int_field` / `str_field` the caller supplied;
    every requested key is present with at least an empty set.
    """
    import tomllib

    result: dict[str, set] = {}
    if int_field is not None:
        result[int_field] = set()
    if str_field is not None:
        result[str_field] = set()

    if not path.exists():
        return result

    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        # Caller passed an absolute path outside ROOT (e.g., a test tmp file);
        # surface it as-is.
        rel = path

    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{rel}: malformed TOML ({e})")
        return result

    if int_field is not None:
        for entry in data.get(int_field, []):
            if isinstance(entry, bool) or not isinstance(entry, int):
                errors.append(
                    f"{rel}: {int_field} entry {entry!r} is not an integer"
                )
                continue
            result[int_field].add(entry)

    if str_field is not None:
        for entry in data.get(str_field, []):
            if not isinstance(entry, str):
                errors.append(
                    f"{rel}: {str_field} entry {entry!r} is not a string"
                )
                continue
            result[str_field].add(entry)

    return result


def load_pending_projection_drills(
    errors: list[str], *, path: Path | None = None
) -> set[str]:
    """Load the pending-projection-drills allowlist.

    Parallel to load_pending_invariants but for matrix rows whose
    Verification column is `projection-rebuild-drill` rather than
    `test-vector`. Schema:

        pending_matrix_rows = ["TR-OP-008", ...]

    `path` is exposed for tests; real callers pass None and use the
    canonical location under fixtures/vectors/.

    Consumed by `check_projection_rebuild_drill_coverage` (R7), which
    uses this allowlist to suppress uncovered-drill errors while a
    drill fixture is still being authored.
    """
    target = path if path is not None else (FIXTURES / "_pending-projection-drills.toml")
    data = load_allowlist(target, errors, str_field="pending_matrix_rows")
    return data["pending_matrix_rows"]


def load_pending_model_checks(
    errors: list[str], *, path: Path | None = None
) -> set[str]:
    """Load the pending-model-checks allowlist (R8).

    Parallel to load_pending_projection_drills but for matrix rows whose
    Verification column is `model-check`. The G-2 audit-paths brief pins
    model-check evidence to the G-4 Rust conformance crate (not yet
    landed), so every current model-check row is expected to sit in this
    allowlist until G-4 ships. Schema:

        pending_matrix_rows = ["TR-CORE-020", ...]

    Consumed by `check_model_check_evidence` (R8). `path` is exposed for
    tests; real callers pass None.
    """
    target = path if path is not None else (FIXTURES / "_pending-model-checks.toml")
    data = load_allowlist(target, errors, str_field="pending_matrix_rows")
    return data["pending_matrix_rows"]


def load_pending_invariants(errors: list[str]) -> tuple[set[int], set[str]]:
    """Load the pending-invariants allowlist (F5).

    The allowlist replaces the old TRELLIS_SKIP_COVERAGE=1 blanket bypass.
    Listed-but-now-covered entries are errors (forces cleanup). Entries that
    are pending AND uncovered are allowed. Missing file = empty allowlist.

    Schema (all fields optional):

        pending_invariants  = [3, 6, 7]          # Phase-1 invariant numbers
        pending_matrix_rows = ["TR-CORE-037"]    # testable matrix row IDs
                                                 # (both TR-CORE-* and TR-OP-*)
    """
    data = load_allowlist(
        FIXTURES / "_pending-invariants.toml",
        errors,
        int_field="pending_invariants",
        str_field="pending_matrix_rows",
    )
    return data["pending_invariants"], data["pending_matrix_rows"]


# Manifest keys whose string values are hex digests, not filesystem paths.
# Extend this list if the schema grows new non-path string fields.
MANIFEST_NON_PATH_STRING_KEYS = {"zip_sha256"}

# Manifest sub-tables that carry inline structured data (not sibling-file
# references). Per the G-3 fixture-system design, small structured outputs
# stay in the manifest; byte outputs go to sibling files. When the walker
# encounters a sub-table named here, it does NOT recurse into it — every
# string inside is opaque data (scopes, enum values, hex digests, URNs,
# or similar), not a path to be resolved.
MANIFEST_STRUCTURED_DATA_TABLES = {
    "report",            # verify/tamper: [expected.report] — booleans + failure codes
    "watermark_fields",  # projection: [expected.watermark_fields] — Watermark CDDL field values
    "cascade_report",    # shred: [expected.cascade_report] — A.7 class → post-state map
}


def _iter_manifest_path_strings(table: dict, path_stack: tuple[str, ...] = ()):
    """Yield (dotted_key, value) for every string value in a manifest table.

    Recurses into nested tables (e.g. [expected.report] in verify manifests)
    AND into lists of strings (e.g. [inputs] payloads = ["a.bin", "b.bin"]).
    Skips non-string values (booleans, ints), keys explicitly listed as
    non-path string fields (e.g. zip_sha256), and sub-tables listed as
    structured-data containers (e.g. watermark_fields).
    """
    for key, value in table.items():
        if isinstance(value, dict):
            if key in MANIFEST_STRUCTURED_DATA_TABLES:
                continue
            yield from _iter_manifest_path_strings(value, path_stack + (key,))
        elif isinstance(value, list):
            if key in MANIFEST_NON_PATH_STRING_KEYS:
                continue
            for index, element in enumerate(value):
                if isinstance(element, str):
                    dotted = ".".join(path_stack + (f"{key}[{index}]",))
                    yield (dotted, element)
        elif isinstance(value, str):
            if key in MANIFEST_NON_PATH_STRING_KEYS:
                continue
            yield (".".join(path_stack + (key,)), value)


VECTOR_NAMING_PATTERN = re.compile(r"^[0-9]{3}-[a-z0-9]+(?:-[a-z0-9]+)*$")


def check_vector_naming(errors: list[str]) -> None:
    """R1 — every vector directory MUST be named `NNN-slug`.

    `NNN` is exactly three digits; `slug` is one-or-more dash-separated
    segments of lowercase-alphanumeric characters. Trailing / leading
    dashes, uppercase, short numeric prefixes, and missing dashes are all
    rejected.

    The walker only considers directories directly under
    fixtures/vectors/<op>/ where <op> is one of VECTOR_OPS. Support dirs
    like `_generator` live at the op level or above, so they are not in
    this rule's scope.
    """
    if not FIXTURES.exists():
        return
    for op in VECTOR_OPS:
        op_path = FIXTURES / op
        if not op_path.exists():
            continue
        for entry in sorted(op_path.iterdir()):
            if not entry.is_dir():
                continue
            if not VECTOR_NAMING_PATTERN.match(entry.name):
                errors.append(
                    f"{entry.relative_to(ROOT)}: vector directory name "
                    f"{entry.name!r} does not match the required "
                    f"`NNN-slug` naming convention "
                    f"(3-digit prefix, dash, lowercase-alphanumeric slug)"
                )


def check_vector_manifest_paths(errors: list[str]) -> None:
    """A/F7 — every string in [inputs] / [expected] must resolve to a file.

    Paths are relative to the vector directory. Sibling paths and
    ``../../_keys/…`` / ``../../_inputs/…`` both resolve here.
    """
    for manifest_path, manifest in vector_manifests():
        vector_dir = manifest_path.parent
        rel = manifest_path.relative_to(ROOT)
        for section in ("inputs", "expected"):
            section_data = manifest.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for dotted_key, value in _iter_manifest_path_strings(
                section_data, (section,)
            ):
                if value == "":
                    errors.append(
                        f"{rel}: {dotted_key} is empty; "
                        f"manifest path values must be non-empty relative paths"
                    )
                    continue
                if Path(value).is_absolute():
                    errors.append(
                        f"{rel}: {dotted_key}='{value}' is absolute; "
                        f"manifest path values must be relative to the vector directory"
                    )
                    continue
                resolved = (vector_dir / value).resolve()
                if not resolved.exists():
                    errors.append(
                        f"{rel}: "
                        f"{dotted_key}='{value}' does not exist "
                        f"(resolved to {resolved})"
                    )


def check_vector_manifest_identity(errors: list[str]) -> None:
    """Validate that manifest identity fields match the vector directory."""
    for manifest_path, manifest in vector_manifests():
        rel = manifest_path.relative_to(ROOT)
        path_op = manifest_op_from_path(manifest_path)
        if path_op is None:
            continue

        declared_op = manifest.get("op")
        if declared_op != path_op:
            errors.append(
                f"{rel}: manifest op={declared_op!r} does not match "
                f"directory op={path_op!r}"
            )

        declared_id = manifest.get("id")
        expected_id = f"{path_op}/{manifest_path.parent.name}"
        if declared_id != expected_id:
            errors.append(
                f"{rel}: manifest id={declared_id!r} does not match "
                f"directory id={expected_id!r}"
            )


def check_vector_manifest_coverage_ids(errors: list[str]) -> None:
    """Validate manifest coverage row IDs before coverage accounting."""
    known_tr_core = set(tr_core_ids())
    known_tr_op = set(tr_op_ids())
    for manifest_path, manifest in vector_manifests():
        rel = manifest_path.relative_to(ROOT)
        coverage = manifest.get("coverage", {})

        for row_id in coverage.get("tr_core", []):
            if not isinstance(row_id, str) or row_id not in known_tr_core:
                errors.append(
                    f"{rel}: coverage.tr_core entry {row_id!r} is not a known "
                    f"TR-CORE matrix row ID"
                )

        for row_id in coverage.get("tr_op", []):
            if not isinstance(row_id, str) or row_id not in known_tr_op:
                errors.append(
                    f"{rel}: coverage.tr_op entry {row_id!r} is not a known "
                    f"TR-OP matrix row ID"
                )


def check_vector_declared_coverage(errors: list[str], warnings: list[str]) -> None:
    for path, manifest in vector_manifests():
        coverage = manifest.get("coverage", {})
        tr_core = coverage.get("tr_core", [])
        tr_op = coverage.get("tr_op", [])
        declared_sections = set(coverage.get("core_sections", [])) if "core_sections" in coverage else None
        declared_companion_sections = (
            set(coverage.get("companion_sections", []))
            if "companion_sections" in coverage
            else None
        )
        declared_invariants = set(coverage.get("invariants", [])) if "invariants" in coverage else None

        if declared_sections is not None:
            derived = derived_sections_for_tr_core(tr_core)
            if declared_sections != derived:
                errors.append(
                    f"{path.relative_to(ROOT)}: declared core_sections={sorted(declared_sections)} "
                    f"does not equal matrix-derived={sorted(derived)}"
                )
        # R5 — same round-trip rule for the Operational Companion. `companion_sections`,
        # when declared, MUST equal the set derived from the manifest's tr_op rows.
        if declared_companion_sections is not None:
            derived_companion = derived_companion_sections_for_tr_op(tr_op)
            if declared_companion_sections != derived_companion:
                errors.append(
                    f"{path.relative_to(ROOT)}: declared companion_sections="
                    f"{sorted(declared_companion_sections)} does not equal "
                    f"matrix-derived={sorted(derived_companion)}"
                )
        # Per amended design F1: invariants is commentary-only. Mismatch is a
        # warning (non-fatal), not an error. Matrix rows with Invariant=— make
        # bidirectional enforcement incoherent; tr_core is the canonical anchor.
        if declared_invariants is not None:
            derived = derived_invariants_for_tr_core(tr_core)
            if declared_invariants != derived:
                warnings.append(
                    f"{path.relative_to(ROOT)}: declared invariants={sorted(declared_invariants)} "
                    f"does not equal matrix-derived={sorted(derived)} (commentary only)"
                )


def check_invariant_coverage(errors: list[str], pending_invariants: set[int]) -> None:
    rows = matrix_rows()
    testable_by_invariant: dict[int, list[str]] = {}
    for r in rows:
        if "test-vector" not in r["verification"]:
            continue
        for inv in parse_invariants_cell(r["invariant"]):
            testable_by_invariant.setdefault(inv, []).append(r["id"])

    covered_ids: set[str] = set()
    for path, manifest in vector_manifests():
        if _is_deprecated_vector(manifest):
            continue  # F6 — deprecated vectors are excluded from audits
        coverage = manifest.get("coverage", {})
        covered_ids.update(coverage.get("tr_core", []))
        covered_ids.update(coverage.get("tr_op", []))

    # Per amended design F2: narrowed rule. Only invariants that have ≥1
    # matrix row with Verification=test-vector are audited here (the byte-
    # testable subset). Invariants without any test-vector row are handled
    # via the separate G-2 non-byte-testable audit path (model-check,
    # declaration-doc-check, spec-cross-ref, etc.) and are NOT flagged here.
    covered_invariants: set[int] = set()
    for inv in sorted(testable_by_invariant.keys()):
        testable_rows = testable_by_invariant[inv]
        is_covered = any(rid in covered_ids for rid in testable_rows)
        if is_covered:
            covered_invariants.add(inv)
            continue
        if inv in pending_invariants:
            continue  # pending-and-uncovered is allowed
        errors.append(
            f"specs/trellis-requirements-matrix.md: invariant #{inv} has no "
            f"vector via any of its testable rows {testable_rows}"
        )

    # F5 — listed-but-now-covered forces allowlist cleanup.
    for inv in sorted(pending_invariants & covered_invariants):
        errors.append(
            f"fixtures/vectors/_pending-invariants.toml: invariant #{inv} is "
            f"listed as pending but is now covered by a vector; remove it from "
            f"pending_invariants"
        )


def check_generator_imports(errors: list[str]) -> None:
    gen_dir = FIXTURES / "_generator"
    if not gen_dir.exists():
        return
    # Generators may import from the narrow `_lib` package that lives
    # alongside them, in addition to the usual stdlib + cryptography + cbor2
    # allowlist. The `_lib` package hosts verbatim-shared byte-level helpers
    # (dcbor, §9.1 domain separation, §18.1 ZIP entry shape) — no spec
    # interpretation, no generator-specific logic. See
    # `fixtures/vectors/_generator/_lib/byte_utils.py` for the allowed
    # surface; the G-5 stranger-test rationale is that these helpers are
    # stdlib-sugar, not derivations of Core prose.
    lib_dir = gen_dir / "_lib"
    allow_lib_import = lib_dir.exists()
    for py_file in sorted(gen_dir.rglob("*.py")):
        # The `_lib` package's own files are not generators; skip them so
        # the forbidden-import rule doesn't accidentally police its
        # internals.
        try:
            py_file.relative_to(lib_dir)
            continue
        except ValueError:
            pass
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError as e:
            errors.append(f"{py_file.relative_to(ROOT)}: syntax error at line {e.lineno}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top == "_lib" and allow_lib_import:
                        continue
                    if top not in GENERATOR_ALLOWED_IMPORTS:
                        errors.append(
                            f"{py_file.relative_to(ROOT)}:{node.lineno}: forbidden import "
                            f"'{alias.name}' (allowed top-levels: {sorted(GENERATOR_ALLOWED_IMPORTS)})"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    errors.append(
                        f"{py_file.relative_to(ROOT)}:{node.lineno}: relative imports forbidden in _generator/ "
                        f"(level={node.level})"
                    )
                    continue
                top = (node.module or "").split(".")[0]
                if top == "_lib" and allow_lib_import:
                    continue
                if top and top not in GENERATOR_ALLOWED_IMPORTS:
                    errors.append(
                        f"{py_file.relative_to(ROOT)}:{node.lineno}: forbidden import "
                        f"'from {node.module}' (allowed top-levels: {sorted(GENERATOR_ALLOWED_IMPORTS)})"
                    )


ALLOWED_VECTOR_STATUSES = {"active", "deprecated"}
ISO_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _is_deprecated_vector(manifest: dict) -> bool:
    """Return True iff the manifest declares a 'deprecated' lifecycle status."""
    return manifest.get("status") == "deprecated"


def check_vector_lifecycle_fields(errors: list[str]) -> None:
    """F6 — validate manifest-level `status` and `deprecated_at` fields.

    Rules:
      * `status` is optional; when present, MUST be "active" or "deprecated".
      * `deprecated_at` is required iff `status = "deprecated"`.
      * `deprecated_at` MUST be an ISO-8601 date string (YYYY-MM-DD).
      * `deprecated_at` without `status = "deprecated"` is permitted but noisy;
         the design doc does not forbid it, so this lint does not flag it.
    """
    from datetime import date

    for manifest_path, manifest in vector_manifests():
        rel = manifest_path.relative_to(ROOT)
        status = manifest.get("status")
        if status is not None:
            if not isinstance(status, str) or status not in ALLOWED_VECTOR_STATUSES:
                errors.append(
                    f"{rel}: status={status!r} is not one of "
                    f"{sorted(ALLOWED_VECTOR_STATUSES)}"
                )
                continue  # can't reason about deprecated_at when status is bogus

        if status != "deprecated":
            continue

        deprecated_at = manifest.get("deprecated_at")
        if deprecated_at is None:
            errors.append(
                f"{rel}: status='deprecated' requires a deprecated_at "
                f"ISO-8601 date (YYYY-MM-DD)"
            )
            continue
        if not isinstance(deprecated_at, str) or not ISO_DATE_PATTERN.match(
            deprecated_at
        ):
            errors.append(
                f"{rel}: deprecated_at={deprecated_at!r} is not a valid "
                f"ISO-8601 date (YYYY-MM-DD)"
            )
            continue
        try:
            date.fromisoformat(deprecated_at)
        except ValueError:
            errors.append(
                f"{rel}: deprecated_at={deprecated_at!r} is not a valid "
                f"ISO-8601 date (YYYY-MM-DD)"
            )


def check_vector_coverage_prefixes(errors: list[str]) -> None:
    """R8 — coverage-bucket prefix discipline.

    `coverage.tr_core` entries MUST start with `TR-CORE-` and `coverage.tr_op`
    entries MUST start with `TR-OP-`. Misfiling an ID into the wrong bucket
    is otherwise silently ignored by R4/R5: a TR-OP row placed under
    `coverage.tr_core` would never land in the TR-OP coverage set and would
    create false-green lint on the TR-OP side. Running this ahead of R4/R5
    surfaces the mistake with a clear diagnostic instead.
    """
    for manifest_path, manifest in vector_manifests():
        if _is_deprecated_vector(manifest):
            continue  # F6 — deprecated vectors are excluded from audits
        rel = manifest_path.relative_to(ROOT)
        coverage = manifest.get("coverage", {})
        for row_id in coverage.get("tr_core", []):
            if not isinstance(row_id, str) or not row_id.startswith("TR-CORE-"):
                errors.append(
                    f"{rel}: coverage.tr_core entry {row_id!r} is not a "
                    f"TR-CORE-* id; misfiled IDs are silently ignored by the "
                    f"bucket-audit rules"
                )
        for row_id in coverage.get("tr_op", []):
            if not isinstance(row_id, str) or not row_id.startswith("TR-OP-"):
                errors.append(
                    f"{rel}: coverage.tr_op entry {row_id!r} is not a "
                    f"TR-OP-* id; misfiled IDs are silently ignored by the "
                    f"bucket-audit rules"
                )


def check_vector_coverage(errors: list[str], pending_matrix_rows: set[str]) -> None:
    testable = {row_id for row_id in testable_row_ids() if row_id.startswith("TR-CORE-")}
    covered: set[str] = set()
    for _path, manifest in vector_manifests():
        if _is_deprecated_vector(manifest):
            continue  # F6 — deprecated vectors are excluded from audits
        covered.update(manifest.get("coverage", {}).get("tr_core", []))
    for row_id in sorted(testable - covered):
        if row_id in pending_matrix_rows:
            continue  # pending-and-uncovered is allowed
        errors.append(
            f"specs/trellis-requirements-matrix.md: no vector covers {row_id} "
            f"(row has Verification=test-vector but no fixtures/vectors/*/manifest.toml "
            f"references it in coverage.tr_core)"
        )

    # F5 — listed-but-now-covered forces allowlist cleanup.
    for row_id in sorted(pending_matrix_rows & covered):
        errors.append(
            f"fixtures/vectors/_pending-invariants.toml: {row_id} is listed in "
            f"pending_matrix_rows but is now covered by a vector; remove it"
        )
    # Unknown row IDs in the allowlist are suspicious — warn via errors.
    known_ids = set(matrix_ids())
    for row_id in sorted(pending_matrix_rows - known_ids):
        errors.append(
            f"fixtures/vectors/_pending-invariants.toml: {row_id} is not a "
            f"matrix row ID; remove it from pending_matrix_rows"
        )


def check_tr_op_coverage(errors: list[str], pending_matrix_rows: set[str]) -> None:
    """R5 — mirror of check_vector_coverage for TR-OP rows.

    A TR-OP row with `Verification=test-vector` is covered when ≥1
    non-deprecated manifest lists it under `coverage.tr_op`. The
    `pending_matrix_rows` allowlist is shared with TR-CORE (both prefixes
    live in the same list); the unknown-ID audit is handled by
    check_vector_coverage and not repeated here.
    """
    testable = {row_id for row_id in testable_row_ids() if row_id.startswith("TR-OP-")}
    covered: set[str] = set()
    for _path, manifest in vector_manifests():
        if _is_deprecated_vector(manifest):
            continue  # F6 — deprecated vectors are excluded from audits
        covered.update(manifest.get("coverage", {}).get("tr_op", []))
    for row_id in sorted(testable - covered):
        if row_id in pending_matrix_rows:
            continue  # pending-and-uncovered is allowed
        errors.append(
            f"specs/trellis-requirements-matrix.md: no vector covers {row_id} "
            f"(row has Verification=test-vector but no fixtures/vectors/*/manifest.toml "
            f"references it in coverage.tr_op)"
        )

    # F5 — listed-but-now-covered forces allowlist cleanup.
    for row_id in sorted(pending_matrix_rows & covered):
        errors.append(
            f"fixtures/vectors/_pending-invariants.toml: {row_id} is listed in "
            f"pending_matrix_rows but is now covered by a vector; remove it"
        )


def check_projection_rebuild_drill_coverage(
    errors: list[str], pending_matrix_rows: set[str]
) -> None:
    """R7 — projection-rebuild-drill rows need projection/shred fixtures.

    A TR-OP row with `Verification=projection-rebuild-drill` is covered when
    at least one non-deprecated manifest under `projection/` or `shred/` lists
    the row in `coverage.tr_op`. `_pending-projection-drills.toml` is the
    narrow allowlist for rows whose drill fixture has not landed yet.
    """
    drill_rows = projection_rebuild_drill_row_ids()
    covered: set[str] = set()
    for manifest_path, manifest in vector_manifests():
        if _is_deprecated_vector(manifest):
            continue
        op = manifest_op_from_path(manifest_path)
        if op not in {"projection", "shred"}:
            continue
        covered.update(
            row_id
            for row_id in manifest.get("coverage", {}).get("tr_op", [])
            if row_id in drill_rows
        )

    for row_id in sorted(drill_rows - covered):
        if row_id in pending_matrix_rows:
            continue
        errors.append(
            f"specs/trellis-requirements-matrix.md: no projection rebuild drill "
            f"covers {row_id} (row has Verification=projection-rebuild-drill "
            f"but no projection/shred manifest references it in coverage.tr_op)"
        )

    for row_id in sorted(pending_matrix_rows & covered):
        errors.append(
            f"fixtures/vectors/_pending-projection-drills.toml: {row_id} is "
            f"listed in pending_matrix_rows but is now covered by a projection "
            f"or shred fixture; remove it"
        )

    known_ids = set(matrix_ids())
    for row_id in sorted(pending_matrix_rows - known_ids):
        errors.append(
            f"fixtures/vectors/_pending-projection-drills.toml: {row_id} is "
            f"not a matrix row ID; remove it from pending_matrix_rows"
        )
    for row_id in sorted((pending_matrix_rows & known_ids) - drill_rows):
        errors.append(
            f"fixtures/vectors/_pending-projection-drills.toml: {row_id} is "
            f"not a TR-OP row with Verification=projection-rebuild-drill; "
            f"remove it from pending_matrix_rows"
        )


_SPEC_CITE_PATTERN = re.compile(
    r"\b(Core|Companion)\s+§([0-9]+(?:\.[0-9]+)*)"
)


def spec_cross_ref_row_ids() -> set[str]:
    """Matrix rows where Verification contains `spec-cross-ref`."""
    return {r["id"] for r in matrix_rows() if "spec-cross-ref" in r["verification"]}


def model_check_row_ids() -> set[str]:
    """Matrix rows where Verification contains `model-check`."""
    return {r["id"] for r in matrix_rows() if "model-check" in r["verification"]}


def check_spec_cross_ref_rows(errors: list[str], warnings: list[str]) -> None:
    """R6 — spec-cross-ref rows must cite resolvable §N headings.

    For every matrix row with `Verification=spec-cross-ref`, scan the
    Requirement / Rationale / Notes cells for `Core §N` or `Companion §N`
    citations. Each cited §N MUST resolve to a top-level heading in the
    named spec; a non-resolving cite is a hard error.

    Rows that declare `spec-cross-ref` but carry no `Core §N` / `Companion §N`
    citation in any of the three text cells are warned, not errored. Many
    existing rows rely on prose anchors that do not use this exact phrasing;
    forcing a hard error would require annotating ~25 rows that are out of
    scope for a lint-only refactor. The warning still surfaces the gap on
    every run so new rows land with cites from day one.
    """
    core_section_numbers = {str(n) for n in core_headings().keys()}
    # Companion section numbers include `A.5.1` / `A.5` style Appendix ids
    # whenever the heading scanner picked them up. Build a permissive set of
    # "any heading anchor number we recognise" for Companion so Appendix
    # cites resolve the same way top-level `## 10.` headings do.
    companion_section_numbers = {str(n) for n in companion_headings().keys()}
    appendix_pattern = re.compile(
        r"^#{2,4}\s+([A-Z]\.[0-9]+(?:\.[0-9]+)*)\b", re.MULTILINE
    )
    companion_text = read(SPECS / "trellis-operational-companion.md")
    for m in appendix_pattern.finditer(companion_text):
        companion_section_numbers.add(m.group(1))

    for row in matrix_rows():
        if "spec-cross-ref" not in row["verification"]:
            continue
        haystack = " ".join((row["requirement"], row["rationale"], row["notes"]))
        matches = list(_SPEC_CITE_PATTERN.finditer(haystack))
        if not matches:
            warnings.append(
                f"specs/trellis-requirements-matrix.md: {row['id']} declares "
                f"Verification=spec-cross-ref but cites no `Core §N` / "
                f"`Companion §N` heading in Requirement/Rationale/Notes"
            )
            continue
        for match in matches:
            spec_name, section = match.group(1), match.group(2)
            if spec_name == "Core":
                known = core_section_numbers
                spec_path = "specs/trellis-core.md"
            else:
                known = companion_section_numbers
                spec_path = "specs/trellis-operational-companion.md"
            # A cite like `Core §5.1` passes when either the top-level
            # `## 5.` heading exists OR any heading matches the full dotted
            # path (`### 5.1`). Split on dots and walk outward.
            if section in known:
                continue
            top = section.split(".", 1)[0]
            if top in known:
                continue
            errors.append(
                f"specs/trellis-requirements-matrix.md: {row['id']} cites "
                f"`{spec_name} §{section}` but no matching heading exists "
                f"in {spec_path}"
            )


def load_model_check_evidence(errors: list[str]) -> dict[str, str]:
    """Load thoughts/model-checks/evidence.toml.

    Schema:

        [evidence]
        "TR-CORE-020" = "thoughts/model-checks/tr-core-020/linear-order.tla"
        "TR-CORE-050" = "thoughts/model-checks/tr-core-050/idempotency.tla"

    Missing file → empty mapping, no error (expected until G-4's
    conformance crate lands). Malformed TOML → lint error.
    """
    import tomllib

    path = ROOT / "thoughts" / "model-checks" / "evidence.toml"
    if not path.exists():
        return {}
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        rel = path
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{rel}: malformed TOML ({e})")
        return {}
    table = data.get("evidence", {})
    if not isinstance(table, dict):
        errors.append(f"{rel}: [evidence] must be a TOML table")
        return {}
    mapping: dict[str, str] = {}
    for row_id, artifact in table.items():
        if not isinstance(artifact, str):
            errors.append(
                f"{rel}: evidence[{row_id!r}]={artifact!r} is not a string path"
            )
            continue
        mapping[row_id] = artifact
    return mapping


def check_model_check_evidence(
    errors: list[str], pending_matrix_rows: set[str]
) -> None:
    """R8 — matrix rows with `Verification=model-check` need an evidence artifact.

    A row is satisfied when either:
      (a) `thoughts/model-checks/evidence.toml` names the row under
          `[evidence]` with a path that resolves relative to the repo root, or
      (b) the row is listed in `_pending-model-checks.toml`'s
          `pending_matrix_rows` (the narrow escape hatch for rows awaiting
          the G-4 Rust conformance crate).

    Allowlist hygiene: evidence-present AND listed-as-pending → error (forces
    cleanup). Unknown row IDs and non-model-check rows in the allowlist →
    error.
    """
    model_check_rows = model_check_row_ids()
    evidence = load_model_check_evidence(errors)

    for row_id in sorted(model_check_rows):
        if row_id in pending_matrix_rows:
            continue
        artifact = evidence.get(row_id)
        if artifact is None:
            errors.append(
                f"specs/trellis-requirements-matrix.md: no model-check "
                f"evidence for {row_id} (row has Verification=model-check "
                f"but thoughts/model-checks/evidence.toml has no entry and "
                f"the row is not in _pending-model-checks.toml)"
            )
            continue
        resolved = (ROOT / artifact).resolve()
        if not resolved.exists():
            errors.append(
                f"thoughts/model-checks/evidence.toml: "
                f"{row_id} evidence path {artifact!r} does not exist "
                f"(resolved to {resolved})"
            )

    for row_id in sorted(pending_matrix_rows & set(evidence.keys())):
        errors.append(
            f"fixtures/vectors/_pending-model-checks.toml: {row_id} is "
            f"listed in pending_matrix_rows but evidence is present in "
            f"thoughts/model-checks/evidence.toml; remove it"
        )

    known_ids = set(matrix_ids())
    for row_id in sorted(pending_matrix_rows - known_ids):
        errors.append(
            f"fixtures/vectors/_pending-model-checks.toml: {row_id} is "
            f"not a matrix row ID; remove it from pending_matrix_rows"
        )
    for row_id in sorted((pending_matrix_rows & known_ids) - model_check_rows):
        errors.append(
            f"fixtures/vectors/_pending-model-checks.toml: {row_id} is "
            f"not a TR-* row with Verification=model-check; remove it "
            f"from pending_matrix_rows"
        )


def check_forbidden_terms(errors: list[str]) -> None:
    for path in TOP_LEVEL_SPECS:
        text = read(path)
        for pattern, label in FORBIDDEN_PATTERNS:
            for match in pattern.finditer(text):
                errors.append(f"{path.relative_to(ROOT)}:{line_for(text, match.start())}: forbidden {label}")


def check_core_section_references(errors: list[str]) -> None:
    headings = core_headings()
    companion = SPECS / "trellis-operational-companion.md"
    text = read(companion)
    ref_pattern = re.compile(r"Core §([0-9]+)(?: \(([^)]+)\))?")
    for match in ref_pattern.finditer(text):
        number = int(match.group(1))
        label = match.group(2)
        heading = headings.get(number)
        line = line_for(text, match.start())
        if heading is None:
            errors.append(f"{companion.relative_to(ROOT)}:{line}: Core §{number} does not exist")
            continue
        if label is None:
            errors.append(
                f"{companion.relative_to(ROOT)}:{line}: Core §{number} must include heading label "
                f'`Core §{number} ({heading})`'
            )
            continue
        if label.strip().lower() != heading.lower():
            errors.append(
                f"{companion.relative_to(ROOT)}:{line}: Core §{number} label `{label}` does not match `{heading}`"
            )


def check_requirement_ids(errors: list[str]) -> None:
    ids = matrix_ids()
    seen: set[str] = set()
    for requirement_id in ids:
        if requirement_id in seen:
            errors.append(f"specs/trellis-requirements-matrix.md: duplicate requirement ID {requirement_id}")
        seen.add(requirement_id)

    known = set(ids)
    for path in TOP_LEVEL_SPECS:
        text = read(path)
        for match in re.finditer(r"\bTR-(?:CORE|OP)-[0-9]{3}\b", text):
            requirement_id = match.group(0)
            if requirement_id not in known:
                errors.append(f"{path.relative_to(ROOT)}:{line_for(text, match.start())}: unknown {requirement_id}")


def check_traceability_anchors(errors: list[str]) -> None:
    core_text = read(SPECS / "trellis-core.md")
    companion_text = read(SPECS / "trellis-operational-companion.md")
    for requirement_id in matrix_ids():
        if requirement_id.startswith("TR-CORE-") and requirement_id not in core_text:
            errors.append(f"specs/trellis-core.md: missing prose anchor for {requirement_id}")
        if requirement_id.startswith("TR-OP-") and requirement_id not in companion_text:
            errors.append(f"specs/trellis-operational-companion.md: missing prose anchor for {requirement_id}")


def check_bare_profile(errors: list[str]) -> None:
    for path in TOP_LEVEL_SPECS:
        text = read(path)
        for match in re.finditer(r"\b[Pp]rofile(?:s)?\b", text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if PROFILE_ALLOWED_CONTEXT.search(line):
                continue
            if any(qualified in line for qualified in ("Posture", "Custody", "Conformance Class", "Trust-Profile")):
                continue
            errors.append(f"{path.relative_to(ROOT)}:{line_for(text, match.start())}: bare Profile/profile wording")


def check_archived_inputs(errors: list[str]) -> None:
    for family in ["core", "trust", "export", "projection", "operations", "forms", "workflow", "assurance"]:
        path = SPECS / family
        if path.exists():
            errors.append(f"{path.relative_to(ROOT)}: superseded spec family directory must be under specs/archive/")


def core_event_type_registry() -> dict[str, dict[str, str]]:
    """Parse Core §6.7's Extension Registration table.

    Returns a mapping from registered identifier to a dict with
    `container`, `phase`, and `purpose` fields. Used by the event-type
    registry rule (R9) once that wires up in a later commit.

    The table is a plain markdown 4-column table under `### 6.7 Extension
    Registration`; the header row and separator row are skipped.
    """
    core_text = read(SPECS / "trellis-core.md")
    section_match = re.search(r"^### 6\.7\b.*$", core_text, re.MULTILINE)
    if not section_match:
        return {}
    # Slice from §6.7 heading to the next same-or-higher heading.
    start = section_match.end()
    next_heading = re.search(r"^#{1,3}\s", core_text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(core_text)
    section = core_text[start:end]

    registry: dict[str, dict[str, str]] = {}
    row_pattern = re.compile(
        r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$",
        re.MULTILINE,
    )
    for m in row_pattern.finditer(section):
        container, identifier, phase, purpose = m.group(1, 2, 3, 4)
        # Skip header rows disguised as data (unlikely here, but defensive).
        if container.startswith("-") or identifier.startswith("-"):
            continue
        registry[identifier.strip()] = {
            "container": container.strip(),
            "phase": phase.strip(),
            "purpose": purpose.strip(),
        }
    return registry


_CDDL_RULE_NAME_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE)


def companion_cddl_blocks() -> dict[tuple[str, str], str]:
    """Extract ```cddl fenced blocks from the Operational Companion.

    Returns a mapping keyed by (appendix_id, rule_name) to the raw block
    body. `appendix_id` is the nearest enclosing `## A.N` / `### A.N.M`
    heading (e.g. "A.5", "A.5.1"). `rule_name` is the first CDDL rule
    name declared in the block (e.g. "CustodyModelTransitionPayload"), and
    must match the identifier pattern `[A-Za-z_][A-Za-z0-9_]*` followed by
    `=`.

    Used by the CDDL cross-ref rule (R10) once that wires up.
    """
    companion_text = read(SPECS / "trellis-operational-companion.md")
    heading_pattern = re.compile(
        r"^(?:#{2,4})\s+(A\.[0-9]+(?:\.[0-9]+)*)\b", re.MULTILINE
    )
    headings: list[tuple[int, str]] = [
        (m.start(), m.group(1)) for m in heading_pattern.finditer(companion_text)
    ]

    block_pattern = re.compile(r"^```cddl\s*\n(.*?)^```", re.MULTILINE | re.DOTALL)
    blocks: dict[tuple[str, str], str] = {}
    for m in block_pattern.finditer(companion_text):
        body = m.group(1)
        rule_match = _CDDL_RULE_NAME_PATTERN.search(body)
        if not rule_match:
            continue
        rule_name = rule_match.group(1)
        # Find the nearest heading at or before this block.
        appendix_id: str | None = None
        for start, label in headings:
            if start <= m.start():
                appendix_id = label
            else:
                break
        if appendix_id is None:
            continue
        blocks[(appendix_id, rule_name)] = body
    return blocks


def _decode_cbor_file(path: Path, errors: list[str]):
    """Decode one CBOR fixture artifact.

    R9/R10 inspect vector event payloads directly because manifests do not
    carry an explicit event-type field. Malformed CBOR in a referenced .cbor
    artifact is already a conformance problem, so surface it as lint.
    """
    import cbor2

    try:
        return cbor2.loads(path.read_bytes())
    except Exception as e:  # cbor2 exposes several decode exception classes.
        # Synthetic unit-test fixture scenarios use empty placeholder .cbor
        # files for path-resolution checks. The real repo must stay strict.
        if ROOT.resolve() == REAL_ROOT.resolve():
            errors.append(f"{relpath(path)}: malformed CBOR ({e})")
        return None


def _event_payload_from_cose_sign1(obj):
    """Return EventPayload from a COSE_Sign1 CBORTag if obj has that shape."""
    import cbor2

    if getattr(obj, "tag", None) != 18:
        return None
    value = getattr(obj, "value", None)
    if not isinstance(value, list) or len(value) < 3:
        return None
    payload_bytes = value[2]
    if not isinstance(payload_bytes, (bytes, bytearray)):
        return None
    try:
        payload = cbor2.loads(payload_bytes)
    except Exception:
        return None
    if _is_event_payload(payload):
        return payload
    return None


def _is_event_payload(obj) -> bool:
    """Heuristic for Core §6 EventPayload maps."""
    if not isinstance(obj, dict):
        return False
    header = obj.get("header")
    return isinstance(header, dict) and "event_type" in header


def _walk_event_payloads(obj):
    """Yield Core EventPayload maps nested in CBOR-decoded fixture objects."""
    if _is_event_payload(obj):
        yield obj
        return
    cose_payload = _event_payload_from_cose_sign1(obj)
    if cose_payload is not None:
        yield cose_payload
        return
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _walk_event_payloads(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _walk_event_payloads(value)


def vector_event_payloads(errors: list[str]) -> list[tuple[Path, dict]]:
    """Return (artifact_path, EventPayload) pairs found in vector CBOR artifacts."""
    payloads: list[tuple[Path, dict]] = []
    for manifest_path, manifest in vector_manifests():
        vector_dir = manifest_path.parent
        for section in ("inputs", "expected"):
            section_data = manifest.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for _dotted_key, value in _iter_manifest_path_strings(section_data, (section,)):
                if not isinstance(value, str) or not value.endswith(".cbor"):
                    continue
                path = (vector_dir / value).resolve()
                if not path.exists():
                    continue  # check_vector_manifest_paths owns the missing-path diagnostic.
                obj = _decode_cbor_file(path, errors)
                if obj is None:
                    continue
                for payload in _walk_event_payloads(obj):
                    payloads.append((path, payload))
    return payloads


def _event_type_text(payload: dict) -> str | None:
    raw = payload.get("header", {}).get("event_type")
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(raw, str):
        return raw
    return None


def check_event_type_registry(errors: list[str]) -> None:
    """R9 — emitted Core extension keys must be registered in Core §6.7."""
    registry = core_event_type_registry()
    for artifact_path, payload in vector_event_payloads(errors):
        rel = artifact_path.relative_to(ROOT)
        extensions = payload.get("extensions")
        if extensions is None:
            continue
        if not isinstance(extensions, dict):
            errors.append(f"{rel}: EventPayload.extensions is neither null nor a map")
            continue
        for extension_key in extensions.keys():
            if not isinstance(extension_key, str):
                errors.append(f"{rel}: EventPayload.extensions contains a non-string key")
                continue
            if not extension_key.startswith("trellis."):
                continue
            entry = registry.get(extension_key)
            if entry is None:
                errors.append(
                    f"{rel}: EventPayload.extensions key {extension_key!r} is "
                    f"not registered in Core §6.7"
                )
                continue
            if entry.get("container") != "EventPayload.extensions":
                errors.append(
                    f"{rel}: EventPayload.extensions key {extension_key!r} is "
                    f"registered for {entry.get('container')}, not "
                    f"EventPayload.extensions"
                )


def _load_event_registry_stub(declaration_path: Path) -> str | None:
    registry_path = declaration_path.parent / "event-registry.stub.md"
    if not registry_path.exists():
        return None
    return registry_path.read_text(encoding="utf-8")


def _as_string_list(value) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return value


def _table(data: dict, key: str, rel: Path, errors: list[str]) -> dict | None:
    value = data.get(key)
    if not isinstance(value, dict):
        errors.append(f"{rel}: [{key}] must be a TOML table")
        return None
    return value


def _required_string(data: dict, key: str, rel: Path, errors: list[str]) -> str | None:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{rel}: {key} must be a non-empty string")
        return None
    return value


TRANSITION_CDDL_BY_EVENT_TYPE = {
    "trellis.custody-model-transition.v1": ("A.5.1", "CustodyModelTransitionPayload"),
    "trellis.disclosure-profile-transition.v1": ("A.5.2", "DisclosureProfileTransitionPayload"),
}


def _cddl_top_level_fields(block: str) -> set[str]:
    """Extract top-level field names from a simple `Type = { ... }` CDDL block."""
    fields: set[str] = set()
    in_map = False
    for line in block.splitlines():
        stripped = line.strip()
        if not in_map:
            if stripped.endswith("{"):
                in_map = True
            continue
        if stripped.startswith("}"):
            break
        match = re.match(r"^\??\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", stripped)
        if match:
            fields.add(match.group(1))
    return fields


def check_transition_cddl_cross_refs(errors: list[str]) -> None:
    """R10 — transition extension payload field names must match Companion CDDL."""
    blocks = companion_cddl_blocks()
    expected_fields_by_type: dict[str, set[str]] = {}
    event_payloads = vector_event_payloads(errors)
    emitted_transition_types = {
        event_type
        for _artifact_path, payload in event_payloads
        for event_type in [_event_type_text(payload)]
        if event_type in TRANSITION_CDDL_BY_EVENT_TYPE
    }

    for event_type in sorted(emitted_transition_types):
        cddl_key = TRANSITION_CDDL_BY_EVENT_TYPE[event_type]
        block = blocks.get(cddl_key)
        if block is None:
            appendix, rule_name = cddl_key
            errors.append(
                f"specs/trellis-operational-companion.md: missing {appendix} "
                f"CDDL block {rule_name} for {event_type}"
            )
            continue
        expected_fields_by_type[event_type] = _cddl_top_level_fields(block)

    for artifact_path, payload in event_payloads:
        event_type = _event_type_text(payload)
        if event_type not in TRANSITION_CDDL_BY_EVENT_TYPE:
            continue
        rel = artifact_path.relative_to(ROOT)
        extensions = payload.get("extensions")
        if not isinstance(extensions, dict) or event_type not in extensions:
            errors.append(
                f"{rel}: transition event {event_type!r} does not carry a "
                f"matching EventPayload.extensions entry"
            )
            continue
        extension_payload = extensions[event_type]
        if not isinstance(extension_payload, dict):
            errors.append(
                f"{rel}: EventPayload.extensions[{event_type!r}] is not a map"
            )
            continue
        actual_fields = set(extension_payload.keys())
        expected_fields = expected_fields_by_type.get(event_type)
        if expected_fields is None:
            continue
        if actual_fields != expected_fields:
            errors.append(
                f"{rel}: EventPayload.extensions[{event_type!r}] fields "
                f"{sorted(actual_fields)} do not match Companion CDDL fields "
                f"{sorted(expected_fields)}"
            )


DECLARATION_ALLOWED_ACTIONS = {"read", "propose", "commit_on_behalf_of"}
DECLARATION_REQUIRED_TOP_LEVEL = {
    "declaration_id",
    "operator_id",
    "posture_declaration_ref",
    "effective_from",
    "scope",
    "authority",
    "audit",
    "attribution",
    "supply_chain",
    "signature",
}
DECLARATION_ALLOWED_TOP_LEVEL = DECLARATION_REQUIRED_TOP_LEVEL | {"supersedes"}
DECLARATION_SIGNATURE_KEYS = {"cose_sign1_b64", "signer_kid", "alg"}

# Phase-1 declaration `[signature].alg` allowed values per Core §7.1 (pinned
# Ed25519 suite). Extensions land here when the §7.2 suite registry adds new
# rows; per Core §7.2 Phase-1 the only Active row is suite_id = 1 (EdDSA).
DECLARATION_ALLOWED_ALGS = frozenset({"EdDSA"})

# Base64-character regex for the placeholder/real `cose_sign1_b64` value. The
# field MUST be a non-empty string composed of base64 characters (allow URL-
# safe variant). Phase-1 reference declarations carry placeholder content;
# the structural lint accepts any non-empty base64-shaped value.
DECLARATION_B64_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _extract_toml_frontmatter(path: Path, errors: list[str]) -> dict | None:
    """Parse TOML frontmatter from a Markdown declaration document."""
    import tomllib

    rel = relpath(path)
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        errors.append(f"{rel}: missing TOML frontmatter opening delimiter")
        return None
    end = text.find("\n---", 4)
    if end == -1:
        errors.append(f"{rel}: missing TOML frontmatter closing delimiter")
        return None
    frontmatter = text[4:end]
    try:
        data = tomllib.loads(frontmatter)
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{rel}: malformed TOML frontmatter ({e})")
        return None
    return data


def _is_utc_datetime(value) -> bool:
    from datetime import timedelta

    return hasattr(value, "tzinfo") and value.tzinfo is not None and value.utcoffset() == timedelta(0)


def declaration_paths(root: Path | None = None) -> list[Path]:
    """Return delegated-compute declaration docs under fixtures/declarations."""
    base = root if root is not None else DECLARATIONS
    if not base.exists():
        return []
    return sorted(base.glob("*/declaration.md"))


def check_declaration_docs(errors: list[str], *, root: Path | None = None) -> None:
    """R11 — O-4 declaration-doc Phase 1 static checks."""
    base = root if root is not None else DECLARATIONS
    for path in declaration_paths(base):
        rel = relpath(path)
        data = _extract_toml_frontmatter(path, errors)
        if data is None:
            continue

        unknown = set(data.keys()) - DECLARATION_ALLOWED_TOP_LEVEL
        if unknown:
            errors.append(f"{rel}: unknown top-level frontmatter keys {sorted(unknown)}")

        missing = DECLARATION_REQUIRED_TOP_LEVEL - set(data.keys())
        if missing:
            errors.append(f"{rel}: missing required frontmatter keys {sorted(missing)}")
            continue

        if path.parent.parent != base or path.name != "declaration.md":
            errors.append(
                f"{rel}: declaration path must be fixtures/declarations/<deployment-slug>/declaration.md"
            )

        posture_ref = data.get("posture_declaration_ref")
        posture_path = path.parent / "posture-declaration.stub.md"
        if not isinstance(posture_ref, str):
            errors.append(f"{rel}: posture_declaration_ref must be a string URI")
        elif not posture_path.exists():
            errors.append(
                f"{rel}: posture_declaration_ref={posture_ref!r} has no sibling "
                f"posture-declaration.stub.md"
            )
        else:
            posture_text = posture_path.read_text(encoding="utf-8")
            if posture_ref not in posture_text:
                errors.append(
                    f"{rel}: posture_declaration_ref={posture_ref!r} is not "
                    f"named in {relpath(posture_path)}"
                )
            operator_id = data.get("operator_id")
            if isinstance(operator_id, str) and operator_id not in posture_text:
                errors.append(
                    f"{rel}: operator_id={operator_id!r} is not named in "
                    f"{relpath(posture_path)}"
                )
            if "delegated_compute" not in posture_text:
                errors.append(
                    f"{relpath(posture_path)}: referenced posture doc "
                    f"does not declare delegated_compute"
                )

        effective_from = data.get("effective_from")
        if not _is_utc_datetime(effective_from):
            errors.append(f"{rel}: effective_from must be an RFC 3339 UTC timestamp")

        scope = _table(data, "scope", rel, errors)
        audit = _table(data, "audit", rel, errors)
        attribution = _table(data, "attribution", rel, errors)
        supply_chain = _table(data, "supply_chain", rel, errors)
        if scope is None or audit is None or attribution is None or supply_chain is None:
            continue
        actions = scope.get("authorized_actions")
        actions = _as_string_list(actions)
        if actions is None:
            errors.append(f"{rel}: scope.authorized_actions must be a list of strings")
        else:
            invalid_actions = sorted(set(actions) - DECLARATION_ALLOWED_ACTIONS)
            if invalid_actions:
                errors.append(
                    f"{rel}: scope.authorized_actions contains non-Phase-1 values "
                    f"{invalid_actions}; allowed values are {sorted(DECLARATION_ALLOWED_ACTIONS)}"
                )

        time_bound = scope.get("time_bound")
        open_ended = scope.get("open_ended_permitted") is True
        if time_bound is None and not open_ended:
            errors.append(
                f"{rel}: scope.time_bound is required unless "
                f"scope.open_ended_permitted = true"
            )
        elif time_bound is not None and not _is_utc_datetime(time_bound):
            errors.append(f"{rel}: scope.time_bound must be an RFC 3339 UTC timestamp")

        event_types = _as_string_list(audit.get("event_types"))
        if event_types is None:
            errors.append(f"{rel}: audit.event_types must be a list of strings")
        else:
            registry_text = _load_event_registry_stub(path)
            if registry_text is None:
                errors.append(f"{rel}: audit.event_types requires sibling event-registry.stub.md")
            else:
                for event_type in event_types:
                    if event_type not in registry_text:
                        errors.append(
                            f"{rel}: audit.event_types entry {event_type!r} is not "
                            f"registered in event-registry.stub.md"
                        )

        actor_rule = attribution.get("actor_discriminator_rule")
        expected_actor_rule = "exactly_one_of(actor_human, actor_agent_under_delegation)"
        if actor_rule != expected_actor_rule:
            errors.append(
                f"{rel}: attribution.actor_discriminator_rule must equal "
                f"{expected_actor_rule!r}"
            )

        content_classes = _as_string_list(scope.get("content_classes"))
        runtime_enclave = _required_string(
            supply_chain, "runtime_enclave", rel, errors
        )
        if content_classes is None:
            errors.append(f"{rel}: scope.content_classes must be a list of strings")
        elif runtime_enclave is not None and posture_path.exists():
            posture_text = posture_path.read_text(encoding="utf-8")
            for content_class in content_classes:
                if content_class not in posture_text:
                    errors.append(
                        f"{rel}: content_class {content_class!r} is not named "
                        f"in {relpath(posture_path)}"
                    )
            exposure_pin = f"delegated_compute_exposure = {runtime_enclave}"
            if exposure_pin not in posture_text:
                errors.append(
                    f"{rel}: supply_chain.runtime_enclave={runtime_enclave!r} "
                    f"does not match delegated_compute_exposure in "
                    f"{relpath(posture_path)}"
                )

        signature = data.get("signature", {})
        if not isinstance(signature, dict):
            errors.append(f"{rel}: [signature] must be a TOML table")
        elif set(signature.keys()) != DECLARATION_SIGNATURE_KEYS:
            errors.append(
                f"{rel}: [signature] keys {sorted(signature.keys())} do not "
                f"match required keys {sorted(DECLARATION_SIGNATURE_KEYS)}"
            )
        else:
            # R14 — signing-key structural validation (no crypto).
            # Pins the [signature] field shapes that a verifier needs to
            # resolve before running any signature crypto: the alg is in
            # the Phase-1 registered set, the kid is a non-empty URI-shaped
            # string, and the cose_sign1_b64 payload is non-empty base64.
            alg = signature.get("alg")
            if not isinstance(alg, str) or alg not in DECLARATION_ALLOWED_ALGS:
                errors.append(
                    f"{rel}: [signature].alg={alg!r} is not in the Phase-1 "
                    f"allowed set {sorted(DECLARATION_ALLOWED_ALGS)} "
                    f"(Core §7.1 / §7.2)"
                )
            signer_kid = signature.get("signer_kid")
            if not isinstance(signer_kid, str) or not signer_kid.strip():
                errors.append(
                    f"{rel}: [signature].signer_kid must be a non-empty "
                    f"string (URI resolving to a key registry entry); got "
                    f"{signer_kid!r}"
                )
            cose_b64 = signature.get("cose_sign1_b64")
            if not isinstance(cose_b64, str) or not cose_b64.strip():
                errors.append(
                    f"{rel}: [signature].cose_sign1_b64 must be a non-empty "
                    f"base64 string; got {cose_b64!r}"
                )
            elif not DECLARATION_B64_PATTERN.fullmatch(cose_b64):
                errors.append(
                    f"{rel}: [signature].cose_sign1_b64 contains characters "
                    f"outside the base64 alphabet (RFC 4648 standard or "
                    f"URL-safe); got {cose_b64!r}"
                )


def check_declaration_supersedes_acyclic(
    errors: list[str],
    *,
    root: Path | None = None,
) -> None:
    """R15 — declaration `supersedes` chains MUST be acyclic, resolvable,
    AND temporal-in-force per Companion §A.6 rule 15.

    Walks every fixtures/declarations/<deployment-slug>/declaration.md,
    builds a directed graph keyed by `declaration_id` with edges
    `declaration_id → supersedes`, and rejects:

    - cycles (a chain that revisits an earlier `declaration_id`),
    - dangling references (a `supersedes` value not appearing as any
      declaration's `declaration_id`),
    - duplicate declaration_ids across the corpus (would silently mask
      a cycle through identifier reuse),
    - non-string `declaration_id` / `supersedes` values,
    - temporal-in-force violations: for each edge
      `successor -> predecessor` the predecessor MUST have been in force
      at `successor.effective_from`. The in-force window is
      `[effective_from, scope.time_bound)`; absent `scope.time_bound`
      (key absent per A.6 nullable-field convention) is open-ended.

    Per Companion §A.6 / Phase-1 convention: `supersedes` absent OR empty
    string denotes "no predecessor" (root of a chain); each declaration
    carries at most one `supersedes` value.

    DFS is iterative (explicit stack). The chain shape is single-parent,
    so the worst-case path length equals the number of declarations in
    the corpus; recursion would risk Python's 1000-frame limit on long
    chains. Iterative shape removes that footgun.
    """
    base = root if root is not None else DECLARATIONS
    if not base.exists():
        return
    paths = sorted(base.glob("*/declaration.md"))
    if not paths:
        return

    # Build (id → supersedes) map keyed by canonical declaration_id, plus
    # the temporal-window state needed for rule-15 enforcement.
    decl_supersedes: dict[str, str | None] = {}
    decl_origin: dict[str, Path] = {}
    decl_effective_from: dict[str, object] = {}
    decl_time_bound: dict[str, object | None] = {}
    for path in paths:
        rel = relpath(path)
        data = _extract_toml_frontmatter(path, errors)
        if data is None:
            continue
        declaration_id = data.get("declaration_id")
        if not isinstance(declaration_id, str) or not declaration_id.strip():
            errors.append(
                f"{rel}: declaration_id must be a non-empty string for "
                f"supersedes-graph membership; got {declaration_id!r}"
            )
            continue
        if declaration_id in decl_supersedes:
            errors.append(
                f"{rel}: declaration_id={declaration_id!r} is also used in "
                f"{relpath(decl_origin[declaration_id])}; declaration ids "
                f"MUST be unique across the corpus"
            )
            continue
        supersedes = data.get("supersedes")
        if supersedes is not None and not isinstance(supersedes, str):
            errors.append(
                f"{rel}: supersedes must be a string or absent; got "
                f"{type(supersedes).__name__}"
            )
            continue
        # Treat empty string and None as "no predecessor" per A.6 convention.
        if isinstance(supersedes, str) and not supersedes.strip():
            supersedes = None
        decl_supersedes[declaration_id] = supersedes
        decl_origin[declaration_id] = path

        # Capture the temporal-window endpoints. R11 separately enforces
        # `effective_from` shape; here we store whatever is present and
        # let R15's temporal check skip edges whose endpoints are not
        # comparable UTC datetimes (R11 will have already flagged the
        # shape error so we do not double-fire).
        decl_effective_from[declaration_id] = data.get("effective_from")
        scope = data.get("scope")
        if isinstance(scope, dict):
            decl_time_bound[declaration_id] = scope.get("time_bound")
        else:
            decl_time_bound[declaration_id] = None

    # Resolve dangling supersedes refs.
    for declaration_id, predecessor in decl_supersedes.items():
        if predecessor is not None and predecessor not in decl_supersedes:
            errors.append(
                f"{relpath(decl_origin[declaration_id])}: "
                f"supersedes={predecessor!r} does not resolve to any "
                f"declaration_id in the corpus"
            )

    # Iterative cycle detection with WHITE/GRAY/BLACK coloring. Each
    # declaration has at most one outgoing edge (chain, not tree), so the
    # walk from any starting node is a single path; iterative form is a
    # simple while-loop over the path_stack rather than the recursive
    # dual-color discipline.
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {k: WHITE for k in decl_supersedes}
    reported_cycles: set[tuple[str, ...]] = set()

    for start in decl_supersedes:
        if color[start] != WHITE:
            continue
        path_stack: list[str] = []
        node: str | None = start
        while node is not None:
            if color[node] == BLACK:
                # Joined an already-cleared chain; nothing more to do.
                break
            if color[node] == GRAY:
                # Cycle: the GRAY node is reachable from itself via the
                # current path_stack (path_stack always contains GRAY
                # nodes for the in-progress walk).
                loop_start = path_stack.index(node)
                cycle = tuple(path_stack[loop_start:]) + (node,)
                cycle_key = tuple(sorted(set(cycle)))
                if cycle_key not in reported_cycles:
                    reported_cycles.add(cycle_key)
                    errors.append(
                        f"{relpath(decl_origin[node])}: supersedes chain "
                        f"contains a cycle: {' -> '.join(cycle)}"
                    )
                break
            color[node] = GRAY
            path_stack.append(node)
            predecessor = decl_supersedes.get(node)
            if predecessor is None or predecessor not in decl_supersedes:
                # Reached a root or a dangling ref (already reported above).
                break
            node = predecessor
        # Mark every node on the in-progress path BLACK; future starts
        # that re-enter this chain short-circuit at the BLACK guard.
        for visited in path_stack:
            color[visited] = BLACK

    # Temporal-in-force enforcement (Companion §A.6 rule 15, second
    # half). For each edge `successor -> predecessor` whose endpoints
    # are both comparable UTC datetimes, assert the predecessor was in
    # force at the successor's `effective_from`:
    #
    #   predecessor.effective_from  <=  successor.effective_from
    #   AND (predecessor.scope.time_bound is None  OR
    #        successor.effective_from < predecessor.scope.time_bound).
    #
    # Window is half-open `[effective_from, time_bound)`: equal lower
    # bound is in, equal upper bound is out. Edges with non-datetime
    # endpoints are skipped — R11 is responsible for the shape error
    # and would double-fire here otherwise.
    for successor_id, predecessor_id in decl_supersedes.items():
        if predecessor_id is None or predecessor_id not in decl_supersedes:
            continue
        succ_eff_from = decl_effective_from.get(successor_id)
        pred_eff_from = decl_effective_from.get(predecessor_id)
        if not _is_utc_datetime(succ_eff_from) or not _is_utc_datetime(pred_eff_from):
            continue
        if pred_eff_from > succ_eff_from:
            errors.append(
                f"{relpath(decl_origin[successor_id])}: predecessor "
                f"declaration_id={predecessor_id!r} (effective_from="
                f"{pred_eff_from.isoformat()}) was not yet in force at "
                f"successor effective_from={succ_eff_from.isoformat()} "
                f"(Companion §A.6 rule 15 — supersedes chain temporal-in-force)"
            )
            continue
        pred_time_bound = decl_time_bound.get(predecessor_id)
        if pred_time_bound is not None and _is_utc_datetime(pred_time_bound):
            if succ_eff_from >= pred_time_bound:
                errors.append(
                    f"{relpath(decl_origin[successor_id])}: predecessor "
                    f"declaration_id={predecessor_id!r} was no longer in "
                    f"force at successor effective_from="
                    f"{succ_eff_from.isoformat()} "
                    f"(predecessor scope.time_bound="
                    f"{pred_time_bound.isoformat()}; window is half-open "
                    f"[effective_from, time_bound)) "
                    f"(Companion §A.6 rule 15 — supersedes chain temporal-in-force)"
                )


def check_vector_renumbering(errors: list[str]) -> None:
    """R16 — invoke the vector-prefix renumbering pre-merge guard.

    Defers to the sibling `check-vector-renumbering.py` script, which
    compares vector `<op>/NNN` prefixes on the current working tree
    against a base ref (default `origin/main`, override via
    `TRELLIS_RATIFICATION_REF`). The corpus has 63 vectors with
    derivation cross-references and Rust conformance test IDs; silent
    renumber would corrupt both.

    **Activation:** opt-in via `TRELLIS_CHECK_RENUMBERING=1`. The check
    is opt-in because local dev branches that have not yet been pushed
    cannot resolve the base ref, and a hard failure on every check-specs
    run would be a usability regression. CI sets the env var; Makefile
    target `check-specs-strict` sets it; local dev runs without it by
    default.
    """
    if os.environ.get("TRELLIS_CHECK_RENUMBERING") != "1":
        return
    script = REAL_ROOT / "scripts" / "check-vector-renumbering.py"
    if not script.exists():
        errors.append(
            f"TRELLIS_CHECK_RENUMBERING=1 was set but "
            f"{script.relative_to(REAL_ROOT)} is missing"
        )
        return
    import subprocess
    result = subprocess.run(
        ["python3", str(script)],
        capture_output=True,
        text=True,
        cwd=str(REAL_ROOT),
    )
    if result.returncode == 0:
        return
    # Either return code 1 (renumber detected) or 2 (base ref unresolvable).
    # Both are lint failures when the env opt-in is set — if you ask for the
    # check, you ask for it to actually run.
    for line in (result.stderr or result.stdout or "").splitlines():
        if line.strip():
            errors.append(f"vector-renumbering guard: {line.strip()}")
    if not result.stderr and not result.stdout:
        errors.append(
            f"vector-renumbering guard exited {result.returncode} with no "
            f"output"
        )


def check_tamper_kind_enum(
    errors: list[str],
    *,
    manifests: list[tuple[Path, dict]] | None = None,
) -> None:
    """R13 — every `op = "tamper"` manifest's `[expected.report].tamper_kind`
    MUST be a value enumerated in `TAMPER_KIND_ENUM`.

    The corpus authors a per-vector `tamper_kind` describing the verifier
    failure category the vector exercises. Values were de-facto consistent
    across the first batch of vectors but not normatively enumerated; drift
    in later batches would silently bifurcate the verifier-output vocabulary.
    This rule pins the contract: prose changes in Core §19.1 or a domain
    validator spec are fail-loud events, forcing matrix + Rust + Python to
    move together.

    The `manifests` kwarg is a test hook (parallel to
    `check_verify_report_consistency`).
    """
    iter_manifests = manifests if manifests is not None else vector_manifests()
    for manifest_path, manifest in iter_manifests:
        if manifest.get("op") != "tamper":
            continue
        rel = relpath(manifest_path)
        report = manifest.get("expected", {}).get("report")
        if not isinstance(report, dict):
            errors.append(
                f"{rel}: tamper manifest missing [expected.report] table"
            )
            continue
        if "tamper_kind" not in report:
            errors.append(
                f"{rel}: tamper manifest [expected.report] missing required "
                f"`tamper_kind` field (Core §19.1)"
            )
            continue
        kind = report["tamper_kind"]
        if not isinstance(kind, str):
            errors.append(
                f"{rel}: tamper_kind must be a string; got {type(kind).__name__}"
            )
            continue
        if kind not in TAMPER_KIND_ENUM:
            errors.append(
                f"{rel}: tamper_kind={kind!r} is not in the verifier enum; "
                f"allowed values are {sorted(TAMPER_KIND_ENUM)}"
            )


def check_hpke_ephemeral_uniqueness(
    errors: list[str],
    *,
    payloads: list[tuple[Path, dict]] | None = None,
) -> None:
    """R17 — every HPKE wrap MUST use a unique X25519 `ephemeral_pubkey`
    (Core §9.4).

    Core §9.4 pins ephemeral-key freshness on the producer side:

      "Every `KeyBagEntry` (hereafter 'wrap') MUST use a fresh X25519
       ephemeral keypair, unique across every wrap in the containing
       ledger scope. ... Reusing an ephemeral private key across wraps,
       within the same event, across events in the same ledger scope, or
       across ledger scopes, is a non-conformance."

    Because the persisted `ephemeral_pubkey` is the single-shot HPKE
    encapsulated key derived from the ephemeral private scalar, two
    identical `ephemeral_pubkey` values across distinct wraps imply the
    private scalar was reused — collapsing the three sub-cases above
    into one detectable byte equality. The Phase-1 HPKE suite (Base
    mode, DHKEM(X25519, HKDF-SHA256), Core §9.4) and the §9.4 carve-out
    for fixture-pinned ephemerals make this a corpus-authoring concern
    rather than a verifier obligation: §19.1 has no `ephemeral_reuse`
    `tamper_kind`, and a verifier seeing only one event has no
    prior-state to compare against. Production-side uniqueness rests on
    `OsRng` in `trellis-hpke::wrap_dek`; this lint closes the
    fixture-side authoring gap (a copy-paste mistake or a buggy
    generator script silently reusing a pinned ephemeral across
    vectors).

    Placement is `check-specs.py` rather than `trellis-verify` (Core
    §16 verification independence — verifiers are stateless across
    events) and rather than `trellis-hpke` (the production wrap path
    already uses fresh randomness via `setup_sender`; the gap is the
    `wrap_dek_with_pinned_ephemeral` carve-out path and any hand-rolled
    fixture that did not flow through `wrap_dek` at all).

    Within-event check (§9.4 second clause — "in an event with N
    recipients the `key_bag` contains N `KeyBagEntry` rows with N
    distinct `ephemeral_pubkey` values"): a `key_bag.entries` list with
    a duplicate `ephemeral_pubkey` is reported as a within-event
    violation, distinct from cross-event reuse so the diagnostic message
    points to the right §9.4 clause.

    Algorithm:
      1. Group payload artifacts by their containing vector directory.
         The shared `vector_event_payloads()` walker yields the same
         logical event multiple times (one per CBOR view —
         `input-author-event-hash-preimage.cbor`,
         `expected-event-payload.cbor`, `expected-event.cbor`); these
         are byte-identical re-encodings of the same wrap, NOT reuse.
      2. For each vector, collect the set of `ephemeral_pubkey` values
         emitted by its wraps (collapsing the multiple-CBOR-view
         duplicates).
      3. Within-event: any `ephemeral_pubkey` appearing more than once
         inside a single `key_bag.entries` list is reported.
      4. Cross-vector: any `ephemeral_pubkey` appearing in two distinct
         vector dirs is reported.

    Test hook: `payloads` is a list of `(artifact_path, EventPayload)`
    tuples parallel to `vector_event_payloads()`. Vector grouping is
    `artifact_path.parent`, which matches every committed
    `fixtures/vectors/append/*` layout today (the only artifacts under
    `_inputs/` and `_keys/` are non-event payloads / COSE keys, not
    EventPayload-shaped CBOR).
    """
    iter_payloads = (
        payloads if payloads is not None else vector_event_payloads(errors)
    )

    # Group artifacts by vector dir.
    by_vector: dict[Path, list[dict]] = {}
    for artifact_path, payload in iter_payloads:
        if not isinstance(payload, dict):
            continue
        vector_dir = artifact_path.parent
        by_vector.setdefault(vector_dir, []).append(payload)

    # ephemeral_pubkey_bytes → (first vector dir, scope_bytes seen there).
    seen: dict[bytes, tuple[Path, bytes]] = {}

    for vector_dir, vector_payloads in sorted(by_vector.items()):
        # Pairs canonicalized within this vector: collapses the multiple-
        # CBOR-view duplicates so byte-identical re-encodings of a single
        # wrap do not look like reuse.
        canonical_pairs: set[tuple[bytes, bytes]] = set()
        # Within-event duplicates: same ephemeral_pubkey in one entries[]
        # list. Tracked separately to surface §9.4 clause (a) distinctly.
        within_event_dupes: set[tuple[bytes, bytes]] = set()

        for payload in vector_payloads:
            scope = payload.get("ledger_scope")
            scope_bytes = (
                bytes(scope) if isinstance(scope, (bytes, bytearray)) else b""
            )
            kb = payload.get("key_bag")
            if not isinstance(kb, dict):
                continue
            entries = kb.get("entries")
            if not isinstance(entries, list):
                continue

            seen_in_event: set[bytes] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                ep = entry.get("ephemeral_pubkey")
                if not isinstance(ep, (bytes, bytearray)):
                    continue
                ep_bytes = bytes(ep)
                if ep_bytes in seen_in_event:
                    within_event_dupes.add((scope_bytes, ep_bytes))
                seen_in_event.add(ep_bytes)
                canonical_pairs.add((scope_bytes, ep_bytes))

        # Within-event diagnostic — §9.4 "N recipients require N distinct
        # ephemeral_pubkey values".
        for scope_bytes, ep_bytes in sorted(within_event_dupes):
            errors.append(
                f"{relpath(vector_dir)}: ephemeral_pubkey "
                f"{ep_bytes.hex()[:16]}... duplicated within a single key_bag "
                f"(Core §9.4 — N recipients MUST have N distinct "
                f"ephemeral_pubkey values)"
            )

        # Cross-vector diagnostic — §9.4 reuse "across events in the same
        # ledger scope, or across ledger scopes". One message per
        # collision; same-scope vs cross-scope is shown inline.
        for scope_bytes, ep_bytes in sorted(canonical_pairs):
            prior = seen.get(ep_bytes)
            if prior is None:
                seen[ep_bytes] = (vector_dir, scope_bytes)
                continue
            prior_vector, prior_scope = prior
            if prior_vector == vector_dir:
                continue  # Same vector dir; collapsed canonical re-encoding.
            scope_clause = (
                f"in ledger_scope {scope_bytes!r}"
                if scope_bytes == prior_scope
                else f"across ledger scopes ({prior_scope!r} and {scope_bytes!r})"
            )
            errors.append(
                f"{relpath(vector_dir)}: ephemeral_pubkey "
                f"{ep_bytes.hex()[:16]}... reused {scope_clause} (also "
                f"appears in {relpath(prior_vector)}); Core §9.4 requires "
                f"every wrap to use a fresh X25519 ephemeral keypair, "
                f"unique across every wrap"
            )


def check_verify_report_consistency(
    errors: list[str],
    *,
    manifests: list[tuple[Path, dict]] | None = None,
) -> None:
    """R12 — verify manifest description and expected.report must agree.

    For every `op = "verify"` manifest, cross-check the failure-kind tokens in
    `description` against the three booleans in `[expected.report]`, per
    Core §19 step semantics:

    - `"fatal"` cites one of the §19 abort paths (2.a/2.b/2.c, 3.f, etc.);
      the verifier stops with `structure_verified = false` and, by convention
      in this fixture corpus, the other two booleans are also `false`.
    - `"localizable"` cites one of the continue-on-failure paths (5.c, 5.d,
      7.b, 8); the verifier keeps going and returns
      `structure_verified = true` but `integrity_verified = false`. Readability
      is typically `true` for these fixtures (payloads decode fine) but we
      do not pin it here — readability is independent of integrity.

    The rule catches fixture-authoring mistakes like declaring a step 5.c
    localizable failure while accidentally expecting
    `structure_verified = false`. It is deliberately lenient: happy-path
    vectors (no "fatal" / "localizable" tokens) are untouched, and ambiguous
    descriptions that list both tokens are flagged rather than silently
    accepting whichever matches first.

    The `manifests` kwarg is a test hook: callers normally let the function
    discover manifests via `vector_manifests()`, but tests pass a synthetic
    list so they can exercise individual scenarios without building a full
    TRELLIS_LINT_ROOT scenario tree.
    """
    iter_manifests = manifests if manifests is not None else vector_manifests()
    for manifest_path, manifest in iter_manifests:
        if manifest.get("op") != "verify":
            continue
        rel = relpath(manifest_path)
        description = manifest.get("description", "")
        if not isinstance(description, str):
            continue
        description_lower = description.lower()
        cites_fatal = "fatal" in description_lower
        cites_localizable = "localizable" in description_lower

        if cites_fatal and cites_localizable:
            errors.append(
                f"{rel}: description cites both 'fatal' and 'localizable' — "
                f"pick one per §19 failure classification"
            )
            continue

        report = manifest.get("expected", {}).get("report")
        if not isinstance(report, dict):
            if cites_fatal or cites_localizable:
                errors.append(
                    f"{rel}: description cites a §19 "
                    f"{'fatal' if cites_fatal else 'localizable'} failure but "
                    f"[expected.report] is missing or malformed"
                )
            continue

        structure = report.get("structure_verified")
        integrity = report.get("integrity_verified")
        readability = report.get("readability_verified")

        if cites_fatal:
            if structure is not False or integrity is not False or readability is not False:
                errors.append(
                    f"{rel}: description cites a §19 fatal failure so "
                    f"[expected.report] must be structure_verified=false, "
                    f"integrity_verified=false, readability_verified=false; "
                    f"got structure_verified={structure!r}, "
                    f"integrity_verified={integrity!r}, "
                    f"readability_verified={readability!r}"
                )
        elif cites_localizable:
            if structure is not True or integrity is not False:
                errors.append(
                    f"{rel}: description cites a §19 localizable failure so "
                    f"[expected.report] must be structure_verified=true, "
                    f"integrity_verified=false; got "
                    f"structure_verified={structure!r}, "
                    f"integrity_verified={integrity!r}"
                )


def reason_code_tables(text_companion: str | None = None, text_adr: str | None = None) -> dict[str, dict[int, str]]:
    """Parse reason-code tables for the three Phase-1 ReasonCode families.

    Returns ``{family: {code: registered_name}}`` keyed by:
      - ``"custody-model"``         — Companion §A.5.1
      - ``"disclosure-profile"``    — Companion §A.5.2
      - ``"erasure-evidence"``      — ADR 0005 §"Reason codes" (Companion §20 once promoted)

    Each table row in spec markdown follows the form::

        | <code>   | `<registered-name>` (...optional gloss...) |

    The parser anchors on the section heading (``A.5.1`` / ``A.5.2`` / the ADR
    heading ``Reason codes``) and consumes consecutive ``| <int> | ... |`` rows
    until the table ends.

    The ``text_companion`` / ``text_adr`` kwargs are test hooks — the regular
    callsite reads from disk via ``SPECS`` / ``REAL_ROOT``.
    """
    if text_companion is None:
        text_companion = read(SPECS / "trellis-operational-companion.md")
    if text_adr is None:
        adr_path = REAL_ROOT / "thoughts" / "adr" / "0005-crypto-erasure-evidence.md"
        text_adr = read(adr_path) if adr_path.exists() else ""

    tables: dict[str, dict[int, str]] = {
        "custody-model": {},
        "disclosure-profile": {},
        "erasure-evidence": {},
    }

    # Match a single table row of the form:  | <int> | `<name>`(...) |
    row_re = re.compile(
        r"^\|\s*(\d+)\s*\|\s*`([a-zA-Z0-9-]+)`",
        re.MULTILINE,
    )

    def _parse_table_after(text: str, heading_re: re.Pattern[str], family: str) -> None:
        m = heading_re.search(text)
        if not m:
            return
        # Limit row scan to the section between this heading and the next ``###``
        # / ``##`` heading or end of text — prevents matching unrelated tables.
        end_re = re.compile(r"^#{1,3}\s", re.MULTILINE)
        end_match = end_re.search(text, m.end())
        slice_end = end_match.start() if end_match else len(text)
        section = text[m.end():slice_end]
        for row in row_re.finditer(section):
            code = int(row.group(1))
            name = row.group(2)
            tables[family][code] = name

    # Companion §A.5.1 custody-model — the row "Reason codes (registered, ...)"
    # heading is plain text, not a markdown header; anchor on the literal phrase
    # to scope the row scan.
    a51_heading = re.compile(
        r"^### A\.5\.1 Custody-Model Transition.*?Reason codes \(registered",
        re.MULTILINE | re.DOTALL,
    )
    _parse_table_after(text_companion, a51_heading, "custody-model")

    a52_heading = re.compile(
        r"^### A\.5\.2 Disclosure-Profile.*?Reason codes \(registered",
        re.MULTILINE | re.DOTALL,
    )
    _parse_table_after(text_companion, a52_heading, "disclosure-profile")

    # ADR 0005 §"Reason codes (registered, extensible)".
    adr_heading = re.compile(
        r"^### Reason codes \(registered, extensible\)",
        re.MULTILINE,
    )
    _parse_table_after(text_adr, adr_heading, "erasure-evidence")

    return tables


# Family-detection markers in derivation.md / generator source. The lint maps
# each derivation/generator file to a single family by the first family marker
# that appears; ambiguous cases (multiple families in one file) are diagnosed.
_FAMILY_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("custody-model",      ("CustodyModelTransitionPayload", "Appendix A.5.1", "trellis.custody-model-transition.v1")),
    ("disclosure-profile", ("DisclosureProfileTransitionPayload", "Appendix A.5.2", "trellis.disclosure-profile-transition.v1")),
    ("erasure-evidence",   ("ErasureEvidencePayload", "trellis.erasure-evidence.v1", "ADR 0005")),
)


def _detect_reason_code_family(blob: str) -> str | None:
    """Return the family name whose marker appears first in ``blob``, or None."""
    earliest: tuple[int, str] | None = None
    for family, markers in _FAMILY_MARKERS:
        for marker in markers:
            idx = blob.find(marker)
            if idx == -1:
                continue
            if earliest is None or idx < earliest[0]:
                earliest = (idx, family)
    return earliest[1] if earliest is not None else None


# Match a derivation.md table row of the form:
#     | `reason_code` | `<int>` (<name-with-dashes>) | ...
# OR an inline body form:
#     `reason_code = <int>` (`<name-with-dashes>` ...)
# OR a generator comment of the form:
#     REASON_CODE = <int>                     # <name-with-dashes>
_DERIVATION_TABLE_RE = re.compile(
    r"`reason_code`\s*\|\s*`?(\d+)`?\s*\(\s*`?([a-zA-Z0-9-]+)`?",
)
_DERIVATION_BODY_RE = re.compile(
    r"`reason_code\s*=\s*(\d+)`\s*\(\s*`([a-zA-Z0-9-]+)`",
)
_GENERATOR_COMMENT_RE = re.compile(
    r"^\s*REASON_CODE\s*=\s*(\d+)\s*#\s*([a-zA-Z0-9-]+)",
    re.MULTILINE,
)
# A.5.1 / A.5.2 prose-form citations like "registered in A.5.1 reason-code table"
# are used as supporting context but not as a (code, name) source.


def check_reason_code_corpus_parity(
    errors: list[str],
    *,
    derivation_files: list[tuple[Path, str]] | None = None,
    generator_files: list[tuple[Path, str]] | None = None,
    tables: dict[str, dict[int, str]] | None = None,
) -> None:
    """R19 — every fixture-side ``reason_code`` annotation MUST agree with
    the registered table for its family (Core §6.9 + Companion §A.5.1 / §A.5.2
    + ADR 0005 §"Reason codes").

    ReasonCode tables are per-family registries under Core §6.9 — Custody-Model
    Transition (Companion §A.5.1), Disclosure-Profile Transition (Companion
    §A.5.2), Erasure Evidence (ADR 0005, Phase-1 home). The tables are the
    authority; fixture annotations are the dependent corpus. Drift between the
    two would silently bifurcate the wire — a verifier reading the table sees
    one meaning, a fixture-author reading the derivation sees another.

    The lint mirrors Wave 15's R13 ``tamper_kind`` corpus-vs-table parity
    check: closed under the same authoring discipline (table-first, fixture-
    second, with matrix updates moving with the table). Closes the gap that
    let TODO item #29's drift (§A.5.2 codes vs. fixture annotations) land
    Wave 15 undetected.

    Algorithm:
      1. Parse the three tables from spec markdown into
         ``{family: {code: registered_name}}``.
      2. Walk every ``derivation.md`` under ``fixtures/vectors/`` and every
         ``gen_*.py`` under ``fixtures/vectors/_generator/`` whose source
         names a registered family marker.
      3. For each ``(code, annotated_name)`` pair found in a file, look up
         the table for the file's detected family. Annotation MUST match
         the registered name exactly. Any divergence — mismatch, unregistered
         code, ambiguous family — is a lint failure naming the file, the
         family, the (code, annotated, registered) triple, and the table
         section.
      4. The ``255 = Other`` cross-family invariant per Core §6.9 is enforced
         transparently: code ``255`` MUST be ``Other`` (or ``other`` — table
         storage normalizes by lowercased compare; we report the registered
         spelling).

    Test hooks: ``derivation_files`` / ``generator_files`` accept lists of
    ``(path, contents)`` tuples; ``tables`` accepts a pre-built family registry.
    Default callsite reads from disk.
    """
    if tables is None:
        tables = reason_code_tables()

    def _walk_default_derivations() -> list[tuple[Path, str]]:
        out: list[tuple[Path, str]] = []
        for path in sorted(FIXTURES.rglob("derivation.md")):
            try:
                out.append((path, path.read_text(encoding="utf-8")))
            except OSError:
                continue
        return out

    def _walk_default_generators() -> list[tuple[Path, str]]:
        out: list[tuple[Path, str]] = []
        gen_root = FIXTURES / "_generator"
        if not gen_root.exists():
            return out
        for path in sorted(gen_root.glob("gen_*.py")):
            try:
                out.append((path, path.read_text(encoding="utf-8")))
            except OSError:
                continue
        return out

    deriv = derivation_files if derivation_files is not None else _walk_default_derivations()
    gens  = generator_files  if generator_files  is not None else _walk_default_generators()

    def _check_blob(path: Path, blob: str, *, source_label: str, patterns: list[re.Pattern[str]]) -> None:
        family = _detect_reason_code_family(blob)
        # Find every (code, name) pair in this file. If there are any pairs
        # but no detectable family, that itself is a lint failure — the file
        # is annotating reason codes without anchoring which family they belong
        # to, which is exactly the drift surface the lint exists to catch.
        pairs: list[tuple[int, str]] = []
        for pat in patterns:
            for m in pat.finditer(blob):
                pairs.append((int(m.group(1)), m.group(2)))
        if not pairs:
            return
        rel = relpath(path)
        if family is None:
            errors.append(
                f"{rel}: {source_label} cites reason_code {pairs!r} but the "
                f"file does not name a registered family (custody-model / "
                f"disclosure-profile / erasure-evidence) — Core §6.9 forbids "
                f"family-ambiguous reason-code annotations"
            )
            return
        registry = tables.get(family, {})
        if not registry:
            errors.append(
                f"{rel}: {source_label} family={family!r} but the registry "
                f"table is empty — could not parse the source-of-truth table "
                f"(Companion §A.5.x / ADR 0005)"
            )
            return
        for code, annotated in pairs:
            registered = registry.get(code)
            if registered is None:
                errors.append(
                    f"{rel}: {source_label} cites reason_code={code} "
                    f"({annotated!r}) but family {family!r} has no code "
                    f"{code} registered (Core §6.9 — verifiers MUST reject "
                    f"unregistered codes)"
                )
                continue
            if annotated.lower() != registered.lower():
                errors.append(
                    f"{rel}: {source_label} reason_code={code} annotated as "
                    f"{annotated!r} but family {family!r} table registers "
                    f"code {code} = {registered!r} "
                    f"(Companion §A.5.1 / §A.5.2 / ADR 0005)"
                )

    derivation_patterns = [_DERIVATION_TABLE_RE, _DERIVATION_BODY_RE]
    generator_patterns  = [_GENERATOR_COMMENT_RE]

    for path, blob in deriv:
        _check_blob(path, blob, source_label="derivation", patterns=derivation_patterns)
    for path, blob in gens:
        _check_blob(path, blob, source_label="generator", patterns=generator_patterns)


def check_key_entry_phase_1_class_lint(warnings: list[str]) -> None:
    """R18 — Core §8.7.4 Phase-1 lint discipline.

    Per ADR 0006 §"Phase-1 lint discipline" + Core §8.7.4: a `KeyEntry` whose
    `kind` is one of the four reserved non-signing classes (`tenant-root`,
    `scope`, `subject`, `recovery`) MUST emit a Phase-1 lint warning. The
    entry remains wire-valid (envelope reservation per Core §8.7); the
    warning surfaces premature use of a Phase-2+ surface so an operator
    notices when their fixture corpus drifts off Phase-1 scope.

    Algorithm:
      1. Walk every committed key-registry artifact under `fixtures/vectors/`.
         Pattern matches both the export-bound name `030-signing-key-registry.cbor`
         and per-vector inputs like `input-signing-key-registry-after.cbor` /
         `input-signing-key-registry-before.cbor`.
      2. Decode each as a dCBOR array of registry entry maps.
      3. For each entry: if a top-level `kind` text-string field is present and
         its value is one of the four reserved non-signing literals, append a
         warning that names the vector + entry index + class.
      4. Unknown extension `tstr` kinds are NOT warned at this level; ADR 0006
         §"Phase-1 lint discipline" scopes the warning to the four reserved
         non-signing classes (the reservation-vs-extension distinction).

    Placement is `check-specs.py` rather than `trellis-verify` because verifier
    failure here is forbidden by ADR 0006: the wire admits these entries, the
    verifier accepts them, and only the operator-side authoring tool warns.
    Phase-2+ activation lifts this warning per ADR 0006 §"Phase 2 evolution".
    """

    try:
        import cbor2  # type: ignore[import-not-found]
    except ImportError:
        # cbor2 is the standard generator dep (also listed in
        # GENERATOR_ALLOWED_IMPORTS); if it isn't installed locally the rest
        # of the lint suite still runs and this check is silently skipped.
        return

    reserved_non_signing = {"tenant-root", "scope", "subject", "recovery"}

    candidate_globs = (
        "030-signing-key-registry.cbor",
        "input-signing-key-registry*.cbor",
    )

    for vector_dir in sorted(FIXTURES.rglob("manifest.toml")):
        # vector_dir.parent is the vector directory.
        vec_root = vector_dir.parent
        for pattern in candidate_globs:
            for registry_path in vec_root.glob(pattern):
                try:
                    raw = registry_path.read_bytes()
                    decoded = cbor2.loads(raw)
                except Exception:  # noqa: BLE001
                    # Decode failures are diagnosed by other checks; skip silently here.
                    continue
                if not isinstance(decoded, list):
                    continue
                for index, entry in enumerate(decoded):
                    if not isinstance(entry, dict):
                        continue
                    kind = entry.get("kind")
                    if not isinstance(kind, str):
                        continue
                    # Core §8.7.6: normalize the legacy `"wrap"` synonym so the
                    # diagnostic carries the canonical class name.
                    norm = "subject" if kind == "wrap" else kind
                    if norm in reserved_non_signing:
                        rel = registry_path.relative_to(ROOT)
                        warnings.append(
                            f"{rel}: KeyEntry[{index}] declares kind=\"{norm}\" "
                            f"(non-signing); Phase-1 runtime is signing-only per "
                            f"Core §8.7.4 + ADR 0006 — wire is admitted, runtime "
                            f"warns until Phase-2+ activates the class."
                        )


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    pending_invariants, pending_matrix_rows = load_pending_invariants(errors)
    pending_projection_drills = load_pending_projection_drills(errors)
    pending_model_checks = load_pending_model_checks(errors)
    check_forbidden_terms(errors)
    check_core_section_references(errors)
    check_requirement_ids(errors)
    check_traceability_anchors(errors)
    check_bare_profile(errors)
    check_archived_inputs(errors)
    check_vector_naming(errors)
    check_vector_manifest_identity(errors)
    check_vector_manifest_coverage_ids(errors)
    check_vector_lifecycle_fields(errors)
    check_vector_coverage_prefixes(errors)
    check_vector_coverage(errors, pending_matrix_rows)
    check_tr_op_coverage(errors, pending_matrix_rows)
    check_projection_rebuild_drill_coverage(errors, pending_projection_drills)
    check_spec_cross_ref_rows(errors, warnings)
    check_model_check_evidence(errors, pending_model_checks)
    check_vector_declared_coverage(errors, warnings)
    check_invariant_coverage(errors, pending_invariants)
    check_vector_manifest_paths(errors)
    check_event_type_registry(errors)
    check_transition_cddl_cross_refs(errors)
    check_declaration_docs(errors)
    check_declaration_supersedes_acyclic(errors)
    check_generator_imports(errors)
    check_vector_renumbering(errors)
    check_tamper_kind_enum(errors)
    check_hpke_ephemeral_uniqueness(errors)
    check_reason_code_corpus_parity(errors)
    check_key_entry_phase_1_class_lint(warnings)
    check_verify_report_consistency(errors)

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("Trellis spec checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
