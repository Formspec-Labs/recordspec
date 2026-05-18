"""Generate Trellis verify vector `verify/023-bundle-unbound-member`.

Authoring aid only. The committed fixture bytes and derivation notes are the
evidence surface; this script exists so the ZIP bytes are reproducible.

Construction
------------
Start from the smallest committed happy-path export
(`export/001-two-event-chain/expected-export.zip`) and inject ONE extra
archive member (`999-stray.bin`) under the existing export-root directory.
The stray member is not in the §18.2 admitted set, not named by any
manifest top-level digest / registry binding / event content_hash /
`interop_sidecars[].path`, and not bound by any registered manifest
extension.

Expected verdict (Core §19 step 3.i, TR-CORE-181)
-------------------------------------------------
The substrate Core sweep emits `bundle_unbound_member` (blocking) and
`integrity_verified` drops to false. Substrate structure / readability
verification still pass — the ZIP parses, the registry resolves, and
manifest digests over registered members still match. Mirrors the
existing Rust unit test at
`integrity-stack/crates/integrity-verify/src/trellis/export.rs::
verify_export_zip_flags_stray_archive_member_as_bundle_unbound_member`
and the Python mirror at
`trellis-py/tests/test_bundle_unbound_member.py`.

Conformance routing
-------------------
The fixture's `first_failure_kind` is `bundle_unbound_member`, which is
NOT in the conformance harness's WOS allowlist (`is_wos_kind` at
`trellis/crates/trellis-conformance/src/lib.rs:508`). Routing stays on
the substrate Core lane (`integrity_verify::trellis::verify_export_zip`)
per the §19 step 3.i invariant pinned by Wave 4's
`bundle_unbound_member_routes_to_substrate_lane` guard test
(commit 47e6c58).
"""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib.byte_utils import deterministic_zipinfo  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
SOURCE_EXPORT = ROOT / "export" / "001-two-event-chain" / "expected-export.zip"
OUT_DIR = ROOT / "verify" / "023-bundle-unbound-member"
STRAY_MEMBER_PATH = "999-stray.bin"
STRAY_BYTES = b"stray bytes"


def inject_stray_member(zip_bytes: bytes, stray_path: str, stray_bytes: bytes) -> bytes:
    """Rebuild a deterministic export ZIP with one extra stray member.

    Mirror of Rust `inject_stray_member` at `export.rs` and the Python test
    helper at `trellis-py/tests/test_bundle_unbound_member.py::
    _inject_stray_member`. The stray member lives under the same export-root
    directory the source ZIP already uses — `parse_export_zip` requires
    exactly one root.

    Uses `deterministic_zipinfo` (Core §18.1 — STORED, no extra field,
    flag_bits=0, external_attr=0, fixed mod time) so the output ZIP is
    byte-reproducible across runs.
    """
    source = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    try:
        infos = source.infolist()
        root = None
        for info in infos:
            if "/" in info.filename:
                root = info.filename.split("/", 1)[0]
                break
        assert root is not None, "source export must have a single root directory"

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as dest:
            arcnames: list[tuple[str, bytes]] = []
            for info in infos:
                with source.open(info) as fh:
                    arcnames.append((info.filename, fh.read()))
            arcnames.append((f"{root}/{stray_path}", stray_bytes))
            arcnames.sort(key=lambda kv: kv[0])
            for arcname, data in arcnames:
                assert arcname.isascii(), arcname
                dest.writestr(deterministic_zipinfo(arcname), data)
            for info in dest.filelist:
                info.external_attr = 0
    finally:
        source.close()
    return buffer.getvalue()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    source_bytes = SOURCE_EXPORT.read_bytes()
    tampered = inject_stray_member(source_bytes, STRAY_MEMBER_PATH, STRAY_BYTES)
    (OUT_DIR / "input-export.zip").write_bytes(tampered)

    write_text(
        OUT_DIR / "manifest.toml",
        '''id          = "verify/023-bundle-unbound-member"
op          = "verify"
status      = "active"
description = """Negative verify vector for Core §19 step 3.i `bundle_unbound_member` (TR-CORE-181). Starts from `export/001-two-event-chain/expected-export.zip` and injects one extra archive member (`999-stray.bin`) under the export-root directory. The stray member is not in the §18.2 admitted set, not bound by any manifest top-level digest, registry binding, event content_hash, `interop_sidecars[].path`, or registered manifest extension. Verifier emits `bundle_unbound_member` (blocking) and `integrity_verified = false`; substrate `structure_verified` and `readability_verified` still pass."""

[coverage]
tr_core = ["TR-CORE-181"]

[inputs]
export_zip = "input-export.zip"

[expected.report]
structure_verified   = true
integrity_verified   = false
readability_verified = true
first_failure_kind   = "bundle_unbound_member"
failing_event_id     = "999-stray.bin"

[derivation]
document = "derivation.md"
''',
    )
    write_text(
        OUT_DIR / "derivation.md",
        """# Derivation — `verify/023-bundle-unbound-member`

This fixture starts from `export/001-two-event-chain/expected-export.zip` —
the smallest committed happy-path export — and injects one extra archive
member (`999-stray.bin`, payload `b"stray bytes"`) under the existing
export-root directory. No other bytes change: the `000-manifest.cbor`
COSE_Sign1 envelope, the events ledger, checkpoints, inclusion / consistency
proofs, the signing-key registry, and the domain registry binding are all
untouched.

`999-stray.bin` is not in the Core §18.2 admitted member set, not named by
any top-level manifest digest field, not referenced by any registry
binding, not the `content_hash` of any event, not listed under
`interop_sidecars[].path`, and not bound by any registered manifest
extension. Per Core §19 step 3.i (TR-CORE-181), the verifier's
post-extension archive sweep MUST surface `bundle_unbound_member` with
the stray member's path as the failure location, and MUST drive
`integrity_verified` to false.

Substrate `structure_verified` and `readability_verified` remain true:
`parse_export_zip` admits the archive (one export-root directory, every
entry STORED with deterministic ZIP metadata), the signing-key registry
parses, the manifest COSE signature verifies, and every registered
member's digest still matches the manifest binding. Only the §19 step
3.i sweep fails.

Routing
-------

`bundle_unbound_member` is a Core-level normative claim (`integrity-verify`
sweep at `integrity-stack/crates/integrity-verify/src/trellis/export.rs:981`
and its Python mirror at
`trellis/trellis-py/src/trellis_py/verify.py:5106`). The conformance
harness routes the fixture to the substrate lane via
`integrity_verify::trellis::verify_export_zip` because
`bundle_unbound_member` is intentionally absent from `is_wos_kind`
(`trellis/crates/trellis-conformance/src/lib.rs:508`); the
`bundle_unbound_member_routes_to_substrate_lane` guard test
(commit 47e6c58) pins that absence.

Cross-runtime parity
--------------------

The same archive is replayed under both runtimes:

- Rust: `cargo nextest run -p trellis-conformance` replays the fixture
  through `verify_export_zip` (substrate lane) and asserts
  `first_failure_kind = "bundle_unbound_member"`,
  `integrity_verified = false`, location `"999-stray.bin"`.
- Python: `python3 -m pytest trellis-py/tests/` exercises
  `trellis_py.verify.verify_export_zip` on the same archive shape (the
  unit tests at `test_bundle_unbound_member.py` build the archive
  in-memory from this same source; this fixture is the committed,
  on-disk byte-evidence counterpart).
- Cross-runtime gate: `python3 scripts/check_cross_runtime_parity.py`
  registers fixture 023 in a substrate export-verifier subgate (NOT the
  WOS `signed-acts-projection` gate) and asserts both runtimes localize
  the stray member to `999-stray.bin` and emit
  `bundle_unbound_member` with `integrity_verified = false`.

Promotes TR-CORE-181 from "evidence-pending" to "evidenced via test
vector" (the matrix row update lands in Wave 6, not in this commit).
""",
    )
    print(f"wrote verify/023-bundle-unbound-member  zip_len={len(tampered)} bytes")


if __name__ == "__main__":
    main()
