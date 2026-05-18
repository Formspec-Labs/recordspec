# Derivation — `verify/023-bundle-unbound-member`

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
