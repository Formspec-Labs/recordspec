# Trellis Ratification Checklist

## Purpose

Define a concrete stopping condition for moving [`../specs/trellis-core.md`](../specs/trellis-core.md) and [`../specs/trellis-operational-companion.md`](../specs/trellis-operational-companion.md) from Phase 1 drafts to ratified normative specs.

The acceptance bar is the **stranger test** from [`../specs/trellis-agreement.md`](../specs/trellis-agreement.md) §10: a second implementor reads Agreement + Core + Operational Companion, then implements `append`, `verify`, and `export` against fixtures without asking which document wins or how to encode a signed byte.

## Gate label crosswalk (refactoring tracker)

Normative **ratification** gates below (G-1…G-6, C/O/M-*) describe **spec-era stranger-test closure**. The stack refactor tracker ([`../../TRELLIS-WOS-REFACTOR-TODO.md`](../../TRELLIS-WOS-REFACTOR-TODO.md#gates)) reuses labels **G-4…G-7** only for **post-integrity-stack protocol trains** (conformance corpus, `integrity-verify-parity`, export emitter sync, cross-stack bundle walker). **Ordinals do not line up by number** — ratification **G-6** (spec lint) is unrelated to refactor **G-6** (emitter parity); ratification **G-5** (Python stranger vs spec) is unrelated to refactor **G-5** (`integrity-verify-parity`). Use the tables below, never `G-n` equality alone. **Implemented / wired-in-CI / product-covering** for refactor rows is defined only in the parent tracker’s [refactor gate evidence matrix (I / C / P)](../../TRELLIS-WOS-REFACTOR-TODO.md#refactor-gate-evidence-matrix-i--c--p) under [Gates](../../TRELLIS-WOS-REFACTOR-TODO.md#gates) — ratification checkboxes here do not encode that rubric.

### Ratification G-1…G-6 → refactor tracker

| Ratification gate | One-line meaning | Refactor tracker gate(s) |
| --- | --- | --- |
| **G-1** | Normalization handoff groups A–D closed | — *(spec program only)* |
| **G-2** | Phase-1 invariant MUST coverage + companion/matrix audits | — *(spec program only)* |
| **G-3** | Byte-exact vectors under `fixtures/vectors/` | Supplies corpus consumed by refactor **G-4**; cross-stack bundles exercised additionally by refactor **G-7** |
| **G-4** | Rust reference workspace builds; every vector passes | **Refactor G-4** — `trellis-conformance` committed corpus replay (same intent, integrity-stack layout) |
| **G-5** | Second implementation byte-matches (Python stranger reads specs only) | **Not** refactor **G-5**. Refactor **G-5** is Python ↔ Rust `integrity-verify` parity (`integrity-verify-parity`) — overlapping goals, different artifact |
| **G-6** | `check-specs.py` lint clean | **Not** refactor **G-6**. Refactor **G-6** is export emitter parity (Rust writer ↔ `gen_export_001.py` ↔ verifier) |

### Refactor G-4…G-7 → ratification checklist

| Refactor gate | One-line meaning | Ratification checklist anchor |
| --- | --- | --- |
| **G-4** | `trellis-conformance` byte-exact replay over Trellis fixture corpus | **G-4** reference implementation + **G-3** vector corpus |
| **G-5** | `integrity-verify-parity` — Python verifier oracle ↔ Rust `integrity-verify` | Related to stranger-test discipline; closest ratification anchor **G-5** (different procedure) |
| **G-6** | Emitter parity — `trellis-export-writer` ↔ Python generator ↔ verifier round-trip | No ratification **G-6** tie-in — orthogonal to spec lint (**ratification G-6**) |
| **G-7** | `integrity-bundle-fixtures` walker over `formspec/tests/fixtures/cross-stack/` | Extends byte discipline beyond Trellis-only vectors (**G-3**); not a ratification ordinal |

**Refactor G-6 — where it is enforced:** (1) Rust writer + `trellis_verify_wos::verify_export_zip` — `trellis-export-writer` crate test `given_export_001_fixture_inputs_when_write_export_then_zip_and_members_match_fixture`; (2) same ZIP bytes — `trellis-conformance` committed-vector replay for `export/001-two-event-chain`; (3) Python generator vs committed tree — `scripts/check_export_001_generator_sync.py` (run via `trellis/Makefile` target `test-scripts`, i.e. `make test-scripts` from `trellis/` or `make -C trellis test-scripts` from the monorepo root).

**This file is the evidence-of-record.** Each gate carries inline commit SHAs and artifact pointers. Tactical work needed to close open gates is tracked in [`../TODO.md`](../TODO.md). A separate `ratification-evidence.md` registry existed briefly as a parallel view; it was removed because the inline evidence pointers here are sufficient and the duplication drifted.

### Ratification vs stack refactor evidence (TWREF-040 / TWREF-042)

Checklist gates **G-1…G-6** below are **ratification** closure: stranger-test artifacts, vectors, and `check-specs.py` discipline at the cited evidence dates. They are **not** a substitute for the stack refactor tracker’s **implemented / wired-in-CI / product-covering** matrix in [`../../TRELLIS-WOS-REFACTOR-TODO.md#refactor-gate-evidence-matrix-i--c--p`](../../TRELLIS-WOS-REFACTOR-TODO.md#refactor-gate-evidence-matrix-i--c--p).

- **Ratification G-6** (this file) = `python3 scripts/check-specs.py` lint clean — unrelated ordinal to **refactor G-6** (export emitter parity: Rust `trellis-export-writer` ↔ `gen_export_001.py` ↔ verifier). Refactor G-6 enforcement includes `trellis/Makefile` target `test-scripts` (run as `make test-scripts` **from `trellis/`**, i.e. `$(MAKE) -C trellis test-scripts` from the monorepo root).

Commands cited here (`cargo nextest run …`, `python3 scripts/check-specs.py`, `python3 -m trellis_py.conformance`) describe **Trellis workspace / ratification** runs. Root `make test` / stack CI fan-out is authoritative for “what CI runs” only where stack workflows duplicate those commands; do not read a ratification checkbox as “prod MVP product-covering” unless prose explicitly says so.

## Global gates

- [x] **G-1 — Normalization handoff complete.** Every task in [`../thoughts/archive/specs/2026-04-17-trellis-normalization-handoff.md`](../thoughts/archive/specs/2026-04-17-trellis-normalization-handoff.md) Groups A–D is closed. *(evidence: 3a143a1)*
- [x] **G-2 — Invariant coverage.** Every Phase 1 envelope invariant #1–#15 appears as normative MUST text in Core and is cross-referenced from at least one `TR-CORE-*` row. Byte-testable invariants are audited via the G-3 lint (`check_invariant_coverage`); non-byte-testable invariants are covered by the model-check registry, declaration-document validator, projection/shred drill coverage, and matrix cross-reference lint. *(evidence: matrix §4 invariant summary; `thoughts/model-checks/evidence.toml`; `crates/trellis-conformance/src/model_checks.rs`; `fixtures/declarations/ssdi-intake-triage/`; `fixtures/vectors/{projection,shred}/`; `scripts/check-specs.py` R7/R8/R11; `python3 scripts/check-specs.py` passed cleanly on 2026-04-21 after the remaining `spec-cross-ref` warning rows gained explicit `Core §N` / `Companion §N` anchors.)*
- [x] **G-3 — Byte-exact vectors.** ~50 test vectors under `fixtures/vectors/{append,verify,export,tamper,projection,shred}/` cover every byte-level claim. Every vector reproducible from Core prose alone. *(evidence: active fixture system design [`../thoughts/specs/2026-04-18-trellis-g3-fixture-system-design.md`](../thoughts/specs/2026-04-18-trellis-g3-fixture-system-design.md) (governs `check-specs.py` coverage contract); archived 12-task scaffold plan [`../thoughts/archive/specs/2026-04-18-trellis-g3-fixture-scaffold-plan.md`](../thoughts/archive/specs/2026-04-18-trellis-g3-fixture-scaffold-plan.md). 44 vectors now landed across six op-dirs — append/1-9, verify/1-12, export/1-4, tamper/1-12, projection/1-5, shred/1-2. The residual V3 breadth batch on 2026-04-21 landed `verify/008-012`, `export/002-004`, and `tamper/009-012`, including the §19 step-4 revoked/`valid_to` branch, step-6 posture-transition happy path, and step-8 optional-anchor happy path. All G-3 coverage allowlists are closed (`_pending-projection-drills.toml` removed, `_pending-invariants.toml` removed, `_pending-matrix-rows.toml` removed, `_pending-model-checks.toml` emptied). Core gaps surfaced by G-3 authoring are documented at [`../thoughts/archive/specs/2026-04-18-trellis-core-gaps-surfaced-by-g3.md`](../thoughts/archive/specs/2026-04-18-trellis-core-gaps-surfaced-by-g3.md), and the revocation-language pin landed in Core §19 step 4.a. Validation passed on 2026-04-21 via `python3 scripts/check-specs.py` and `cargo nextest run -p trellis-conformance committed_vectors_match_the_rust_runtime`. Current tree: universal export/offline verification lives in sibling `integrity-stack/crates/integrity-verify`; WOS-aware reporting wraps it from `crates/trellis-verify-wos`.)*
- [x] **G-4 — Reference implementation passes.** `trellis-core`, `trellis-server`, `trellis-server-ports`, `trellis-service-client`, `trellis-export-writer`, `trellis-verify-wos`, `trellis-witness-registry`, `trellis-store-postgres-async`, `trellis-store-memory`, `trellis-conformance`, `trellis-cli` build; workspace list is authoritative in [`../Cargo.toml`](../Cargo.toml); public service/reference path is append / verify / export via `trellis-server` + `integrity-verify` / `trellis-verify-wos`; every vector passes. *(evidence: Rust workspace under `crates/`; `cargo nextest run` over workspace members per `Cargo.toml`; committed-corpus replay in `crates/trellis-conformance/src/lib.rs`; model-check suite in `crates/trellis-conformance/src/model_checks.rs`.)*
- [x] **G-5 — Second implementation byte-matches.** An independent implementation (Python or Go) written by someone who read only the specs produces byte-identical output on every vector. *(evidence: clean-room `trellis-py/` stranger pass; `trellis-py/BYTE-MATCH-REPORT.json` (`failed = 0`, `total_vectors = 45`), `trellis-py/ATTESTATION.md`, `trellis-py/ALLOWED-READ-MANIFEST.txt`, `trellis-py/DISCREPANCY-LOG.txt`; final SHA-256s pinned below in §Evidence SHAs.)*
- [x] **G-6 — Lint clean.** `python3 scripts/check-specs.py` reports zero violations across all normative documents. *(evidence: 3a143a1)*

## Per-document readiness gates

### [`../specs/trellis-core.md`](../specs/trellis-core.md)

- [x] **C-1 — Signature model via COSE_Sign1.** Signatures use RFC 9052 `Sig_structure` preimage. No custom signature-zeroing procedure. *(evidence: 3a143a1)*
- [x] **C-2 — Explicit hash preimages.** Every hashed artifact (`author_event_hash`, `canonical_event_hash`, `tree_head_hash`, manifest digest) has a single CDDL-defined preimage structure; domain separation tags defined; ledger scope included in signed material. *(evidence: 3a143a1)*
- [x] **C-3 — Tagged payload references.** `PayloadInline` and `PayloadExternal` variants defined; verifier output reports `structure_verified`, `integrity_verified`, `readability_verified` independently. *(evidence: 3a143a1)*
- [x] **C-4 — Deterministic export.** ZIP layout reproducible via a single `zip -0` invocation over prefix-ordered filenames (`000-`, `010-`, …); local-file-header fields pinned. *(evidence: 3a143a1)*
- [x] **C-5 — Strict-superset semantics normative.** "Strict superset" defined as reserved-extension preservation; Phase 1 verifiers MUST reject unknown top-level fields; `extensions` container reserved in CDDL. *(evidence: 3a143a1)*
- [x] **C-6 — Idempotency identity scope-permanent.** Same key + same payload → same canonical reference; same key + different payload → deterministic rejection; no reuse within ledger scope after TTL expiry. Retry budgets and dedup-store lifecycle are deferred to the Operational Companion. *(evidence: 3a143a1)*
- [x] **C-7 — Agency-log extension points reserved.** §24 extension points reflected in §11 checkpoint CDDL as reserved fields. *(evidence: 3a143a1)*
- [x] **C-8 — Profile/Custody/Conformance-Class vocabulary unambiguous.** No bare "Profile" without scope qualifier; Respondent Ledger owns `Profile A/B/C`; legacy core profiles named "Conformance Classes"; legacy companion profiles named "Custody Models." *(evidence: 3a143a1)*

### [`../specs/trellis-operational-companion.md`](../specs/trellis-operational-companion.md)

- [x] **O-1 — Core section references resolve.** Every `Core §N` reference points to the correct heading in the current Core. *(evidence: 3a143a1)*
- [x] **O-2 — Custody-model identifier set unified.** Companion §9 custody-model identifiers match Core §21 vocabulary and Matrix `TR-OP-010..014` rows. *(evidence: 3a143a1)*
- [x] **O-3 — Projection discipline testable.** Watermark contract, rebuild equivalence, snapshot cadence, and purge-cascade verification have conformance fixtures. *(evidence: design brief `e895920`; projection + shred fixture batches `00042c4`, `334bb75`, `905668b`, `964716c`; fixtures under `fixtures/vectors/{projection,shred}/`; committed corpus replayed by `cargo nextest run --workspace` via `trellis-conformance` `tests::committed_vectors_match_the_rust_runtime` on 2026-04-21.)*
- [x] **O-4 — Delegated-compute honesty declarations present.** Every agent-in-the-loop deployment has a declaration document covering scope, authority attestation, audit trail, attribution per Companion §19. *(evidence: template/design brief `b40e8a4`; Companion A.6 normative text `8069062` + `65090f8`; reference declaration corpus under `fixtures/declarations/ssdi-intake-triage/` landed in `7d47c3e`; static validator `R11` landed in `b0f114d`; `python3 scripts/check-specs.py` and `python3 -m pytest scripts/test_check_specs.py` passed on 2026-04-21, including `TestDeclarationDocs`.)*
- [x] **O-5 — Posture-transition auditability enforced.** Custody-model and disclosure-profile changes are recorded as canonical events per Companion §10 AND are verified symmetrically by the Rust reference verifier (`integrity-verify` / workspace adapters) and the Python stranger on both transition axes. **Retroactively reopened 2026-04-23** after the design-doc audit (`thoughts/audit-2026-04-23-design-docs-vs-specs-and-code.md`) surfaced that `integrity-verify`'s posture-transition decoding handled only custody-model transitions; a tampered `from_disclosure_profile` value passed verification. **Re-closed 2026-04-23** by extending both implementations' transition decoding to `trellis.disclosure-profile-transition.v1`, adding a parallel `shadow_disclosure_profile` baseline parsed from the declaration's top-level `disclosure_profile` string, routing the attestation rule through Appendix A.5.3 step 4's `scope_change` enum, and landing `tamper/016-disclosure-profile-from-mismatch` as the negative oracle. **Hardened 2026-04-24:** both implementations reject events that carry **both** `trellis.custody-model-transition.v1` and `trellis.disclosure-profile-transition.v1` extension keys (mutual-exclusion guard in transition decode). Verified by `cargo nextest run -p trellis-conformance tests::committed_vectors_match_the_rust_runtime` and `python3 -m trellis_py.conformance` (63 vectors, 0 failures). *(evidence SHAs — disclosure-profile verifier + stranger parity: `086d844`; ratification doc re-close: `5a6c9d5`; design brief `f94342b`; normative Companion posture-transition text + Appendix A.5 schemas in `8069062`; append posture-transition vectors `dbdfe0a`; tamper posture-transition vectors `814b2fe`; tamper-kind reconciliation `fd54232`.)*

### [`../specs/trellis-requirements-matrix.md`](../specs/trellis-requirements-matrix.md)

- [x] **M-1 — Factual consistency with Core.** TR-CORE-032 specifies dCBOR (not JCS); every MUST in Core has at least one matching `TR-CORE-*` row; every MUST in Companion has at least one matching `TR-OP-*` row. *(evidence: 3a143a1)*
- [x] **M-2 — Gap-log soundness.** Every dropped legacy row is justified against an invariant, an upstream spec, or a replacement `TR-*` row. *(evidence: 3a143a1)*
- [x] **M-3 — Invariant coverage.** All 15 invariants are covered by at least one `TR-CORE-*` row, except invariant #11 (Profile-namespace disambiguation) which is covered by Matrix §4 prose. *(evidence: 3a143a1; wording refined in a later commit to reflect #11's §4 routing accurately.)*

## Evidence SHAs

- `trellis-py/BYTE-MATCH-REPORT.json` — `ebcccdea3cf9a7fa472e2ced1067066015117dc80201ce2c8c9c46f5c4e80b4f` (63 vectors; updated 2026-04-23 on G-O-5 re-close)
- `trellis-py/ATTESTATION.md` — `b3998def1404f2a59ffa09abd218b5adf731d2f8177f05bbb1ea615cddc9ee9c` (updated 2026-04-23 with G-O-5 re-close note)
- `trellis-py/ALLOWED-READ-MANIFEST.txt` — `50e52a5d4b3e96b4fe88d4342bf9b6029e9b537c682089bb6d7781809c952f3d`
- `trellis-py/DISCREPANCY-LOG.txt` — `274817e01b19b6fe9757759f5b181911fa3673739a2266fd2ca5aa4e0b37f6f0`

## Natural stopping point

Ratification is complete: all gates above are checked, the stranger test has landed an independently-written second implementation that byte-matches every vector, and the lint reports zero violations. That bar is **spec-era closure** for Trellis normative documents — not, by itself, the refactor tracker’s **product-covering** column for compose-backed or fleet-shaped runtime (see *Ratification vs stack refactor evidence* above and [`TRELLIS-WOS-REFACTOR-TODO.md#refactor-gate-evidence-matrix-i--c--p`](../../TRELLIS-WOS-REFACTOR-TODO.md#refactor-gate-evidence-matrix-i--c--p)).
