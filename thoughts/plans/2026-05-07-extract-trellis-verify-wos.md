# Plan: Extract WOS-aware verification (`trellis-verify-wos`, composed on `integrity-verify`)

## Context

`trellis-verify` carries WOS/Formspec domain knowledge in violation of Core §16's verification-independence contract. The 2026-05-06 dependency-inversion audit (closing [TODO #15](../../TODO.md)) catalogued the residue:

- 6 hardcoded `wos.kernel.*` / `wos.governance.*` event-type literals (`lib.rs:154-165`)
- 4 WOS record parsers (`parse.rs:1261-1401`) and 4 WOS record-detail types (`types.rs:857-905`)
- Two ~250-line WOS catalog cross-checks in `export.rs` (`verify_signature_catalog`, `verify_intake_catalog`)
- Intake-mode dispatch (`lib.rs:885-921`) and rescission terminality (`lib.rs:622-635`) — pure WOS semantics
- ~20/147 `VerificationFailureKind` variants are WOS-domain
- The inversion originates upstream in Core §6.7 (extension table) and §19 (verifier obligations naming WOS shapes); spec is the bug, code faithfully implements it

Five more ADRs are queued behind this debt (#11 supersession terminality, #12 clock semantics, #6 tenant, #8 commit-failure, #10 migration pins). Without extraction, every ratification compounds the violation.

**Architectural shape decision (revised):** the architecture-relevant fix is the **trait + literal removal from `trellis-verify`**. The destination crate's *location* is a packaging decision, not an architecture decision. Verified precedent: `trellis-interop-c2pa`, `trellis-interop-did`, `trellis-interop-scitt`, `trellis-interop-vc` all sit as sibling adapter crates in `trellis/crates/` depending only on `trellis-types`. A `trellis-verify-wos` sibling fits that pattern exactly. WOS event-type literals are duplicated against `wos-core`'s eventual canonical home — fine, because `wos-core` doesn't yet own those strings (spec-only today).

**Trade-off vs cross-repo extraction:** ~60% less work, no fixture migration, conformance harness stays unified, single submodule mostly. Gives up the symbolic statement "WOS owns WOS validation in `work-spec/`." `trellis-verify` itself becomes integrity-only either way — that's the architectural fix, and it's preserved here.

**Done state:** `trellis-verify` is integrity-only (chain link, signature, hash, COSE, checkpoint, Merkle, sidecar digest binding, tenant scope discriminator, timestamp ordering, structural supersession-graph cycles). `trellis-verify-wos` (sibling crate in trellis) carries every line that knows what `wos.kernel.*` or `wos.governance.*` mean. `wos-server` (and any future WOS consumer) depends on `trellis-verify-wos`; integrity-only consumers (`trellis-cli`, `trellis-interop-c2pa`) stay on `trellis-verify`.

---

## Architecture

```
                                          ┌─ trellis/crates/trellis-verify-wos (NEW) ────┐
wos-server ──────────────────────────────► │  WosRecordValidator: RecordValidator         │
    │                                     │  - WOS event-type literals                    │
    │                                     │  - 4 WOS record parsers                       │
    │                                     │  - intake-mode dispatch                       │
    │                                     │  - rescission terminality                     │
    │                                     │  - clock semantic checks                      │
    │                                     │  - WosFinding aggregation                     │
    │                                     │  - WosVerificationReport (composes Trellis)   │
    │                                     └────────────────────┬──────────────────────────┘
    │                                                          │ depends-on (path)
    │                                                          ▼
    └─► trellis-verify ◄── trellis-cli, trellis-interop-c2pa, trellis-conformance
        - integrity-only
        - publishes `RecordValidator` trait
        - dispatches per-event + per-sidecar to registered validator
        - returns TrellisVerificationReport (no WOS variants)
```

Both crates live under `trellis/crates/`. `trellis-verify-wos` follows the `trellis-interop-*` precedent: sibling adapter, depends only on `trellis-types` + `trellis-verify` (intra-trellis path-deps). No reverse path-coupling to `work-spec/`.

`wos_trellis_verify::verify_export_zip(bytes)` internally calls `trellis_verify::verify_export_zip(bytes, &validator)`, where `WosRecordValidator` does field-level matching during the trellis-verify chain walk.

---

## RecordValidator trait surface (lives in `trellis-verify`)

Trait takes **opaque bytes + opaque event-type strings**. No typed enums of WOS variants. No knowledge of WOS field names.

```rust
// trellis-verify/src/validator.rs (NEW)

pub trait RecordValidator {
    /// Called once per event after integrity checks pass.
    /// `event_type` is the raw string; `payload` is dCBOR bytes; chain context is read-only.
    fn validate_event(
        &self,
        event_type: &str,
        payload: &[u8],
        ctx: EventContext<'_>,
    ) -> Vec<DomainFinding>;

    /// Called when a manifest extension URI matches a registered prefix.
    /// `extension_uri` is opaque (e.g. "wos.signature-catalog.v1").
    /// `sidecar_bytes` are post-digest-verified.
    fn validate_sidecar(
        &self,
        extension_uri: &str,
        sidecar_bytes: &[u8],
        chain: VerifiedChain<'_>,
    ) -> Vec<DomainFinding>;

    /// Returns the manifest extension URIs this validator handles. Trellis-verify
    /// uses this to decide whether a manifest extension is "domain-claimed" or
    /// must surface as `UnknownManifestExtension`.
    fn known_extension_uris(&self) -> &[&str];
}

pub struct DomainFinding {
    pub kind: String,                    // e.g. "rescission_terminality_violation"
    pub event_hash: Option<[u8; 32]>,
    pub severity: Severity,              // failure | advisory
    pub message: String,
}

pub enum Severity { Failure, Advisory }
```

A no-op `()` impl ships in `trellis-verify` so integrity-only consumers don't need a validator.

---

## Crate: `trellis-verify-wos`

**Location:** `trellis/crates/trellis-verify-wos/`

**Cargo.toml:**
```toml
[package]
name = "trellis-verify-wos"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
trellis-types = { path = "../trellis-types" }
trellis-verify = { path = "../trellis-verify" }
ciborium = { workspace = true }
serde = { workspace = true, features = ["derive"] }
sha2 = { workspace = true }
```

Match `trellis-interop-c2pa`'s pattern for workspace-inherited fields. No `wos-core` dependency — WOS event-type strings are duplicated as crate-local constants here, same as `trellis-interop-c2pa` carries C2PA strings without depending on a c2pa crate.

**Workspace Cargo.toml change:** add `"crates/trellis-verify-wos",` to `[workspace] members` in `trellis/Cargo.toml`. Insert near the other `trellis-verify*` and adapter crates.

**Module layout:**
```
src/
  lib.rs                     # public API: WosRecordValidator, verify_export_zip(), verify_single_event()
  validator.rs               # WosRecordValidator: RecordValidator impl
  records.rs                 # 4 record parsers (moved from trellis-verify/src/parse.rs)
  record_types.rs            # 4 record-detail structs (moved from trellis-verify/src/types.rs)
  intake.rs                  # intake-mode dispatch (moved from trellis-verify/src/lib.rs)
  rescission.rs              # rescission terminality (moved from trellis-verify/src/lib.rs)
  clock_semantics.rs         # calendar-ref + deadline checks (carved from open_clocks.rs)
  catalog.rs                 # signature/intake catalog field-matching (carved from export.rs)
  certificate_eventtype.rs   # WOS event-type assertion (carved from certificate.rs:152)
  findings.rs                # WosFinding, WosVerificationReport
  event_types.rs             # 6 WOS event-type constants (moved from trellis-verify/src/lib.rs:154-165)
  tests.rs                   # WOS-aware tests (moved from trellis-verify/src/tests.rs)
```

**Public API (`lib.rs`):**
```rust
pub use validator::WosRecordValidator;
pub use findings::{WosFinding, WosVerificationReport};

/// One-call composition: integrity verification + WOS-domain validation.
pub fn verify_export_zip(zip: &[u8]) -> WosVerificationReport;

/// Single-event variant for in-process append-time validation (wos-server hot path).
pub fn verify_single_event(public_key: [u8; 32], signed_event: &[u8]) -> WosVerificationReport;
```

---

## `trellis-verify` changes

### Stays (integrity-only)

| File | What stays |
|---|---|
| `lib.rs` | Verifier loop (with new validator dispatch hooks); chain link; signature; hash; checkpoint; Merkle |
| `parse.rs` | Envelope/payload structural decoding; non-WOS record types |
| `types.rs` | `VerificationReport`, `VerificationFailure`, `PostureTransitionOutcome`, etc. (WOS detail types removed) |
| `kinds.rs` | Integrity error variants (~127/147) |
| `export.rs` | Manifest parsing; ZIP layout validation; **digest binding helpers** for sidecar extensions (extracted from `verify_signature_catalog` / `verify_intake_catalog` and made `pub(crate)` or re-exported) |
| `certificate.rs` | ADR 0007 envelope binding (signer count, content hash, etc.); event-type assertion at `:152` becomes a validator dispatch |
| `erasure.rs` | ADR 0005 erasure evidence (envelope-level) |
| `user_attestation.rs` | ADR 0010 envelope binding |
| `interop_sidecar.rs` | ADR 0008 envelope binding |
| `merkle.rs` | Merkle proofs |
| `util.rs` | Subject-scope shape validation (per-subject/per-scope/per-tenant) — **tenant integrity stays** (envelope-level scope, not domain) |
| `supersession.rs` | Graph cycle detection; predecessor checkpoint binding; head_chain_id structural matching — **all integrity, no WOS literals** |
| `open_clocks.rs` | **Split**: integrity (manifest binding, sidecar digest, JSON canonical encoding) stays; semantic checks (calendar-ref consistency across pause/resume, deadline-vs-sealed_at advisory) move |

### Removed (moves to `trellis-verify-wos`)

| Origin | Destination | Lines |
|---|---|---|
| `lib.rs:154-165` (6 WOS event-type constants) | `trellis-verify-wos/src/event_types.rs` | 12 |
| `lib.rs:622-635` (rescission terminality) | `trellis-verify-wos/src/rescission.rs` | ~14 |
| `lib.rs:885-921` (intake-mode dispatch: `intake_entry_matches_record`, `case_created_record_matches_handoff`) | `trellis-verify-wos/src/intake.rs` | ~37 |
| `parse.rs:1261-1401` (4 WOS record parsers) | `trellis-verify-wos/src/records.rs` | ~141 |
| `types.rs:857-905` (4 WOS record-detail structs) | `trellis-verify-wos/src/record_types.rs` | ~49 |
| `export.rs:1067-1166` (`verify_signature_catalog` field-matching portion) | `trellis-verify-wos/src/catalog.rs` | ~100 (digest binding stays) |
| `export.rs:1168-1343` (`verify_intake_catalog` field-matching portion) | `trellis-verify-wos/src/catalog.rs` | ~175 (digest binding stays) |
| `certificate.rs:152` (event-type assertion) | `trellis-verify-wos/src/certificate_eventtype.rs` | (assertion only; envelope binding stays) |
| `open_clocks.rs` (semantic checks: calendar-ref consistency, deadline-vs-sealed_at) | `trellis-verify-wos/src/clock_semantics.rs` | ~150 (split — integrity portion stays) |
| `kinds.rs` (~20 WOS variants: `CaseCreated*`, `Intake*`, `Signature*` field-level, `RescissionTerminalityViolation`, `ClockCalendarMismatch`) | `trellis-verify-wos/src/findings.rs` (as `WosFinding::kind` strings, NOT a Rust enum exposed across the seam) | ~20 lines |

### Added (new dispatch hooks)

- `lib.rs::verify_event_set` gains a `&dyn RecordValidator` parameter; calls `validator.validate_event(event_type, payload, ctx)` after integrity checks for each event.
- `export.rs::verify_export_zip` gains a `&dyn RecordValidator` parameter; calls `validator.validate_sidecar(uri, bytes, chain)` for each manifest extension whose URI is in `validator.known_extension_uris()`. Unknown extensions surface as `UnknownManifestExtension` (existing kind) instead of being silently consumed.
- New no-op default `impl RecordValidator for ()` so integrity-only consumers call `verify_export_zip(bytes, &())`.

---

## Fixtures (stay in place)

**No fixture migration.** All 99 vectors remain in `trellis/fixtures/vectors/`.

**Conformance harness extension:** `trellis-conformance` gains awareness of which vectors require the WOS validator. Two viable shapes (decide during Phase 4):

- **(a) Feature flag:** `trellis-conformance` adds a `with-wos` feature that pulls in `trellis-verify-wos` as a dev-dependency and runs the WOS-coupled vectors through composition. Default feature-set runs only the integrity-only vectors.
- **(b) Sibling test crate:** `trellis-conformance-wos` (new) depends on `trellis-conformance` (for vector discovery helpers) and `trellis-verify-wos`, runs the WOS-coupled vectors through the composed verifier.

Lean: (a). Single conformance binary, single fixture-corpus invariant ("Vectors and Rust move together" preserved trivially since they don't move).

**WOS-coupled vectors driven through the composed verifier:**
- `append/{010,019,020,021,022}` — WOS record binding
- `append/{043,044,045,046}` — clock semantics
- `tamper/050-rescission-terminality`
- `tamper/051-clock-calendar-mismatch`
- (`verify/018-export-043-open-clocks` semantic-side; integrity-side already covered by `trellis-verify` alone)

**Integrity-only vectors driven through `trellis-verify` with `()` validator:**
- All `append/{001-009, 011-018, 023-042}` — chain, COSE, hash, posture, key lifecycle, attestation, certificates, UCA, idempotency
- All `tamper/{001-049, 052+}` — signature, hash, chain, scope, attestation, sidecar, timestamp, supersession-graph integrity
- All `verify/*` — export integrity (positive paths)
- All `export/`, `projection/`, `shred/` — pure Trellis infrastructure

---

## Spec changes

| File | Change |
|---|---|
| `trellis/specs/trellis-core.md` §19 | Carve out: §19 keeps integrity verifier obligations (steps 1-6e); WOS-specific obligations (signature catalog field-matching, intake catalog field-matching, rescission terminality, clock semantics) become a non-normative **"Domain validator extension points"** subsection that points to `wos-trellis-verification.md`. |
| `trellis/specs/trellis-core.md` §6.7 | Note added: "Extension table entries naming WOS event types are normative for WOS deployments but are not byte-level commitments of the Trellis envelope." |
| `trellis/specs/trellis-core.md` §16 | Strengthen verification-independence prose: "Integrity verification (this spec) MUST NOT depend on domain semantics. Domain validators (consumer-owned) extend verification via the `RecordValidator` interface." |
| `trellis/specs/trellis-requirements-matrix.md` | TR-CORE-* rows for moved obligations either renumber to `WOS-TV-*` and migrate to the new spec, or stay marked "moved to wos-trellis-verification.md" with cross-reference. Lean: hard-renumber (zero production records). |
| `trellis/specs/wos-trellis-verification.md` (NEW) | Normative spec describing `WosRecordValidator` obligations: catalog field-matching, intake-mode dispatch, rescission terminality, clock semantics. Numbered as `WOS-TV-*` requirements. Lives in `trellis/specs/` (alongside `trellis-core.md`) since the validator ships in `trellis/crates/`. Cross-references `work-spec/specs/` for canonical event-type catalog. |
| `trellis/COMPLETED.md` | Wave entry recording the extraction. |
| `trellis/TODO.md` #15 | Closed with link to the wave entry. |

---

## Error / report taxonomy

- `trellis-verify::VerificationFailureKind` loses ~20 WOS variants. **Breaking change for consumers that match those variants.** Acceptable per Trellis CLAUDE.md ("`v1.0.0` is a coherent-snapshot tag, not a freeze.").
- `trellis-verify-wos::WosFinding::kind` carries them as strings (e.g. `"rescission_terminality_violation"`) — not as a fresh Rust enum. Future-proof: WOS spec evolution adds new finding kinds without breaking the trait surface.
- `trellis-verify-wos::WosVerificationReport` composes:
  ```rust
  pub struct WosVerificationReport {
      pub trellis: trellis_verify::VerificationReport,
      pub wos_findings: Vec<WosFinding>,
  }
  ```

---

## Consumer migration

| Consumer | Change |
|---|---|
| `workspec-server/crates/wos-server/` | Switch dep from `trellis-verify` to `trellis-verify-wos`. Cargo.toml edge: `trellis-verify-wos = { path = "../../../trellis/crates/trellis-verify-wos" }` (matches existing `trellis-store-postgres-async` path-dep style). Call sites: `verify_export_zip` and `verify_single_event` swap to the WOS-aware versions. Composes `EventStore` write-path and bundle export. |
| `trellis/crates/trellis-cli/` | Stays on `trellis-verify`. Reports integrity-only. (Optional: add `--wos` flag pulling `trellis-verify-wos` via feature — defer; not in this train.) |
| `trellis/crates/trellis-interop-c2pa/` | Stays on `trellis-verify`. C2PA path is envelope-only. |
| `trellis/crates/trellis-conformance/` | Either feature-flagged WOS coverage or sibling test crate (Phase 4 decision). |
| Python `trellis-py/` | **Verify whether it carries WOS-aware verification.** Phase 0 grep determines scope; Phase 2 mirrors the carve there if needed. |

---

## Test split

- `trellis/crates/trellis-verify/src/tests.rs` (3386 lines): WOS-aware fixtures and tests move to `trellis-verify-wos/src/tests.rs`. Specifically:
  - Lines 345-370 (`intake_handoff_value()` fixture)
  - Lines 846-860 (WOS record fixtures)
  - All catalog cross-check integration tests exercising signature/intake catalog field-matching
  - Tests asserting `RescissionTerminalityViolation`, `ClockCalendarMismatch`, intake-mode error variants
- Integrity-only tests STAY (chain link, signature, hash, COSE, checkpoint, Merkle, sidecar digest binding, posture transitions, erasure, certificates, UCA, sidecar interop, supersession-graph cycles, timestamp ordering).
- New `trellis-verify-wos/tests/integration.rs`: end-to-end "WOS event → Trellis envelope wrapping → composed verify round-trip" — establishes the cross-stack three-way agreement (Rust + Python via `trellis-py` + reference adapter) for the WOS-validated path.

---

## Sequencing — phased with parallel streams

Five phases. Phase 0 is parallel with Phase 1's prep; Phases 2 and 3 each fan out into multiple parallel subagent streams. Phases 4 and 5 are short serial closeouts.

### Phase 0 — Discovery (1 parallel subagent, ~15 min)

**Stream 0a (subagent):** `trellis-py` WOS-coverage grep.
- Search `trellis/trellis-py/` for WOS event-type literals, intake-mode dispatch, rescission terminality.
- Verdict: same carve needed in Python or no?
- Output: short report; if carve needed, sketch the symmetric Python module structure.
- Not blocking; Phase 1 starts in parallel.

### Phase 1 — Foundation (serial, 1 commit, ~1h)

Pure-addition work in `trellis-verify`. Runs inline (no subagent) — owner-traceable foundational commit.

1. Add `trellis-verify/src/validator.rs`: `RecordValidator` trait, `EventContext<'_>`, `VerifiedChain<'_>`, `DomainFinding`, `Severity`, no-op `impl RecordValidator for ()`.
2. Wire dispatch hooks in `lib.rs::verify_event_set` and `export.rs::verify_export_zip` (`&dyn RecordValidator` parameter, default `&()` callers).
3. Strengthen `trellis-core.md` §16 prose (verification-independence reframed in terms of `RecordValidator`).
4. Add TR-CORE-* row(s) for the dispatch surface in the requirements matrix.

**Verification gate:** `cargo nextest run -p trellis-verify` passes; `python3 scripts/check-specs.py` passes.

**Single commit lands.** This is the trait foundation everything else builds on.

### Phase 2 — Build out (3 parallel subagent streams, ~3h wall-clock)

All three streams branch off the Phase 1 commit. They edit non-overlapping files; merge contention is zero.

**Stream 2a (subagent — largest):** Create `trellis-verify-wos` crate.
- New directory `trellis/crates/trellis-verify-wos/{Cargo.toml,src/...}`.
- Add to workspace members in `trellis/Cargo.toml`.
- Port code (read-only from `trellis-verify`; do not delete originals yet — Phase 3 deletes after this lands):
  - `event_types.rs` — 6 constants from `trellis-verify/src/lib.rs:154-165`
  - `records.rs` — 4 parsers from `trellis-verify/src/parse.rs:1261-1401`
  - `record_types.rs` — 4 structs from `trellis-verify/src/types.rs:857-905`
  - `intake.rs` — intake-mode dispatch from `trellis-verify/src/lib.rs:885-921`
  - `rescission.rs` — terminality from `trellis-verify/src/lib.rs:622-635`
  - `clock_semantics.rs` — semantic checks carved from `trellis-verify/src/open_clocks.rs`
  - `catalog.rs` — field-matching from `trellis-verify/src/export.rs:1067-1343`
  - `certificate_eventtype.rs` — assertion from `trellis-verify/src/certificate.rs:152`
  - `findings.rs` — `WosFinding`, `WosVerificationReport`, `Severity` re-export
  - `validator.rs` — `WosRecordValidator: RecordValidator` impl wiring all of the above
  - `lib.rs` — `verify_export_zip()`, `verify_single_event()` composition wrappers
- Move WOS-aware tests from `trellis-verify/src/tests.rs` into `trellis-verify-wos/src/tests.rs` (Phase 3 will delete the originals).
- Add `tests/integration.rs` with end-to-end round-trip.

**Stream 2a verification:** `cargo nextest run -p trellis-verify-wos`.

**Stream 2b (subagent):** Spec authoring.
- Author `trellis/specs/wos-trellis-verification.md` — normative spec for `WOS-TV-*` obligations covering `WosRecordValidator`'s contract.
- Draft (not apply) Core §19 carve-out and §6.7 note for Phase 3 to land alongside the code removal.
- Draft requirements-matrix renumbering: which `TR-CORE-*` rows become `WOS-TV-*`.
- Draft trellis/COMPLETED.md wave entry.

**Stream 2b verification:** spec lints clean (`python3 scripts/check-specs.py` once integrated in Phase 3).

**Stream 2c (subagent, conditional on Phase 0a result):** `trellis-py` mirror.
- If 0a found WOS-aware verification in Python, port the symmetric carve (a `trellis_verify_wos.py` module under `trellis-py/`).
- If 0a found nothing, Stream 2c is a no-op and skipped.

**Phase 2 merge:** all three streams complete → integrate into a single feature branch in trellis. Lands as one or several commits (one per stream is fine).

### Phase 3 — Cleanup (2 parallel subagent streams, ~2h wall-clock)

Both streams operate on the post-Phase-2 tree. They edit different repos / different file sets.

**Stream 3a (subagent — destructive cleanup in `trellis/`):**
- Delete moved code from `trellis-verify/src/{lib.rs,parse.rs,types.rs,kinds.rs,export.rs,certificate.rs,open_clocks.rs,tests.rs}`.
- Hard-delete the ~20 WOS variants from `kinds.rs`.
- Delete WOS detail types from `types.rs`.
- Trim `tests.rs` of the moved tests.
- Apply Phase 2b's drafted Core §19 carve-out, §6.7 note, requirements-matrix renumbering.

**Stream 3a verification:** `cargo nextest run -p trellis-verify` passes (integrity-only); `cargo nextest run -p trellis-verify-wos` still passes (cross-crate integration); `python3 scripts/check-specs.py` passes.

**Stream 3b (subagent — `wos-server` migration in `workspec-server/`):**
- Edit `workspec-server/crates/wos-server/Cargo.toml`: replace `trellis-verify` dep with `trellis-verify-wos`.
- Update import paths and call sites: `trellis_verify::verify_export_zip` → `trellis_verify_wos::verify_export_zip`; types may need re-imports.
- If wos-server matches on removed `VerificationFailureKind` variants, those branches now consume `WosFinding::kind` strings instead.

**Stream 3b verification:** `cargo nextest run -p wos-server` passes; broader workspec-server workspace builds.

**Phase 3 merge:** both streams complete → trellis-verify is integrity-only; wos-server consumes the composed verifier; spec is in shape.

### Phase 4 — Conformance (serial, ~1h)

Inline, owner-traceable.

1. Decide harness shape (feature flag vs sibling crate — lean: feature flag).
2. Edit `trellis-conformance` Cargo.toml + lib to add WOS coverage:
   - New `with-wos` feature pulling `trellis-verify-wos` as dev-dep (or regular dep gated).
   - Tag WOS-coupled vector dirs and dispatch them through `trellis_verify_wos::verify_export_zip`; integrity-only vectors continue through `trellis_verify::verify_export_zip(bytes, &())`.
3. Run full corpus: `cargo nextest run -p trellis-conformance --features with-wos`. All 99 vectors pass.
4. Run Python cross-check: `python3 -m pytest -q trellis-py` (if Phase 2c added a mirror).

### Phase 5 — Closeout (serial, ~30 min)

Inline.

1. Update `trellis/TODO.md` — close #15 with link to the wave entry.
2. Add wave entry to `trellis/COMPLETED.md` (drafted in Phase 2b).
3. Update `trellis/CLAUDE.md` if architecture pointers need adjusting (e.g. "Center: `trellis-core` + `trellis-types` + `trellis-cddl` + `trellis-cose` + `trellis-verify`" expands to mention `trellis-verify-wos` alongside `trellis-interop-*` adapters).
4. Submodule pointer bumps:
   - Commit in `trellis/` (or several commits — one per phase if branched).
   - Commit in `workspec-server/`.
   - Commit in parent monorepo bumping both submodule pointers.
5. End-to-end smoke: `make test` from parent monorepo.

---

## Parallelism summary

| Phase | Streams | Wall-clock | Sequential alt | Savings |
|---|---|---|---|---|
| 0 — Discovery | 1 (subagent) | 15 min | 15 min | 0 |
| 1 — Foundation | 1 (inline) | 1h | 1h | 0 |
| 2 — Build out | 3 (subagents) | 3h | ~5h | ~40% |
| 3 — Cleanup | 2 (subagents) | 2h | ~3h | ~33% |
| 4 — Conformance | 1 (inline) | 1h | 1h | 0 |
| 5 — Closeout | 1 (inline) | 30 min | 30 min | 0 |
| **Total** | | **~7.75h** | **~10.75h** | **~28%** |

Subagent dispatches: 6 (Phase 0a + Phase 2a/2b/2c + Phase 3a/3b). Inline phases: 3 (1, 4, 5).

Worktrees considered but rejected for this layout: parallel streams within a phase edit disjoint file sets in the same submodule, so a single feature branch in trellis is sufficient — no isolation gain from worktrees. Use of `superpowers:dispatching-parallel-agents` skill is appropriate at Phases 2 and 3.

---

## Critical files

**New:**
- `trellis/crates/trellis-verify-wos/Cargo.toml`
- `trellis/crates/trellis-verify-wos/src/{lib.rs,validator.rs,records.rs,record_types.rs,intake.rs,rescission.rs,clock_semantics.rs,catalog.rs,certificate_eventtype.rs,findings.rs,event_types.rs,tests.rs}`
- `trellis/crates/trellis-verify-wos/tests/integration.rs`
- `trellis/specs/wos-trellis-verification.md`
- `trellis/crates/trellis-verify/src/validator.rs`
- (conditional, Phase 2c) `trellis/trellis-py/trellis_verify_wos.py`

**Modified:**
- `trellis/Cargo.toml` (add member)
- `trellis/crates/trellis-verify/src/{lib.rs,parse.rs,types.rs,kinds.rs,export.rs,certificate.rs,open_clocks.rs,tests.rs}`
- `trellis/crates/trellis-conformance/Cargo.toml` + `src/lib.rs` (Phase 4)
- `trellis/specs/trellis-core.md` (§16, §19, §6.7)
- `trellis/specs/trellis-requirements-matrix.md`
- `trellis/TODO.md` (close #15)
- `trellis/COMPLETED.md` (wave entry)
- `trellis/CLAUDE.md` (architecture pointer if needed)
- `workspec-server/crates/wos-server/Cargo.toml` + call sites

**Deleted:** none (no fixtures move).

---

## Reused existing utilities / patterns

- `trellis-interop-c2pa/Cargo.toml` — pattern reference for sibling adapter crate manifest (workspace-inherited fields, `trellis-types` path-dep).
- `trellis-verify::export::parse_manifest` and digest-binding helpers — extracted as `pub(crate)` helpers (or made `pub` for the limited surface `trellis-verify-wos` needs) so `trellis-verify-wos::catalog` validates sidecar field shapes after digest binding succeeds.
- `trellis-conformance/src/lib.rs:39` vector discovery — extended with feature-gated WOS dispatch in Phase 4.
- `superpowers:dispatching-parallel-agents` skill — used in Phases 2 and 3 to coordinate the multi-stream work.

---

## Verification

End-to-end gates that must pass before submodule pointers bump in Phase 5. All `cd` paths below are relative to the parent stack repo (`formspec-stack/`).

```bash
# trellis side
cd trellis
cargo nextest run --workspace                          # both verify crates + conformance
cargo nextest run -p trellis-conformance --features with-wos  # full 99-vector corpus through composition
python3 -m pytest -q trellis-py                        # stranger oracle (G-5)
python3 scripts/check-specs.py                         # spec discipline + fixture coverage

# workspec-server side
cd ../workspec-server
cargo nextest run -p wos-server                        # consumer migrated

# parent
cd ..
make test                                              # fan-out across all submodules
```

**Functional verification:**
- Integration test in `trellis-verify-wos`: construct a WOS `signatureAffirmation` event → wrap into Trellis envelope → call `trellis_verify_wos::verify_single_event` → assert (a) integrity report is clean, (b) WosFinding list is empty for valid input, (c) tampering an affirmation field surfaces `signature_catalog_field_mismatch` as a `WosFinding` (not a `VerificationFailure`).
- Negative test: same event but with `event_type` set to `wos.governance.determinationRescinded` followed by a determination event → `WosFinding{kind: "rescission_terminality_violation"}` surfaces from `trellis-verify-wos`, not from `trellis-verify`.
- Three-way agreement: Rust `trellis-verify-wos` + reference fixture replay + Python cross-check (if applicable) produce byte-identical findings.

---

## Decisions taken (lean + rationale, redirect during execution if needed)

1. **Crate location**: `trellis/crates/trellis-verify-wos/` (sibling to `trellis-verify`). Rationale: matches `trellis-interop-*` precedent (4 existing sibling adapter crates depending only on `trellis-types`). Avoids cross-repo refactor, fixture migration, and submodule pointer dance for a packaging-only difference.
2. **WOS event-type strings**: duplicated as crate-local constants in `trellis-verify-wos/src/event_types.rs`. No `wos-core` dep. Rationale: matches `trellis-interop-c2pa`'s self-contained pattern; `wos-core` doesn't yet own canonical WOS event-type strings (spec-only today), so depending on it would buy nothing.
3. **WOS variant removal in `kinds.rs`**: hard-delete the ~20 WOS variants. No `#[deprecated]` shims. Rationale: `v1.0.0` is a coherent-snapshot tag, zero production records, breaking change is the point of the architectural fix.
4. **Fixtures**: stay in `trellis/fixtures/vectors/`. Rationale: single conformance harness, single fixture-corpus invariant, no migration cost.
5. **Conformance harness shape**: extend `trellis-conformance` with a `with-wos` feature flag pulling `trellis-verify-wos`. Lean confirmed in Phase 4. Rationale: avoids crate proliferation; preserves single-binary corpus replay.
6. **`trellis-cli` WOS opt-in**: deferred. CLI stays integrity-only in this train. Rationale: keeps the train scoped; CLI WOS surface is a follow-on item once `trellis-verify-wos` stabilizes.
7. **WOS-TV-* spec home**: `trellis/specs/wos-trellis-verification.md` (alongside trellis-core.md). Rationale: validator ships in `trellis/crates/`; spec ships with code; cross-references `work-spec/specs/` for the canonical event-type catalog.
8. **Worktrees**: not used. Parallel streams within a phase edit disjoint file sets in the same submodule; a single feature branch in trellis suffices. Subagent isolation provides the parallelism.
