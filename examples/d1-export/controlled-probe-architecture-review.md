# Controlled writer probe: preliminary architecture BEFORE gate

**APPROVE the bounded serialized probe execution scope. DEFER generic writer implementation approval until actual RED evidence and an exact design receipt exist.** The necessary native 010 subset is sufficient to test the first byte-carriage limitation; it cannot qualify full D1 or the complete desired member set.

Reviewer `/root/oidc_arch_review`, independent non-author, October 8, 2026. Read `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` in full and invoked `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`, with universal/application guidelines for Rust inspection. No builds, Cargo, execution, live calls, source changes or sibling edits. Only this preliminary certificate was written. Serialized queue and all other holds remain in force.

## 1. Artifact summary and pins

Category: proof infrastructure. Problem: current maintained writer lacks input/member emission for registered 060/061/065 bytes while free-form extensions may advertise their digests. Decision: replay one committed valid synthetic event chain through `write_export`, preserve exact signed-event bytes, record missing required native members and output verifier result, then stop full desired construction on the first actual failure.

Trellis HEAD: `092792f9f57d94db9e1f67390b9037d1908c1a01`. Authored inputs independently match `controlled-probe-input-pins.json`:

| Input | SHA-256 |
| --- | --- |
| `crates/trellis-export-writer/examples/full-member-qualification.rs` | `0317ae9bc322d901b404d90672d6c7e2ba7163c41824f355d3313782ae51fe9b` |
| `crates/trellis-export-writer/Cargo.toml` | `ec77fecf06f7295a12931af15bf500abb16893c973747702848135d3f96578e3` |
| `examples/d1-export/controlled-writer-qualification.md` | `0eaeca86f9ac5f44b5e4e46e80e94c2e067b16e7a9840862d95c4480a5623451` |
| `examples/d1-export/controlled-probe-input-pins.json` | `0bf25aa4925aec8907ed3ff20588640a7e902219c551c894ef1892132fc34fa2` |
| Writer `src/lib.rs` | `955cac11ad0dc1966b4484aed25a096eab58386229345871ad7f522d560db60b` |
| Native 010 `expected-export.zip` | `f4c9e31ec0c3581857ab44cd46e64faef4e9c05d4ab12689a3ceadd2e849745c` |
| Integrity single complete candidate | `565b98c822104a3e0d826ea5a8385cf2e7be26539e45451c478c282bb503d413` |

No actual probe result exists in this reviewed scope. Prior installed-binary fixture results are lineage, not this source execution. Candidate pin readback confirms the shared desired graph snapshot; its semantic acceptance remains with Integrity.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| GOAL | Independent complete evidence survives live service | `GOAL.md:Product Claim; Critical Path 5` |
| Development philosophy | Fixtures before enforcement; reuse maintained mechanisms | `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility; Wire format discipline` |
| Core | Native member/digest rules, independent verification | `specs/trellis-core.md:16.1,18.2–18.3` |
| Trellis local guide | Consumer meanings outside byte center | `CLAUDE.md:Architecture` |
| Authored writer qualification | Desired full39 distinct from baseline/synthetic proof | `examples/d1-export/writer-qualification.md:Input boundary; Native member coverage` |
| Existing profile derivation | Subsumes 066/067/068 consumer derivation | `crates/trellis-server/src/export_profile.rs:129–158` |

| Seam | Owner | Depends on / consumers | Named? |
| --- | --- | --- | --- |
| Synthetic fixture input | Trellis conformance | Committed native010; diagnostic only | Yes, probe `59–122` |
| `ExportWriterInput` / `write_export` | Trellis composition | Integrity ZIP/COSE; service exporters | Yes, writer `247–289,354` |
| Archive byte assembly | Integrity | Trellis entries; verifiers | Yes, Core §18 substrate authority |
| Consumer catalog/history/disclosure | Application bindings/host | Actual accepted bytes and reader policy | Existing ownership in writer/Bindings qualification; outside this probe |
| Complete desired verifier candidate | Integrity | Full39 native Need graph; root runtime | One linked candidate; no new `BundleCreateRequest` |

## 3. Invariants and commitments

1. **Exact committed signed events — PRESERVED by intended gate.** Probe `80–95` checks entire signed array re-encoding equality and preserves each signed record. Failure stops before writer qualification; no replacement business/signature events may be invented.
2. **One maintained writer — PRESERVED.** Probe `129` calls existing `write_export`; no ZIP assembler or D1 exporter appears. Core §18 assigns archive bytes to Integrity.
3. **Conditional catalogs need real source evidence — RELIED-UPON.** Core §18.2 permits optional absence; native010 supplies the synthetic attachment/certificate chain. This qualifies only applicable 060/061/065, not all desired families or actual D1 completion.
4. **Checkpoints are a new controlled sequence — PRESERVED by explicit disclosure.** Probe `90–112` supplies each signed authored timestamp and checks the final timestamp against native head. Document states native010 stores one head while writer emits one checkpoint per event. Byte-exact fixture ZIP reproduction is not promised.
5. **Registered advertised members need byte carriage — current seam gap, prospective NEW requirement.** Writer `validate_top_level_input:778–837` pairs known 031/seal/066/068/067 inputs, but corresponding general 060/061/065 carriage is absent. Document diagnoses free extensions separately from consumer semantics. Actual missing-member output remains to be observed.
6. **Default library builds do not acquire probe-only requirements — PRESERVED by declared feature gate.** Cargo example requires `fixture-inputs`; verifier is a dev dependency. This is static shape evidence, not executed build proof.
7. **Independent trust and visibility remain separate — PRESERVED.** Controlled doc requires source evidence/reader permission, labels synthetic certificate, and preserves no real D1 claims. Internal fixture signing validity is not agency authority or human legal assurance.

## 4. User-value analysis

Beneficiary: export maintainers and eventual recipients needing complete permitted evidence. Immediate outcome is a falsifiable minimal failure diagnosis before adding public API complexity. Conceptual debt stays low through an existing native fixture, writer and verifier. No runtime feature or speed/resource gain is certified.

Smaller shape considered: listing missing source fields without executing the seam would be cheaper but would not distinguish input conversion defects from writer omissions. A full39 synthetic composite would add false cross-ledger history. The chosen native010 necessary subset provides the first meaningful rejection without that debt.

Value refutation: after executing, only compilation or fixture conversion fails, but the result is labeled a missing-member writer RED and used to justify a generic carrier. Another refutation is adding arbitrary file carriage rather than the registered member capability that the receipt demonstrates is required.

## 5. Counterfactual analysis

Kill criterion: source signed bytes change, required inputs are malformed, or current writer already emits the necessary bytes correctly. Stop or revise the hypothesis; do not preselect the fix.

Counter-decision: build every desired family now. That would fabricate unsupported full D1 history or combine records from unrelated ledgers, defeating evidence authority.

Removal probe: removing the diagnostic breaks no application runtime. It removes the causal check supporting a future public writer change.

Sibling subsumption: PARTIAL. Existing profile derivation already covers 066/067/068; do not reimplement it. Native fixture/verifier handles other member formats, but that does not prove writer input support.

Six-month critic: flags misleading “full-member” interpretation, an uncaptured early error, arbitrary paths/bytes in a new API, or stale source pins. Explicit subset/status and exact receipts prevent those promotions.

## 6. Findings

**F1 — KEEP.** Severity OBSERVATION; category scope/ownership. Location controlled document native010 paragraph and probe `126–144`. Native010’s required 060/061/065 is the appropriate first necessary subset. Keep full39 as desired shared input, not generated synthetic records.

**F2 — DEFER.** Severity OBSERVATION; category intent-vs-shape. Location prospective generic fix paragraph. Closed registered-member byte carriage and derived digests are a plausible minimum direction, not approved implementation. Before implementation, bind actual RED and exact proposed type/validation design, list enabled member families and paired extension behavior, and retain current wire shape/Integrity assembly. Consumer catalog derivation must stay outside the writer.

**F3 — KEEP with explicit result classification.** Severity OBSERVATION; category proof infrastructure. Location probe `61–66,80–82,108–111,129,146–150`. Several errors return before diagnostic ZIP/JSON files are written. Root's retained execution receipt must preserve argv/cwd/toolchain/source/input digests and stdout/stderr even for early refusal. Compilation, fixture validity, conversion mismatch, writer refusal, missing member and verifier failure are different results. Only the observed writer behavior supports the eventual design gate.

**F4 — REVERSE any broader promotion.** Severity OBSERVATION; category trust/user-value. Location full desired families paragraph. Synthetic completion events are valid controlled fixture inputs, not accepted D1 certificate evidence; complete desired coverage, independent agency trust and reader disclosure remain open. Do not use this probe to close those gates.

## 7. Preliminary verdict

APPROVE root's serialized execution of the exact authored diagnostic once prerequisite owners release the slot. Intent vs shape MATCHES; user-value SUPPORTED as causal proof preparation; commitments HONORED; conceptual debt NEUTRAL; sibling subsumption PARTIAL; confidence HIGH on source shape and MEDIUM on predicted outcome.

Generic implementation BEFORE verdict is DEFERRED pending actual RED plus exact design receipt and both independent reviews. This certificate does not authorize concurrent Cargo, live calls, writer source edits or default-build/runtime activation. No compiler or verifier execution occurred here.

All six review phases completed. H1 existing bytes can expose a minimal writer gap REFINED: native010 subset is suitable but actual failure is unobserved. H2 all families require a new carrier REFUTED by existing 066/067/068 profile support. H3 probe output reproduces fixture ZIP REFUTED by explicitly different checkpoint sequence. H4 early nonzero automatically proves omission REFUTED by preconditions/early returns. Further reading should follow the actual diagnostic and exact prospective design, rather than expand into unrelated full-case implementation.
