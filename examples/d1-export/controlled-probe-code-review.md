# Controlled writer probe: independent pre-execution code review

Review ID `trellis-controlled-writer-code-2026-10-08-01`; reviewer `/root/oidc_code_review`, nonauthor. Skills read in full: `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; applicable Rust guidelines `02_application_guidelines.md`, `08_universal_guidelines.md`. Applied root/Trellis local instructions and direct report-only, no-execution ownership. Only this certificate was written; no Rust/Cargo.lock/implementation edits by reviewer.

**APPROVE for the queued controlled probe only.** Three pre-execution blockers were found and corrected by the author. Static evidence predicts missing060/061/065 rather than an invalid input failure, but actual RED is not established until compilation and execution return the retained output. No generic implementation BEFORE verdict or product acceptance is issued.

## Findings and dispositions

**F1 — BLOCKER / correctness / initial example:85–86; resolved.** `map_lookup_u64` returns `Result<u64,CborHelperError>` (`../integrity-stack/crates/integrity-cbor/src/lib.rs:531`), but initial probe called Option's `.ok_or`. Author replaced it with `?`; re-read at final example:89. This correction removes a statically evident compile error, not proof the example compiles.

**F2 — BLOCKER / correctness / initial example:91–98; resolved.** Fixture010 has three signed events and one head checkpoint. Initial probe populated only one timestamp; writer rejects timestamp/event count mismatch before emission (`crates/trellis-export-writer/src/lib.rs:755–762`). Author now derives one timestamp per event from signed `header.authored_at`, as server does (`crates/trellis-server/src/lib.rs:200–203,395–396`), and requires final timestamp equal original head. Read-only CBOR inspection found event times1776900400/450/500 and original head/generated_at1776900500; thus corrected count is3. Writer generates a new three-checkpoint sequence (`writer lib.rs:1128–1143`); doc:9 explicitly distinguishes it from byte-exact fixture ZIP reproduction.

**F3 — BLOCKER / correctness / `crates/trellis-export-writer/Cargo.toml`; resolved.** Example imports fixture-only utility gated in library at `src/lib.rs:33–37`. Without target metadata, default example builds would import an unavailable utility. Author added `[[example]] name="full-member-qualification", required-features=["fixture-inputs"]` at Cargo.toml:27–29. Planned command enables the feature. No new dependency or production behavior was added.

**F4 — OBSERVATION / test-coverage / example:63–66,132–180.** Original fixture is verified first; writer output member checks and substrate flags are emitted separately; missing member nonzero exit follows artifact retention. Compile failure, fixture decode failure, re-encoding mismatch, output-directory failure, or missing writer-input precondition must be classified as probe failure, never promoted to the desired missing-member RED. Root must retain stderr/exit status and confirm diagnostic names060/061/065 in the queued run.

**F5 — OBSERVATION / correctness / example:68–83.** Probe verifies the original ZIP but loads loose manifest/events/checkpoint/registry files. Reviewer compared those exact current loose bytes to matching ZIP members: all equal. Final event array re-encoding equality gate (`82–84`) prevents signed-event byte drift. Root's planned exact input snapshot must include both ZIP and loose inputs/key/utility dependencies; no runtime gate here checks ZIP-versus-loose equality for every member. Given checked current bytes and required execution pins this is not an unresolved blocker.

## 1. Patch summary and exact binding

Changes: fixture-backed Rust example, controlled qualification note, and feature-required example metadata. The probe reconstructs StoredEvent inputs from valid signed synthetic fixture010, calls maintained `write_export`, records archive/member diagnostics, and intentionally returns nonzero when necessary members are absent. No business events, new ZIP writer, wire request, service calls or product fix. Important caller: example `main`; external caller is the root's planned serialized Cargo command (`controlled-writer-qualification.md:14`).

Trellis source/base HEAD observed `092792f9f57d94db9e1f67390b9037d1908c1a01`; Integrity source HEAD `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Writer library and fixture utility remain unchanged. Unrelated Cargo.lock insertion preserved. Exact final reviewed SHA-256:

| File | SHA-256 |
| --- | --- |
| `crates/trellis-export-writer/examples/full-member-qualification.rs` | `0317ae9bc322d901b404d90672d6c7e2ba7163c41824f355d3313782ae51fe9b` |
| `examples/d1-export/controlled-writer-qualification.md` | `0eaeca86f9ac5f44b5e4e46e80e94c2e067b16e7a9840862d95c4480a5623451` |
| `crates/trellis-export-writer/Cargo.toml` | `ec77fecf06f7295a12931af15bf500abb16893c973747702848135d3f96578e3` |
| source010 `expected-export.zip` | `f4c9e31ec0c3581857ab44cd46e64faef4e9c05d4ab12689a3ceadd2e849745c` |
| source010 `000-manifest.cbor` | `915b12d8730bfac85d217498ce1bd8c3b8432887610d2c55c678a90fec67cb85` |
| source010 `010-events.cbor` | `c46c372b23536259436e32525ae2ba4121be1fa61ab9faecfe6e5bd5c2d82592` |
| source010 `040-checkpoints.cbor` | `12c8918836d4173105e65c55cee9fbb75c4c5dd24c4591294a3c69a8d2109755` |
| fixture `_keys/issuer-001.cose_key` | `ca088759545e41ecf5ffdc4c0251c31c1ccc7f7df7b2742d680da92a68445f09` |

The desired full graph remains Integrity's candidate digest `565b98c822104a3e0d826ea5a8385cf2e7be26539e45451c478c282bb503d413`, matching disk at review. Its semantic review belongs to Integrity; this probe tests a necessary minimal native subset only. All39 Needs and remaining families stay desired, not fulfilled.

## 2. Function trace

| Function | File:line | Inputs → outputs | Verified behavior |
| --- | --- | --- | --- |
| `fixture_value` | example:19 | path→CBOR value/error | reads and decodes loose fixture |
| `field` | example:23 | value/name→borrowed field/error | scans text-key map; no provider/business interpretation |
| `timestamp` | example:31 | CBOR array→TrellisTimestamp/error | checked u64/u32 conversions; new validates timestamp; no invented wall clock |
| `main` | example:52 | output path + fixed corpus→ZIP/JSON/nonzero | original validity gate; builds input; event equality gate; timestamp/head check; writer call; member diagnostics; fails after saving |
| `export_001_writer_input` | `src/export_001_fixture_input.rs:52` | corpus root→input | loads maintained issuer001 seed/public key and defaults; probe replaces scope/events/times/registries/extensions |
| fixture `read_fixture` / key parser | same:14,25 | fixture path/key→bytes/seed/public | panics on missing/malformed maintained fixtures; classify as setup failure |
| `decode_cose_sign1` / value decoder | Integrity `integrity-cose/src/lib.rs:190,199` | encoded tagged COSE→envelope/error | requires tag18/four fields; extracts embedded payload; does not resign source events |
| `encode_cbor_value` | Integrity `integrity-cbor/src/lib.rs:209` | Value→bytes/error | ciborium encoding without recursive canonicalization; equality gate guards whole event array |
| `StoredEvent::new` | `trellis-types/src/lib.rs:173` | scope/sequence/payload/signed bytes→record | carries original payload/signature bytes into existing writer |
| `write_export` / input validation | writer `src/lib.rs:354,741` | input→package/error | input/contiguity/scope/payload preconditions then current emission path |
| `prepare_events` | writer:945 | records→prepared hashes/leaves/error | contiguous0 sequence, scope/payload consistency, COSE payload equality and hashes |
| `checkpoint_chain` | writer:1118 | input/prepared events→signed checkpoints | one per event using supplied times; newly signs checkpoints with fixture key |
| `manifest_extensions_value` | writer:520 | input→extension map | preserves provided attachment/completion extension values; only declared typed members augment map |
| `ExportPackage::member_bytes` | writer:316 | relative name→optional bytes | exact root-prefixed entry lookup |
| `trellis_verify_wos::verify_export_zip` | called example:62,148 | ZIP→report | original gate and output substrate flags; no live custody proof |

## 3. Data flow and invariants

Fixed fixture root enters at example:58–59; original ZIP verifies before writer input construction. Manifest `scope`, `generated_at`, extensions flow into input; registry bytes/version match original manifest binding. Original signed event payloads remain byte strings inside tagged COSE values. Read-only CBOR inspection confirmed tagged values and whole-array re-encoding equality; final Rust gate must still execute to prove its encoder preserves bytes. Fixture key from utility signs new manifest/checkpoints, not replacement business events. The input retains utility posture defaults; both original/default flags are provider-readable/no delegated compute/no reader-held, with differing fixture descriptive text. ZIP equality is not claimed.

Original fixture extensions are attachment and completion bindings, not seal-fence/witness/066/067/068 extensions. Therefore existing validation requiring typed inputs for those other extensions does not cause an unrelated early failure. Current emission adds base members, optional031/066/067/068 and no060/061/065 (`writer:431–493`); extensions are preserved (`531–539,557–575`). Static expected failure is omitted referenced native members. `payloads_inlined` is currently hardcodedfalse (`1288`), another evidence point for the future design, not modified here.

Required filenames are sourced from fixture payload directory plus061/065, sorted, compared to actual package entries. Diagnostics and output ZIP escape into root-owned directory only. Outputs are synthetic; no actual case response/photo or secrets are read. New output must not replace retained source fixture. Existing original-verifier success alone is not field authorization, complete history or D1 legal/signature proof.

## 4. Tests, checks and edge cases

**Executed by reviewer: no Cargo/build/run/verifier/tests/live calls.** Read-only CBOR/ZIP/hash inspection checked fixture shape, timestamps and loose/archive equality. Compilation and actual RED remain unverified until queued run. No existing test covers this new example main; the planned retained probe run is its acceptance check. No extra implementation-mirroring tests are required for this bounded example.

Relevant tests read earlier in this session and unchanged here: writer `given_export_001_fixture_inputs_when_write_export_then_zip_and_members_match_fixture` (`src/lib.rs:1669`) reconstructs001 and compares emitted members to committed bytes; writer066/068/067 tests (`2067,2130,2243`) assert carriage and manifest digests, not missing060/061/065 emission. Server `publish_bundle_is_byte_identical_across_independent_states` (`server lib.rs:1972`) asserts archive equality from same event/key inputs at2043. None changes behavior because library source is unchanged; none substitutes for compiling this example.

Concrete edge cases: malformed fixture/COSE fails before writer (correct setup refusal, not desired RED); re-encoding mismatch fails before emission (correct source-byte refusal); event count/time mismatch initially caused falseRED and is corrected; a future writer guard rejecting unsupported bound extensions before assembly would be a different legitimate capability refusal, not current predicted omission output; unwritable directory fails retention and cannot be qualified as member-lossRED. After successful compilation, root must distinguish these through exact stderr/diagnostic/output pins. Unexpected missing required family list, original validityfalse or output not retained requires correction.

## 5. Exploration notes and remaining gaps

H1 medium: committed valid source should reach writer. Initial source motivated type/API and fixture reads; Result misuse and checkpoint count refuted it, author corrected both. H2 medium: re-encoding source COSE preserves signed payload. Tagged shape, reference encoder check and added Rust equality gate confirm static approach; actual Rust gate pending. H3 medium: current writer loses extension-bound members. Full input/validation/extensions/emission reads support prediction; actual RED pending. H4 medium: probe should not enter default builds. Fixture feature gate and target metadata resolved default-build risk. H5 low: source docs accurately distinguish controlled checkpoint generation from original archive. Final doc explicitly qualifies new sequence and complete graph deferral.

Unresolved: compiler/type-check result, actual output verifier/member-loss receipt, toolchain/input snapshot, future generic carrier design and full D1 runtime evidence. Maintained library dependency internals beyond inspected CBOR/COSE helpers were not reviewed. No speed/resource claims or product refactor occurred; concrete improvement is removal of false probe failures and reuse of one maintained writer rather than a second implementation.

## 6. Conclusion

VERDICT: APPROVE — controlled serialized probe execution only.

The corrected probe preserves valid source records, satisfies known native input prerequisites and can expose current missing-member behavior. Coverage of static probe paths: ADEQUATE; executable qualification: INSUFFICIENT until queued run records actual RED. Confidence HIGH for source/fixture/precondition checks, MEDIUM for run outcome because compilation/execution is intentionally pending. Generic implementation BEFORE acceptance must wait for that receipt and exact proposed design; this certificate authorizes no product fix or full39Need completion claim.
