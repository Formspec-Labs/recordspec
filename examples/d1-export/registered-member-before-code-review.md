# Registered-member writer input: independent BEFORE code/design review

Review ID `trellis-registered-members-before-code-2026-10-08-01`; reviewer `/root/oidc_code_review`, nonauthor. Applied full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and Rust review skill `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` (read earlier in this continuous session); Rust application/universal guidelines and root/Trellis instructions apply. Only this certificate was written. No Cargo/build/run/verifier/live calls or source changes performed.

**APPROVE the corrected BEFORE proposal and AFTER controlled probe/evidence for a scoped local commit.** F1–F3 are resolved at the design/evidence boundary. The generic writer change remains unimplemented; this certificate does not accept an implementation or establish full D1 completion, publication, custody or read permission.

## Findings

**F1 — RESOLVED (original BLOCKER) / correctness / proposal:24.** Decode/re-encode equality alone does not prove canonical CBOR when using shared `encode_cbor_value`, explicitly documented as lacking recursive canonicalization (`../integrity-stack/crates/integrity-cbor/src/lib.rs:205–213`). Unsorted map entries or duplicate map keys can survive a plain decode/encode. Suggestion: require `encode_canonical_cbor_value(decoded) == input_bytes`, using maintained recursive sorting/duplicate rejection (`same:158–187,220–222`), plus array shape. Reject mismatches rather than silently rewrite admitted bytes. Add unsorted nested map and duplicate nested key negatives. Existing shared tests demonstrate the necessary behavior (`769–817`), while writer catalog checks today only decode (`writer src/lib.rs:844–846,859–861`). Final proposal:24 explicitly requires the canonical helper, equality, recursive duplicate-key rejection and both negative tests. This resolves the design finding; future implementation/tests remain required.

**F2 — RESOLVED (original BLOCKER) / correctness / proposal:18,24.** OpenClocks binding specifies digest alone, omitting required `open_clock_count`. Core CDDL requires both fields (`specs/trellis-core.md:3170–3173`); native Core parser reads count (`Integrity integrity-verify/src/trellis/parse.rs:996–1015`), and native validator compares it to row length (`open_clocks.rs:46–49`). Suggestion: include explicitly typed count supplied by owner (then existing verifier checks it), or derive it through an existing maintained format parser. Do not invent a second canonical-JSON serializer or clock semantics. Add open-clock success, wrong-count and malformed/canonical JSON refusal evidence; fixtures006/007/010 do not cover this variant. Final proposal:18,24 derives count from the native array with existing `serde_json`, replaces stale counts, and requires canonical emission plus an independently tampered signed-count refusal. This resolves the design finding without adding a serializer or clock interpretation; all such tests are prospective.

**F3 — RESOLVED (original BLOCKER) / evidence prerequisite / proposal:3,36.** Actual controlled native missing-member RED is not yet available at initial review. Cold build timeout/lock prerequisites cannot establish byte loss. Retain original valid source, successful writer construction, generated output/member list, nonzero missing-member error, exact inputs/source/toolchain and command before implementation approval. Existing-source prediction and installed-binary fixture passes do not satisfy this prerequisite. Final receipt/log/output inspection establishes actual execution after compilation: original structure/integrity true, writer structure true/integrity false, all three required members missing, exit1 at the named missing060 assertion. Independently executed Python reports substrate-integrity failure on the exact output ZIP. F3 is resolved for this necessary synthetic subset; other requested families and real D1 remain unqualified.

**F4 — OBSERVATION / correctness / proposal:13,20.** Payload content addressing must use `domain_separated_sha256("trellis-content-v1", ciphertext)` (Core:749–757, verifier obligation1804–1809); catalog extension digests use bare SHA-256 (Core:2090–2092). Use `[u8;32]` hash inputs and generated lowercase hex paths, never caller path strings. Document this distinction in concrete helper/tests so catalog hashing cannot accidentally replace ciphertext hashing. Incorrect payload hash must fail before signing/emission.

**F5 — OBSERVATION / maintainability / proposal:9,34.** Adding a public struct field requires all maintained struct literals to initialize it: server publication (`crates/trellis-server/src/lib.rs:230`), fixture utility (`writer/src/export_001_fixture_input.rs:76`), empty-event test (`writer/src/lib.rs:1727`). Historical copied source under root reports is evidence, not a live consumer to rewrite. Empty initialization must preserve001 byte-for-byte. This is a local input API change, not a new wire format.

## 1. Patch summary and review binding

Reviewed only authored `examples/d1-export/registered-member-input-proposal.md`: final SHA-256 `9e0e86a03016ffa839d561cc9fdabb34e14e81efa42e8485998b95df2be05c25` (initial reviewed SHA `854345b98d8d8ef0458995746b68a65e8177cf55d5bcdbc58f64b5553b6f1c04`, retained finding history above). No implementation diff exists. Trellis source HEAD `092792f9f57d94db9e1f67390b9037d1908c1a01`; Integrity HEAD `d2dd4827cd294aaecc470e6a49dd8954a48880cf`; unchanged native writer `src/lib.rs` SHA-256 `955cac11ad0dc1966b4484aed25a096eab58386229345871ad7f522d560db60b`. Unrelated Cargo.lock and parallel source preserved. Current tracked diff contains only the four-line fixture-gated example target in writer Cargo.toml and one pre-existing Cargo.lock line; production writer source has no diff. Untracked probe/docs/receipts are the authored evidence scope. No generic implementation diff exists.

Final exact review map `examples/d1-export/registered-member-before-input-pins.json` SHA-256 `8b3616c79305d0646ae89f1ac5d1dcdcf37e88d853e0bb2b23a0443fbe847868` binds 21 files; every listed digest was independently recomputed and matched. Principal evidence pins:

| Artifact | SHA-256 |
| --- | --- |
| controlled result document | `ae9a0893c903b95d2dfdfe5c161f501f5edd2c376f294c5f9fe77bb87791d0c8` |
| compiled probe source | `0317ae9bc322d901b404d90672d6c7e2ba7163c41824f355d3313782ae51fe9b` |
| Cargo example configuration | `ec77fecf06f7295a12931af15bf500abb16893c973747702848135d3f96578e3` |
| native executed receipt | `ef2763626a0a39a0e36d50be51089858f63125b0d7d834d0e9ae55741a9cb601` |
| actual output ZIP | `969a421696cfbb44baccb87598281a58625ab57dceac1d8acf2eee64667bbf72` |
| native output JSON | `2cf7a4c82af57d49f44025ea2c5d9102a7faa8caf9bd778b12ca078acec8ca38` |
| independent Python receipt | `2cfb3b84d3bd3d28fbb916d4ce57ae49dd1a37c26694a5519145a0eef7a17758` |
| consumed-input guard | `e59765c4b1490b3e8dd7286c91af0130cbc7d74e8e16e53172e9f399c3ca9bd8` |

Fresh read-only comparison of the guard found no drift in 85 local source and 49 synthetic fixture files. Current Cargo.lock matches retained starting SHA `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`. Receipt records process-group absence, restored lock, exact argv/cwd and rustc1.89; this review verifies artifact consistency, not a new live process audit.

Intent: one closed `ExportEvidenceMember` collection adds missing060/061/062/063/065/open-clock byte inputs, derives existing bindings, leaves031/066/067/068 typed inputs intact, and uses current BundleEntry/ZIP path. No new catalog derivation, consumer permission, business records or public API request. Proposed types/preparation helper are **unimplemented**: their behavior below is required design, not verified code.

## 2. Existing and prospective function trace

| Function / input | File:line | Inputs→outputs | Verified behavior or required future behavior |
| --- | --- | --- | --- |
| `ExportWriterInput` | writer `src/lib.rs:247` | scope/events/registries/signing/typed catalogs | existing fields lack proposed families |
| `write_export` | writer:354 | input→signed ZIP/error | validates; prepares events/proofs/registries/checkpoints; creates manifest; emits entries through Bundle |
| `validate_top_level_input` | writer:741 | input→unit/error | current advertised031/seal/066/068/067 without typed inputs refuses; existing catalog bytes decode only |
| `manifest_extensions_value` | writer:520 | typed members + base extensions→map | derives existing typed digests and merges before signing |
| current extension merge helpers | writer:632,657,683,712 | base map + digest metadata→canonical map | omit owned old key and replace with derived binding; other entries preserved |
| `manifest_payload_cbor` | writer:1253 | generated digests/input→manifest bytes | payloads_inlined currently hardcodedfalse at1288 |
| current member emission | writer:431–493 | package pieces→Bundle entries | base members and optional031/066/067/068 only |
| `publish_bundle` | server `src/lib.rs:190,230` | closed scope events→verified immutable publication | constructs input; profile validators precede publication at272–287; no new-family consumer wiring proposed |
| `encode_canonical_cbor_value` | Integrity `integrity-cbor/src/lib.rs:220` | decoded value→canonical bytes/error | recursive sorting, duplicate canonical-key/invalid float refusal |
| `domain_separated_sha256` / `sha256_bytes` | same:122,135 | ciphertext/tag or bytes→digest | distinct content and catalog hash constructions |
| `Bundle::add_entry` / `to_zip_bytes` | Integrity `integrity-bundle/src/lib.rs:221,239` | entries→ZIP/error | current deterministic assembly; duplicate paths refused during serialization |
| open-clock parser/validator | Integrity `integrity-verify/src/trellis/parse.rs:996`; `open_clocks.rs:13,80` | bound member→report | count/digest, canonical format and sealed_at checks; parser is pub(crate), not a public writer dependency seam |
| prospective evidence preparation helper | proposal:22; **unimplemented** | closed variants→validated entries + bindings + payload presence | require unique family/hash, source-byte canonicality, correct typed hash/path, owned extension/member pairing |
| prospective enum | proposal:9–18; **unimplemented** | owner-provided admitted bytes | retain opaque content; no actor/consent/case derivation or permission inferred |

## 3. Data flow and invariants

Consumer owns selection/derivation and supplies exact admitted bytes; proposed input temporarily owns them, preparation creates fixed registered BundleEntry paths and binding digests, signed manifest binds those entries, output ZIP escapes to consumer. Writer must not normalize accepted bytes, derive business authority, expose arbitrary member paths or silently carry mismatched digests. Caller-authored stale digest replacement is consistent with current typed witness/catalog behavior; declared owned extension with missing member must reject before signing. Empty new member set plus no new advertised extensions must keep001 exactly unchanged.

Enum eliminates reserved-path collisions by construction; duplicate variant/hash guards still needed before adding entries. Deterministic Bundle assembly already sorts and detects path duplicates; do not duplicate ZIP serialization. New060 presence determines payloads_inlined; catalog digests hash exact bytes, and060 filenames/content address use signed-event content construction. Signed-event/catalog relationships and disclosure stay consumer/profile-validator responsibilities; capability does not admit an arbitrary attached document to a case.

Format-only CBOR shape is justified: current061/062/063/065 fixture catalogs inspected are arrays. Final proposal requires the maintained canonical helper and equality (resolved F1). Open-clock canonical JSON and chain/time semantics already reside in maintained verifier; count derived from the native array is existing wire metadata (resolved F2), not permission to add serializer/clock derivation. Supplied inline_attachments flag must be tested with actually present payloads through the independent verifier; writer cannot claim readable evidence merely because digest-binding succeeded.

## 4. Tests inspected, planned behavior and edge cases

**Executed by reviewer: none.** Retained native and Python execution receipts, logs and results were read; they are observed external execution evidence. Existing assertions inspected in this continuous session:

| Test | File:line | Trace/assertion and implication |
| --- | --- | --- |
| `given_export_001_fixture_inputs_when_write_export_then_zip_and_members_match_fixture` | writer:1669 | writer→every base member bytes equal; parsed entries equal; whole ZIP digest asserted at1720; new empty initialization must preserve it |
| `write_export_binds_signed_acts_catalog_when_provided` | writer:2067 |066 member hash and extension digest/ref/derivation equal expected; keep existing behavior |
| `write_export_emits_068_member_when_signed_acts_manifest_provided` | writer:2130 | member byte identity and binding assertions; raw valid CBOR used, profile verification not implied |
| `write_export_binds_policy_closure_when_provided` | writer:2243 |067 digest/ref/version binding checks; preserve |
| `rejects_signed_acts_manifest_extension_without_member` / policy counterpart | writer:2180,2333 | advertised owned extension + no typed member→named refusal; new families need same pattern |
| `canonicalize_cbor_value_sorts_nested_maps_by_key_bytes` | Integrity cbor:769 | sorted nested keys and exact canonical bytes; must compare with original input for refusal |
| `canonicalize_cbor_value_rejects_duplicate_nested_map_keys` | Integrity cbor:797 | duplicate nested map key→error containing canonical-key refusal |
| `parse_open_clocks_catalog_accepts_canonical_json` | Integrity verify `open_clocks.rs:257` | canonical bytes→one row/expected id |
| `verify_open_clocks_validates_catalog_binding_without_domain_warning` | same:266 | digest/count1/sealed_at11 → no event failures/warnings; no writer emission coverage |

No existing writer tests exercise proposed060/061/062/063/065/open-clock emission. Current tests cannot pass/fail differently under an unimplemented patch; listed compatibility outcomes are future required checks. Concrete negatives: duplicate family/hash; wrong ciphertext content hash; unsorted/duplicate CBOR keys; extension-without-member; stale digest override; incorrect open-clock count; invalid canonical JSON; missing inlined attachment payload. Each must yield named precondition or independent verifier failure, not unnoticed valid export. Controlled010 tests necessary subset only;006/007 cover distinct original ledger fixture sources; open-clock fixture/test coverage must be added explicitly. No concatenating unrelated histories to fabricate a passing full39Need export.

## 5. Observed probe execution and exploration notes

Probe `main` at `crates/trellis-export-writer/examples/full-member-qualification.rs:53` reads the committed010 ZIP and refuses invalid original verification at62–66. It loads exact signed events (80–95), enforces full-array byte equality (81–83), uses each signed authored timestamp for the maintained per-event checkpoint requirement and matches the final committed timestamp (97–112). It passes original registered extensions into the maintained `write_export` (114,129), tests returned member bytes (130–144), verifies the produced ZIP (145), writes diagnostics/ZIP before returning the named missing-member error (146–175). No second writer or synthetic business records exist in this probe. Callers are the explicit fixture-gated Cargo example and receipt argv; callees are fixture input, shared CBOR/COSE helpers, maintained writer and composed verifier. The previously reviewed Result, checkpoint and feature-gate blockers remain resolved.

Cached log shows compilation finished and the probe executable ran; JSON and exit1 trace the missing-member branch at171–172, not an earlier invalid source/precondition. Python receipt stdout has structure true, integrity false, missing attachment manifest/presentation attachment/certificate catalog, relying_party_result invalid; exit0 means checker completion. The original locked attempt exit101 and cold retry timeout/-15 produced no outputs and are prerequisite evidence only. Restored starting lock and absence of consumed-input drift support source binding. Full requested families are listed but the probe stops at necessary010 subset; it never proves their construction.

### Exploration notes and unresolved evidence

H1 medium: closed carriage belongs in native writer; existing public input, emission and server caller reads confirm. H2 medium: proposed canonical guard is sufficient; shared encoder implementation refutes plain round-trip and identifies maintained fix (F1). H3 medium: all existing extension metadata represented; CDDL/native parser refutes digest-only clocks (F2). H4 medium: actual controlledRED will distinguish missing byte carriage from unrelated probe failure; retained cached compilation/run and independent verifier receipts confirm missing060/061/065, while prior failed/timeout attempts do not count as RED. H5 medium: one field/helper lowers duplicate mechanisms; future measurable implementation footprint required, no unmeasured speed claim.

Resolved: exact corrected proposal, actualRED/source-output pins, format-derived open_clock_count and retained execution provenance. Unresolved: final implementation; all prospective positive/negative tests; full D1 consumer custody/history/permissions. Dependency internals beyond read maintained helpers are not certified. No hidden compiler/runtime guarantee.

## 6. Conclusion

VERDICT: APPROVE — corrected BEFORE generic design and AFTER controlled probe/evidence only, suitable for the proposed scoped local commit.

Justification: the corrected proposal specifies maintained recursive canonical encoding, format-derived open-clock count with stale binding replacement, and independent refusal checks; actual compiled current-writer execution establishes the missing-member gap without inventing D1 history. F4/F5 are explicit implementation obligations, not unresolved design blockers. No production implementation is present or accepted.

Coverage of the observed controlled probe/evidence: ADEQUATE for the necessary010 missing-member RED. Coverage of prospective implementation paths: INSUFFICIENT until the promised new emission/negative tests and exact-diff AFTER review exist. Confidence HIGH in the bounded design/evidence decision; MEDIUM in future implementation because proposed functions/types remain unimplemented. The second nonauthor BEFORE certificate and separate AFTER implementation review remain independent gates.
