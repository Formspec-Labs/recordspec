# Registered export evidence inputs: independent AFTER code review

Review ID `trellis-registered-members-after-code-2026-10-08-01`; nonauthor reviewer `/root/oidc_code_review`. Applied the full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`; applicable Rust application, documentation, library, interoperability and universal guidelines were read. Root instructions and Trellis `AGENTS.md` → `CLAUDE.md` apply. Reviewer performed static reads, digest checks and ZIP byte comparisons; executed no Cargo, build, test, verifier or live commands. Only this certificate was written; other agents' source and unrelated lock edits were preserved.

**APPROVE the scoped implementation and retained evidence for a local checkpoint.** The implementation carries and binds the missing native evidence bytes through the maintained writer. Retained native/Python executions, Clippy and actual server caller compilation support the scoped behavior, including the required missing-inline refusal. Final45-file pins match; no unresolved source blocker remains. This certificate does not establish genuine D1 history, custody, creator wiring, agency trust, disclosure admission or a live publication.

## Findings and dispositions

- **F1 — OBSERVATION / ownership / `crates/trellis-server/src/lib.rs:260`.** The server deliberately initializes `evidence_members` empty. `publish_bundle` still performs independent cryptographic and applicable profile checks before reserving/publishing (272–285). Generic carriage works; server derivation of these members remains a separate task. The change gives no new HTTP request input or permission. No correction required within the approved scope.
- **F2 — RESOLVED / test coverage / probe:245–296.** Early review found no independent refusal test for a promised inline attachment with missing ciphertext. The explicit010 `--omit-payloads` run now retains061/065 and the native inlining claim, removes only payload variants, writes the composed report and returns the named missing060 error. Native reports `MissingAttachmentBody` and `PresentationArtifactAttachmentMissing`; independent Python reports `missing_attachment_body`, `presentation_artifact_attachment_missing` and invalid. The retained executed negative satisfies this gate without a duplicate unit test.
- **F3 — RESOLVED / provenance / runner:34–60,76–114.** Early guards missed inputs consumed by the001 fixture utility and other tests; final guard includes the whole fixture tree, local transitive dependency manifests/source and workspace resolution. Numbered attempts retain failures. Binary digest requires Finished/Running log evidence. Leftover groups receive bounded cleanup; process-exit races are caught; lock restoration runs in a nested `finally`; ownership remains retained on cleanup/restoration failure. Observed receipts have no drift in their recorded inputs, absent owned groups and restored starting locks. The final caller runner additionally guards external build schemas/literal include inputs and records explicit build environment; earlier guards did not cover those bytes or historical environment overrides, so their evidence is bounded accordingly. No new executions by reviewer.
- **F4 — OBSERVATION / verification boundary / writer:626–636; tests:2167–2187.** The writer parses JSON only to derive the existing native array count. Canonical JSON, sealed timestamp and clock semantics remain with the maintained Core verifier. Noncanonical JSON can be carried and signed but composed verification refuses it, as tested. This matches the approved byte-carriage scope; successful `write_export` alone must not be presented as publication acceptance.

## 1. Patch summary and exact binding

Baseline Trellis HEAD `5326fe56eed60918fdc7f7d0ce9c9bbf7ccf25a3` contains the retained BEFORE proposal, original RED and independent certificates. Reviewed four-file implementation patch `examples/d1-export/registered-member-implementation.patch` SHA-256 `fce5c023c789c72594ac596577a47183e93c62fefa68ac03c8085f5c394fdaa5`; its bytes match current `git diff --cached --` for exactly the four files below (source/evidence staged by author; reviewer certificate and unrelated Cargo.lock excluded). The qualification runners and observed evidence are also reviewed. Final `examples/d1-export/registered-member-after-input-pins.json` SHA-256 `18cd0e1a89b1ffcfb6a4a89c75ccb0bc44fc019c2b0a6b901cbf2a81c2c7726e` pins45 files; every digest independently recomputed and matched. Reviewer certificates are excluded to avoid self-reference. Final qualification document SHA-256 `21ea91264bfcc17e1ca151f9fd100afd5ff7f02c6190934d801098e55c6b5c02` is included. Shared Integrity helpers remain implementation dependencies, not authored changes; Integrity HEAD previously read `d2dd4827cd294aaecc470e6a49dd8954a48880cf`, with exact consumed source hashes in each receipt.

| Source | SHA-256 |
| --- | --- |
| `crates/trellis-export-writer/src/lib.rs` | `1fbd02fd1f6401aa608174c650a7c6d523aa1c8bbbde22c7515c7bc8a715663d` |
| `crates/trellis-export-writer/src/export_001_fixture_input.rs` | `505d5c339d343bdffd4561a790179697689c99c6fecaaa0c13379be8def2dccf` |
| `crates/trellis-server/src/lib.rs` | `c3afa4e64c22067ca4473d2da48fc85e2afc23b9d667bce462b96ef369aaa9c9` |
| `crates/trellis-export-writer/examples/full-member-qualification.rs` | `e84b5cc671c673c5f362dcc1a9e39f81da9e9efa605cb83a9d7cb8fbbd9cbbc8` |
| `examples/d1-export/probes/run-member-input-qualification.py` (also retained first-two-window copy) | `af4153fb82725980e235d26887d3ad2e5b36897031118135c43feb73c70e3c73` |
| `examples/d1-export/probes/run-caller-minimal-repair.py` | `1570b3610787bf2eddccbd6e9b42e93b59765a169e362c5ad8ff89e7bba80d0d` |

Intent and affected behavior: one public closed `ExportEvidenceMember` enum (writer:174), one `ExportWriterInput::evidence_members` field (317), one preparation helper (580) and one binding merge (702) add060/061/062/063/065/open-clock inputs. Existing031/066/067/068 stay on their maintained typed paths. `write_export` prepares before manifest signing, emits existing `BundleEntry` values and derives top-level payload presence. Both live struct-literal callers initialize empty: fixture utility:129 and server:260; empty-event test:2286 also updated. Probe selects separate006/007/010 histories and supplies their existing bytes. No new manifest dependency, serializer, arbitrary path API, archive writer, business derivation or HTTP API is added.

Concrete simplicity improvement: six closed variants and a five-family fixed table share one validation/emission/binding path, instead of independent writers or repeated per-family merge mechanisms. Existing deterministic ZIP assembly and canonical/digest helpers are reused. One helper prepares entries and metadata; another performs the same owned-key replacement for every family. This is structural reuse, not a measured speed/resource claim.

## 2. Function trace

Locations below are relative to the Trellis repository unless marked Integrity.

| Function/type | File:line | Inputs → outputs | Verified behavior and important calls |
| --- | --- | --- | --- |
| `ExportEvidenceMember` / field | writer `src/lib.rs:174,317` | caller admitted byte vectors → closed native choices | bytes, typed32-byte payload hash and inline flag; no caller paths or permissions |
| `write_export` | writer:383,417,441,510 | ledger/signing/catalog input → signed package/error | current events/proofs/checkpoints unchanged; preparation→existing extensions→new merge→manifest signing→same Bundle emission |
| `prepare_evidence_members` | writer:580 | immutable input/root → entries/bindings/presence/error | every enum arm traced; payload domain hash, fixed paths, duplicate refusal, canonical CBOR array equality, JSON count, digest/ref/count, advertised-extension-without-member refusal |
| `merge_evidence_bindings` | writer:702 | base extensions + derived owned entries → canonical map/error | empty unchanged; Null→map; map removes all matching owned keys then appends actual binding; nonmap refuses |
| `manifest_payload_cbor` | writer:1468,1503 | manifest data and actual payload presence → CBOR | new bool replaces prior hardcodedfalse; all other field constructions unchanged |
| `manifest_extensions_value` | writer:733 | existing witness/seal/066/068/067 inputs → extensions | preserved maintained merge order before new evidence merge |
| `text_map` / `canonical_map` | writer:1784,1793 | derived field pairs → ordered Value map/error | existing key encoding/order behavior reused |
| `publish_bundle` | server `src/lib.rs:190,230,260,272` | closed stored scope → verified publication | empty new field preserves existing service behavior; cryptographic/profile validators precede reserve/artifact write |
| `export_001_writer_input` | fixture input:52,76,129 | committed001 fixture directory → input | only new empty list; signing/event data retained |
| probe `main` | example:54,74,93,111,121,245,250 | chosen fixture/output/mode → archive/diagnostics/exit | original validity gate; exact signed event array equality; retained head timestamp; existing registered catalog/payload inputs; negative drops onlyPayload; independent report before member-error |
| probe `fixture_value`, `field`, `timestamp` | example:22,26,33 | native values → parsed data/error | shared CBOR/COSE lookup; checked unsigned conversions and maintained timestamp constructor |
| `decode_cbor_value` / `encode_canonical_cbor_value` | Integrity `integrity-cbor/src/lib.rs:145,220` | exact bytes/value → single decoded/canonical encoding | trailing-byte refusal; recursive sorting and duplicate canonical-key refusal at158–187; equality prevents normalization |
| `domain_separated_sha256` / `sha256_bytes` | Integrity same:122,135 | tag+ciphertext / catalog bytes → digest | payload uses `trellis-content-v1`; catalogs use bare SHA-256 |
| `Bundle::add_entry`, `to_zip_bytes` | Integrity `integrity-bundle/src/lib.rs:221,239` | fixed entries → deterministic ZIP/error | current assembler reused; duplicate paths refused |
| Core clock parser/validator | Integrity verify `trellis/open_clocks.rs:13,80`; `parse.rs:996` | JSON/binding/sealed timestamp → findings | count/digest and canonical native format checked independently |
| original runner `local_inputs` / execution / cleanup | original Python:34,64,76 | named argv/local inputs → retained receipt/exit | transitive local path/workspace discovery, full fixture guard, subprocess group, timeout cleanup, unconditional lock restoration, exact outputs/log hashes; receipt125 retains ownership on failure |
| minimal runner `lock_diff`, `local_inputs`, `observe_lock`, `retain_final_lock`, cleanup | minimal Python:27,49,124,142,176 | authorized exact starting lock/argv/input guard → result/resolved-lock/diff/receipt | stop any registry version replacement or>10 added registry entries;900-second bound/30-second progress; catches group-exit races; final snapshot before restoration;125 retains ownership on cleanup/restoration failure,126 for policy stop |

## 3. Data flow and invariants

Caller owns catalog derivation/admission and passes exact bytes into `evidence_members`. Preparation borrows immutable input, copies accepted bytes into fixed native `BundleEntry` values, hashes those exact bytes and creates metadata. Binding merge removes stale owned claims, then signed manifest binds newly emitted entries. Package bytes escape to caller; server still verifies before publication. No new data escapes to a network or service in the probe.

- Canonical CBOR bytes remain byte-identical: writer:638–652 compares shared recursive canonical encoding with input and requires arrays; malformed/trailing/unsorted/duplicate keys refuse. Accepted bytes are never rewritten.
- Payload path identity uses typed32-byte content hash and lowercase hex (597–610). Wrong domain hash refuses before signing; duplicate paths/families refuse (603,621). Fixed enum/table paths cannot target000–050 or066–068.
- Catalog bindings use SHA-256 of exact bytes (654); certificate ref is fixed065 and count derives from array length (659–667); clock count derives from native `open_clocks` length (626–636,669–675). Owned stale metadata cannot survive replacement (718).
- An advertised owned extension without its bytes refuses (686–697). Unknown unrelated extensions survive merge. Empty evidence leaves base extensions and false payload presence unchanged, supported by001 exact ZIP parity.
- `payloads_inlined` describes actual060 presence (611), as Core:1526 specifies. `inline_attachments` is a supplied native claim (658), independently checked against all referenced ciphertext by composed verification; the negative proves absence refuses. It conveys no disclosure authority.
- JSON remains exact-byte opaque carriage after format-level count extraction. The existing verifier owns canonical JSON and sealed time; noncanonical carriage yields a verifier refusal, not successful publication acceptance.
- Probe original signed event bytes are retained; each fixture keeps its own history. Final checkpoint uses exact retained head timestamp, since006/007 authored time differs. Member byte equality is asserted independently of regenerated manifest/checkpoints. Probe evidence does not claim whole ZIP parity with006/007/010 originals.
- Runner snapshots starting lock and restores exact bytes. Full guarded inputs include1343 fixture files plus local source/manifests/config/runner. The guard is deliberately overinclusive; it is not proof of registry dependency bytes beyond pinned lock checksums. Window release requires confirmed cleanup/restoration, separately from a command result.

## 4. Test behavior and edge cases

**Reviewer executed none.** Read retained external command receipts/logs/output, inspected source assertions, recomputed receipt/log/output/source hashes and directly compared ZIP member bytes with committed fixture bytes.

| Test/qualification | File:line | Read assertion trace and observed behavior |
| --- | --- | --- |
| `evidence_catalogs_bind_exact_native_bytes_and_fixed_paths` | writer:1888 | each061/062/063/065 prepares one fixed path, byte-identical member, correct bare digest; inline flag and065 ref/count asserted; PASS |
| `evidence_rejects_duplicates_bad_hashes_and_noncanonical_catalogs` | writer:1958 | `write_export` rejects duplicate payload, wrong content hash, all five duplicate catalog families, nested unsorted map, duplicate nested key, nonarray and truncated CBOR; PASS |
| `registered_evidence_extension_requires_member_and_preserves_unknown_extensions` | writer:2018 | all five registered claims without bytes→named error; unknown extension survives actual manifest; PASS |
| `payload_presence_and_catalog_digest_replace_stale_bindings` | writer:2049 | actual060 byte equality, payloads_inlinedtrue and derived063 digest replace stale Null; PASS |
| `native_open_clock_count_is_derived_and_signed_count_tampering_fails` | writer:2096 | canonical native member with stale99 becomes count1/exact digest and verifies; resigning count2 preserves valid signature but verifier refuses; PASS |
| `open_clocks_malformed_input_and_noncanonical_output_refuse` | writer:2167 | malformed/no/null array rejects; extra newline is carried without normalization but independent verification rejects; PASS |
| existing001 byte-exact export | writer:2191 | base members and parsed entries equal fixture, whole ZIP digest unchanged; PASS |
| existing witness/seal/066/068/067/empty/Merkle tests | writer:2248–2889 | existing named refusal and binding/parity paths retained; all23 writer tests PASS |
| separate native010/006/007 probe | example:54–304 | original valid; required members present and exact bytes; output structure/integrity true, no missing/mismatched members; exit0 for each |
| native010 missing-inline probe | example:245–296 | onlyPayload omitted; missing060 plus named composed attachment failures; structure true/integrity false; expected exit1 |
| independent Python originals/generated | retained `original-python-baselines.json`, `generated-python-verification.json` | three original baselines and three generated archives valid; generated negative invalid with named missing attachment failures; Python exit0 is checker completion, not automatic archive acceptance |

Concrete risks/coverage: duplicate or wrong-hash input is pre-signing bad_request, covered; wrong count with valid signature is independent-verifier refusal, covered; missing inline ciphertext is refusal, covered externally; unknown extensions preserve bytes/metadata, covered. Full D1 open clocks and real business/history relationships are deliberately outside synthetic format/binding coverage. Existing shared canonical tests at Integrity cbor:769,797 also assert nested ordering/duplicate-key behavior. No missing changed-path test remains within the scoped native carriage goal. Clippy and server caller check now have actual passing receipts. Formatting is reported in the qualification document; no separate formatter receipt is present in this45-file evidence set, so this review does not claim independent formatter execution.

## 5. Observed execution and exact receipts

Receipts are under `examples/d1-export/probes/member-input-after/` and pin exact argv/cwd, rustc1.89, starting lock `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`, transient generated lock `d8e6bd3dfb558d300ea85bd20d59047cf9d3b65916655f32d3951d10d8d803a7`, source/fixture guard, output and log hashes. All completed native receipts report owned group absent, starting lock restored and no drift in recorded guards. Fresh read-only comparisons match1433 guarded files for writer tests/Clippy/probes,1521 for the two timed-out caller attempts and1529 for the final caller check. The older guard omits external build/include inputs and explicit environment; the final caller guard includes them. These limitations are preserved rather than retroactively expanded. Probe log Finished/Running and actual binary digest `795283e0b3a06d3c4dcc307ed02d085a26d0234a38737e16b6aafb55b3023bd8` confirm source-built execution rather than an installed verifier result.

| Receipt/artifact | SHA-256 | Observed result |
| --- | --- | --- |
| `writer-tests-receipt.json` | `61b9e4f8c3c2b21ef544df6f2abd29c3e86529de55bdb80627534de0d4f69420` | exit0;23PASS including001 exact parity |
| `probe-010-receipt.json` | `f8d105e2124eb7b8e95f11c530845737753a73273f5b7c4a87ce2f95de571fe9` | exit0;060/061/065 bytes exact |
| `probe-006-receipt.json` | `cc52e82c98e181d5980e8a1c35d1393d77531209d490ec23c6a4b2b019ce9e8b` | exit0;062/066/067/068 bytes exact |
| `probe-007-receipt.json` | `334fe09a12ca6cac7a7e3ea02feeb122cc7cb9ca923e0f500f5414cff40421c1` | exit0;063 bytes exact |
| `probe-010-missing-inline-receipt.json` | `4dc7d2327c9c262fd1e415bd4b59e9149ede45859254d6bd3bb9fa242c8e3731` | expected exit1;named missing attachment failure |
| `original-python-baselines.json` | `1abf3d51ce771648582147d304aff29b1bce6594a9f16ffe617c687cc4db7086` | three source ZIPs valid |
| `generated-python-verification.json` | `66556b3c5ce7df4d360def289608007b9321061fe8070a13ae66ebdf3bc0b00e` | three positive valid;negative invalid |
| `writer-clippy-receipt.json` | `3deeef9015616c14c9cadc78b68435cb5ffb2c1216861613ce082f4fc8a4c6c1` | exit0;all targets/features, warnings denied |
| `server-check-receipt.json` | `bd46eeda18b50329c2a06ea16cb13ca4d972ab0ab157c20c12948b3d87385ff4` |300-second dependency timeout;not caller pass/failure |
| `server-check-attempt-2-receipt.json` | `b7608109ab6be66baa801d56e63aabf7f256cd603c2e82904edbf35f61db6411` |second300-second dependency timeout;not caller pass/failure |
| `server-check-minimal-receipt.json` | `4422ec5d37da2846d71d959b1549eb53f7675b63637bda6910ed063f8a9d5b85` | exit0;actual trellis-server compilation in91seconds |

Generated positive ZIP SHA-256:010 `f5b46c3aa881339fcdf3ed79c4cc639d85a1e7b023aafdf02ae1683bd99f99d0`;006 `895caa62395790afcd9e20ef69d2096ef318a3635a263f0ecce928f61a1d7dea`;007 `0b25d5949bf30efe9ed4273dcdc0e5d3811bb83df3b7378f2e3207523d76ba7b`. Negative ZIP `e2c244e7fe514e6035bcd1ddc00d95162765ab881067e30bef2a807eba78ab3f`. These raw ZIP identifiers differ from manifest/checkpoint domain-separated identities. Python verifier source digests also match fresh reads.010 retains an advisory missing policy-closure finding in both source and generated verification; it is not hidden or promoted to genuine D1 completion.

Final caller log SHA-256 `696748bcaba9e44a0170d6993ab4eaafad67591eacca7a0caec2869921cb64f7` explicitly shows `Checking trellis-server` then `Finished` in1m31s. Final receipt records empty package additions/removals/replacements and no policy stop. Direct starting/resolved lock diff adds only existing `async-trait` to `stack-common-auth` dependency list; resolved temporary SHA `e8db9355f0959eebb70c3d951168497ae579224fb7d1ee07ab71f4c90e6b8523`. Current Cargo.lock equals starting SHA `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`, including the unrelated foreign line. Native group absence and direct release to Core are retained in immutable third-window summary `bfa28d140804edc6de2556f07ad7b848635ea791a69632479d2277d6ec0fc6c1`; this read-only review performs no new live process audit. Final caller pass qualifies compilation under its recorded inputs/environment; it does not reinterpret either earlier timeout as a pass or establish a general performance improvement. Retained raw patch context spaces/log final blank line are evidence-format whitespace, not a source defect.

## 6. Exploration notes and remaining gaps

H1 medium: shared canonical helper prevents normalization/duplicate acceptance. CONFIRMED by helper implementation, equality branch and nested negatives. H2 medium: generic metadata replaces stale caller claims and byte paths stay closed. CONFIRMED by fixed table, typed hash and tests. H3 medium: actual060 omission independently refuses. CONFIRMED by native and Python negative evidence. H4 medium: source-bound probe preserves all required006/007/010 evidence bytes. CONFIRMED by assertions and fresh direct ZIP/source comparison. H5 medium: runner release is cleanup-safe and consumed inputs remain stable. REFINED after complete fixture guard and nested finally corrections; completed receipts confirm intended paths, not every exceptional OS/filesystem failure. H6 medium: server caller compiles with empty new field. CONFIRMED by final minimal-repair caller log, exit0 and exact source/lock pins.

Next action rationale: exact final pins, current staged four-file patch and required results are verified; no further source exploration is warranted without changed bytes or a new finding. Dependency internals beyond the read maintained primitives are not independently certified. Live case export/admission, WOS consumer derivation and full39Need construction remain outside this review.

## 7. Conclusion

VERDICT: APPROVE — exact scoped native evidence carriage implementation/evidence for a local checkpoint; no blocking findings.

Justification: the patch meets the closed native evidence-carriage intent with source-built positive results and independent negative refusal. Coverage of changed carriage paths: ADEQUATE. Confidence HIGH in this bounded implementation/evidence assessment. Actual23-test pass,001 exact parity, three native positive histories, named native/Python missing-inline refusal, Clippy and actual caller compilation support the conclusion against the exact45-file map and staged patch. No push/release/live publication approval is implied; full39Need case construction and consumer/service derivation remain unqualified. Separate architecture certificate remains the independent architectural disposition.
