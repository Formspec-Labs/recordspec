# Registered evidence input: AFTER architecture review

**VERDICT: APPROVE the exact registered-member library change and controlled synthetic qualification evidence. No architecture blocker remains.** The patch adds library byte-carriage capability; the service initializes the new field empty and therefore gains no live D1 member selection from this change alone.

Reviewer `/root/oidc_arch_review`, independent non-author, October 8, 2026. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` used for Rust review. Static diff/source inspection only. No Cargo, build, execution, service/source/lock edits. Only this certificate written. Trellis released its native window to Core; this review grants no execution authority.

## 1. Artifact summary and snapshot

Trellis HEAD `5326fe56eed60918fdc7f7d0ce9c9bbf7ccf25a3`; uncommitted patch is bound separately:

| Source | SHA-256 |
| --- | --- |
| `crates/trellis-export-writer/src/lib.rs` | `1fbd02fd1f6401aa608174c650a7c6d523aa1c8bbbde22c7515c7bc8a715663d` |
| `crates/trellis-export-writer/src/export_001_fixture_input.rs` | `505d5c339d343bdffd4561a790179697689c99c6fecaaa0c13379be8def2dccf` |
| `crates/trellis-server/src/lib.rs` | `c3afa4e64c22067ca4473d2da48fc85e2afc23b9d667bce462b96ef369aaa9c9` |
| `crates/trellis-export-writer/examples/full-member-qualification.rs` | `e84b5cc671c673c5f362dcc1a9e39f81da9e9efa605cb83a9d7cb8fbbd9cbbc8` |

Category: proof infrastructure/public library input. Trigger: retained actual RED omitted 060/061/065 while native source fixture verified, established in the exact approved `registered-member-before-architecture-review.md`. Shape: closed `ExportEvidenceMember`, one preparation/binding path, existing archive assembly. Consumer semantics/public creator remain outside scope.

## 2. Lineage and relationships

| Artifact | Relation | Citation |
| --- | --- | --- |
| Approved BEFORE proposal/certificate | Constrains families, validation and ownership | `registered-member-input-proposal.md:Problem and smallest owning change`; `registered-member-before-architecture-review.md:Final evidence refresh` |
| Core | Existing paths, hash domains, registered bindings and offline checks | `specs/trellis-core.md:9.3,18.2–18.3,19` |
| GOAL/philosophy/local guide | Independent evidence; reuse and inward dependencies | `../GOAL.md:Critical Path 5`; `../DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility`; `CLAUDE.md:Architecture` |
| Current service profile | Existing031/066/067/068 support must stay canonical | `crates/trellis-server/src/export_profile.rs:129–158` |

| Seam | Owner | Dependencies / consumers | Named? |
| --- | --- | --- | --- |
| Closed byte input | Trellis writer | Primitive bytes/hashes; application adapters | Yes, writer `lib.rs:174–198,320` |
| Preparation/binding | Trellis composition | Existing CBOR/hash/BundleEntry; manifest signer | Yes, `lib.rs:546–722` |
| ZIP assembly | Integrity | Existing Bundle; writer/verifiers | Existing, `write_export` retained |
| Actual evidence/disclosure | Application exporter | Accepted source and reader grants | External; server currently initializes empty |
| Fixture qualifier | Test example | Separate010/006/007 sources; verifier | Existing example extended, not joined history |

## 3. Invariants and commitments

- **Single writer/byte assembler — PRESERVED.** `write_export` prepares entries and merges derived binding before signing (`417,441`); existing `BundleEntry` and ZIP serializer remain in use.
- **Closed paths — PRESERVED.** Six enum variants, fixed five-catalog table and hash-only payload path. Duplicate paths reject; no arbitrary path input.
- **Hash domains — PRESERVED.** Payload branch uses domain-separated content hash; catalog path uses bare SHA-256. Presentation hash remains outside new API.
- **Canonical accepted bytes — PRESERVED in CBOR path.** Decode/canonical-encode equality rejects normalization, duplicate keys and noncanonical ordering. Open-clock format parsing derives count; existing verifier retains canonical JSON responsibility.
- **Derived binding and flags — PRESERVED.** Existing advertised member without bytes refuses; stale controlled extensions replaced with observed member digests/count. `payloads_inlined` derives from entries. Consumer verification still checks attachment inlining truth.
- **Existing mechanism authority — PRESERVED.** Existing031/066/067/068 types not duplicated. Only empty initializers added in fixture/service.
- **Live outcome claims — MUST REMAIN BOUNDED.** Server empty initializer means no producer chooses new permitted evidence yet. Library success cannot qualify full D1, live source custody, reader disclosure or trusted agency keys.

## 4. User-value and simplicity

The patch makes previously unrepresentable registered evidence bytes available through the maintained library. This directly addresses the measured missing-member boundary and preserves application-owned admission/disclosure.

Snapshot footprint: writer +528/-5 lines, including roughly307 test lines and220 production/API lines; example +154/-31; two one-line empty initializations. One closed field and one catalog table/preparation/merge path handle five catalog families plus payloads. That avoids five separate emitter/digest APIs. It adds code to supply missing capability rather than shrinking total code; no measured speed or memory improvement is claimed. Existing duplication in other binding helpers is not expanded into this task.

The numeric table indexes are correct in inspected branches. A private named family enum could improve readability if more families arrive, but introducing it now is optional and no correctness defect follows from current mapping. Avoid an unrelated broad refactor before verification.

Falsifiability: library output advertises a catalog without its emitted bytes, changes empty-input001, normalizes original admitted bytes, or omits a required member while reporting success.

## 5. Counterfactuals

Kill criterion: native verification reveals binding/count/canonicalization defects, or existing empty-input output changes. Fix the owning path before final acceptance.

Counter-decision: an arbitrary path/byte API would be smaller at declaration level but weaken reserved-name and registered-capability restrictions. Current fixed variants preserve the closed boundary.

Removal: library remains unable to carry missing native families; service profile still works for existing fields.

Sibling subsumption PARTIAL: existing catalog derivation and primitive ZIP/hash/CBOR handling are reused; no application logic duplicated.

Six-month critic: flags claims that server export is now complete when server never populates `evidence_members`, or treats byte-level unit catalogs from distinct fixtures as joined case histories.

## 6. Findings

**F1 — KEEP.** Severity OBSERVATION; category ownership. Location: writer `lib.rs:174–198,546–722`. Implementation matches the approved closed input design. The Core registered names and hash rules flow through existing `BundleEntry` assembly; application evidence derivation remains outside the writer. Keep one shared preparation/merge path. No new transport, public creator or serializer was found.

**F2 — KEEP.** Severity OBSERVATION; category scope. Location: `registered-member-implementation-qualification.md:Executed checks`; final pins and receipts below. Writer23 tests,001 parity,010/006/007 exact-member probes, missing-inline negative, independent Python verdicts, Clippy and server caller pass substantiate the intended library behavior. Preserve failed attempts and their guard limitations alongside passing evidence. All45 final pins match; source drift requires fresh pins.

**F3 — DEFER the live outcome decision.** Severity OBSERVATION; category intent-vs-shape. Location: server empty `evidence_members` initialization and qualification document's scope limits. Existing service `export_profile.rs:129–158` owns derived066/067/068; this patch supplies no new production selection. Keep this approval scoped to library capability and synthetic qualification. Genuine D1 history, trusted issuer evidence, reader grants and field visibility require their owning application evidence before a live completeness claim.

**F4 — KEEP the present footprint.** Severity OPTIONAL; category debt-accretion. Location: writer `EVIDENCE_BINDINGS` and preparation branches. A private family enum could replace numeric table indexes if the family set grows, but inspected mappings are correct. The shared table/path already avoids five separate emitters. No RESHAPE or REVERSE finding is supported; an unrelated helper rewrite would add scope without resolving an observed defect.

## 7. Final verdict

VERDICT: APPROVE. Final 45-file pins and successful server caller receipt are independently read and bound below. Intent MATCHES approved proposal; user-value SUPPORTED by actual prior RED; commitments HONORED in static shape; debt PAYS DOWN missing capability via shared machinery while adding necessary code; sibling subsumption PARTIAL; confidence HIGH for ownership/source shape, HIGH for tested library behavior; no inference to untested live export behavior.

All six reasoning phases applied. H1 patch adds consumer semantics REFUTED by primitive-only preparation. H2 patch duplicates existing typed031/066/067/068 REFUTED. H3 static test source proves behavior REFUTED; retained native and independent verifier executions now supply behavior evidence. H4 service now emits new families REFUTED by empty initializer. Approval covers the exact reviewed library change and recorded synthetic evidence; full D1 remains unqualified.


## Retained execution evidence reviewed

Exact four-file implementation patch SHA-256 `fce5c023c789c72594ac596577a47183e93c62fefa68ac03c8085f5c394fdaa5`; example final source change adds qualified optional missing-inline selection and observed event failures. Current source pins above match execution shape. No dependency declarations, manifests or generic wire schemas changed in the four-file implementation. The caller check used a temporary minimal lock repair described below and restored the starting lock.

| Receipt / evidence | SHA-256 | Observed result |
| --- | --- | --- |
| writer-tests | `61b9e4f8c3c2b21ef544df6f2abd29c3e86529de55bdb80627534de0d4f69420` | 23 passed; includes001 exact export parity and six new focused tests |
| probe010 | `f8d105e2124eb7b8e95f11c530845737753a73273f5b7c4a87ce2f95de571fe9` | exit0; source required member bytes unchanged; integrity/structure true |
| probe006 | `cc52e82c98e181d5980e8a1c35d1393d77531209d490ec23c6a4b2b019ce9e8b` | exit0; isolated signature chain/catalog passes |
| probe007 | `334fe09a12ca6cac7a7e3ea02feeb122cc7cb9ca923e0f500f5414cff40421c1` | exit0; isolated intake chain/catalog passes |
| probe010 missing-inline | `4dc7d2327c9c262fd1e415bd4b59e9149ede45859254d6bd3bb9fa242c8e3731` | expected exit1; missing attachment body/presentation attachment |
| writer-clippy | `3deeef9015616c14c9cadc78b68435cb5ffb2c1216861613ce082f4fc8a4c6c1` | exit0 with all targets, fixture feature, warnings denied |
| original Python baselines | `1abf3d51ce771648582147d304aff29b1bce6594a9f16ffe617c687cc4db7086` | original synthetic sources valid |
| generated Python checks | `66556b3c5ce7df4d360def289608007b9321061fe8070a13ae66ebdf3bc0b00e` | three valid; missing-inline invalid |

Generated010 ZIP SHA `f5b46c3aa881339fcdf3ed79c4cc639d85a1e7b023aafdf02ae1683bd99f99d0`;006 `895caa62395790afcd9e20ef69d2096ef318a3635a263f0ecce928f61a1d7dea`;007 `0b25d5949bf30efe9ed4273dcdc0e5d3811bb83df3b7378f2e3207523d76ba7b`; missing-inline `e2c244e7fe514e6035bcd1ddc00d95162765ab881067e30bef2a807eba78ab3f`. Python receipts bind those inputs and verifier sources. The diagnostic binary is pinned as `795283e0b3a06d3c4dcc307ed02d085a26d0234a38737e16b6aafb55b3023bd8`.

Each inspected native receipt records empty source/fixture drift, absent owned process group and restoration to the starting lock digest `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`. These are retained execution observations; this reviewer did not rerun processes or establish live process state. Original RED remains retained separately and turns GREEN only for supported valid010 inputs. Missing-inline stays RED because byte carriage does not manufacture referenced content.

The six focused tests cover fixed path/digest/count/ref, payload hash and duplicates, catalog family duplicates, malformed/noncanonical/duplicate-key CBOR, extension/member pairing, unknown extension retention and replacement, actual payload flag, native clock count, signed-count tampering and malformed/noncanonical clock JSON. This supports the exact byte-boundary design. It does not assert complete D1 clock/business history. Existing composed validation remains required for service publication; server empty initialization retains that limitation.

The shared-path improvement is demonstrated structurally: five catalog path/digest tuples feed one preparation path and one replacement merge, plus one payload branch. Six public variants do not create six independent writers. Production code grows to implement missing capability; total line reduction and speed/resource wins are not claimed. This is the measured constraint/tradeoff: source count increases while repeated per-family mechanisms are avoided. No broader helper refactor is needed for acceptance.

## Final snapshot and caller qualification binding

Final input index: `examples/d1-export/registered-member-after-input-pins.json`, SHA-256 `18cd0e1a89b1ffcfb6a4a89c75ccb0bc44fc019c2b0a6b901cbf2a81c2c7726e`. Independent readback checked all45 path/hash pairs: **zero mismatches**. Reviewer certificates are explicitly excluded from this index to avoid self-reference. Current HEAD independently matches `5326fe56eed60918fdc7f7d0ce9c9bbf7ccf25a3`; implementation remains the separately pinned four-file patch `fce5c023c789c72594ac596577a47183e93c62fefa68ac03c8085f5c394fdaa5`. Final qualification document SHA-256 `21ea91264bfcc17e1ca151f9fd100afd5ff7f02c6190934d801098e55c6b5c02`.

Caller receipt `probes/member-input-after/server-check-minimal-receipt.json` SHA-256 `4422ec5d37da2846d71d959b1549eb53f7675b63637bda6910ed063f8a9d5b85` records `cargo check --offline -j1 -p trellis-server`, exit0, approximately91.65seconds, rustc1.89.0, input drift `{}`, process group7300 absent and starting lock restored. Log SHA-256 `696748bcaba9e44a0170d6993ab4eaafad67591eacca7a0caec2869921cb64f7` binds the completed check. The temporary resolved lock SHA-256 `e8db9355f0959eebb70c3d951168497ae579224fb7d1ee07ab71f4c90e6b8523` retains every package/version selection and adds only the existing `async-trait` entry to `stack-common-auth`'s dependency list. Starting lock SHA-256 is `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`. This is caller compile evidence, not a live request test.

The two earlier caller attempts each exhausted300seconds during dependency checking. Retained receipt hashes are `bd46eeda18b50329c2a06ea16cb13ca4d972ab0ab157c20c12948b3d87385ff4` and `b7608109ab6be66baa801d56e63aabf7f256cd603c2e82904edbf35f61db6411`. Neither is classified as a pass or a source failure. The final runner records explicit non-secret build environment/configuration and external build/schema/include inputs; older guards did not capture all external bytes or historical environment overrides. Their stability statements therefore apply only to their recorded inputs. The final native-window summary SHA-256 `bfa28d140804edc6de2556f07ad7b848635ea791a69632479d2277d6ec0fc6c1` preserves cleanup observations. This reviewer read receipts and hashes, did not rerun commands or assert current live process state.

Invariant failure consequences: violating closed paths permits reserved-name substitution; violating the two hash domains breaks content identity or catalog integrity; accepting normalized CBOR alters admitted bytes; wrong derived flags/counts misstates completeness; duplicating application derivation creates competing authority; bypassing composed verification permits structurally carried evidence to be advertised as semantically complete. Core §9.3,§18–19 and the cited source checks declare these boundaries. The executed positive and negative probes test the byte boundary; genuine legal signing assurance and application admission remain relied-upon external responsibilities.

Final confidence is HIGH for the exact source ownership and exercised library boundary. Intent matches the approved BEFORE shape; user value is supported by actual native RED→GREEN; commitments are honored; missing capability is paid down through shared machinery with necessary code growth; sibling subsumption is PARTIAL. Evidence does not establish performance improvements, full39 desired-member construction, real D1 completion, live export, agency trust or field-level disclosure. No blocking correction is required within the reviewed scope.
