# Registered evidence-member input: architecture BEFORE review

**VERDICT: APPROVE the corrected prospective registered-member input design. APPROVE the controlled probe/evidence slice for scoped local commit.** Current-source execution and independent Python verification now demonstrate the missing 060/061/065 byte carriage. Approval is a BEFORE architecture gate for the exact proposal and an AFTER gate for the diagnostic evidence; no generic implementation exists or is accepted. The second independent gate and root scheduling remain prerequisites for implementation.

Independent non-author reviewer `/root/oidc_arch_review`, October 8, 2026. Full architecture skill retained and applied: `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`; Rust-review skill retained: `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md`. No Cargo, build, probe execution, live calls, service changes or Rust edits. Only this certificate written; shared work preserved.

## 1. Artifact summary

Proposal: `examples/d1-export/registered-member-input-proposal.md`, SHA-256 `9e0e86a03016ffa839d561cc9fdabb34e14e81efa42e8485998b95df2be05c25`. Trellis HEAD `092792f9f57d94db9e1f67390b9037d1908c1a01`. Inspected writer source `crates/trellis-export-writer/src/lib.rs`, SHA-256 `955cac11ad0dc1966b4484aed25a096eab58386229345871ad7f522d560db60b`. These pin the prospective design, not an implemented diff.

Category: proof infrastructure/public library input boundary. Problem: registered 060/061/062/063/065/open-clock archive members have no writer byte inputs, although free extensions may claim corresponding bindings. Decision: add one closed `evidence_members: Vec<ExportEvidenceMember>` input field, one preparation path using existing `BundleEntry`, and derived registered digest bindings. Preserve 031/066/067/068 inputs. No consumer derivation, new request format, HTTP creator or ZIP serializer.

Beneficiaries: application exporters and recipients needing exact permitted records. Retained current-source native execution now supplies actual member RED; the locked prerequisite refusal and cold compilation timeout remain separate attempts, not writer evidence. See exact final evidence binding below.

## 2. Lineage and relationship tables

| Artifact | Relation | Citation |
| --- | --- | --- |
| GOAL | Parent: exported evidence and independent verification | `GOAL.md:Product Claim; Critical Path 5` |
| Development philosophy | Parent: maintained mechanisms, wire fixtures, narrow ownership | `DEVELOPMENT-PHILOSOPHY.md:Naming discipline; Evidence and responsibility` |
| Trellis guide | Dependency direction and consumer boundary | `CLAUDE.md:Architecture` |
| Core | Normative ciphertext hash, registered members/digests | `specs/trellis-core.md:9.3,18.2–18.3,19` |
| Controlled qualification | Necessary subset must first produce actual failure | `examples/d1-export/controlled-writer-qualification.md:native010 paragraphs` |
| Existing writer inputs | Existing sibling capabilities must remain canonical | `src/lib.rs:247–289,520–580` |
| Server profile | Existing consumer derivation subsumes 066/067/068 work | `crates/trellis-server/src/export_profile.rs:129–158` |
| Certificate ADR | Rationale for catalog shape only; normative digest comes from Core/code | `thoughts/adr/0007-certificate-of-completion-composition.md:Export manifest catalog` |

| Component / seam | Owner | Dependencies / consumers | Named? |
| --- | --- | --- | --- |
| `ExportEvidenceMember` | Trellis writer | Registered fixed names; application-provided bytes | Proposed closed enum, exact design still pending |
| Preparation/binding | Trellis composition | Existing CBOR/hash helpers; manifest signer | Proposed helper; existing merge patterns `520–580` |
| ZIP entries/order | Integrity | Existing `BundleEntry`/assembler | Yes, Core §18 substrate authority |
| Catalog derivation/disclosure | Application adapters | Genuine events, granted recipient fields; writer input | Existing consumer-owned obligation, not enum semantics |
| Verification | Core plus WOS bindings | Exact archive; digest/source relationships | Yes, Core §19 and composed validators |

## 3. Invariants and commitments

1. **Single maintained writer — PRESERVED.** Proposal preparation helper feeds current `write_export` and Integrity assembly (`src/lib.rs:354–451`). Failure would duplicate archive byte behavior.
2. **Closed registered paths — NEWLY INTRODUCED input restriction, preserves existing wire.** Enum maps fixed variants to existing filenames; payload path derives from fixed hash bytes. Reject duplicates; no arbitrary reserved path override. Failure would allow unbound files or collisions with mandatory/orientation members.
3. **Binding derives from emitted bytes — PRESERVED/extended.** Existing 031/066/067/068 merge helpers derive digests (`520–580`). New registered extension without bytes refuses; stale supplied digests cannot be signed as authoritative. Failure creates a signed manifest that claims unavailable/different evidence.
4. **Ciphertext content hash differs from catalog digest — RELIED-UPON.** Core §9.3 uses domain-separated `trellis-content-v1` over exact ciphertext. Core §6.7 catalog bindings use bare SHA-256; current certificate verifier uses `sha256_bytes(catalog_bytes)` (`integrity-stack/crates/integrity-verify/src/trellis/certificate.rs:297`). Presentation-artifact hash has another domain and belongs to existing certificate validation. Mixing them rejects valid fixtures or binds wrong bytes.
5. **Consumer meanings stay outside center — PRESERVED.** Opaque admitted bytes, generic canonical-CBOR array checks, and digest/filename bindings do not infer actor authority, consent, complete history or field permissions. Core/profile verification still rederives relationships.
6. **Truthful inlining flags — RELIED-UPON.** Core §18.3 `payloads_inlined` must reflect actual payload entries. `inline_attachments` is a caller's assertion whose referenced-entry completeness remains checked by existing composed verification (Core §19 attachment checks). Failure permits misleading success despite missing attachment bytes.
7. **No public transport/wire revision — PRESERVED.** Proposal changes local input struct initializations; existing BundleCreateRequest, catalog shape and ZIP format stay unchanged. Empty input must preserve fixture001 bytes.
8. **Evidence precedes implementation — PRESERVED after observed RED.** Proposal last paragraph and current direct owner instruction require actual RED/exact design. Build failure or timeout cannot satisfy that gate.

## 4. User-value analysis

One closed field enables currently missing registered native evidence bytes without a parallel exporter. Conceptual debt remains bounded by fixed native families and existing hash/entry helpers. The six-family design is justified by the frozen desired graph plus existing schema/verifier families; native010 alone proves only the first 060/061/065 path, so independent fixtures must qualify 062/063/open-clock behavior before claiming all-family coverage.

Smaller candidate considered: enable only010's files. That would solve the observed subset but force repeated input/binding designs for already-required native families. The proposed common byte-carriage path is reasonable provided no extra consumer logic or arbitrary file capability is added. Existing 031/066/067/068 remain separate canonical inputs, avoiding duplicated public mechanisms.

No speed/resource claim is warranted. AFTER review should count duplicated binding/emission code and identify any new helper that fails to replace repetition. Value refutation: final archive verifies cryptographically while required source records remain missing, grants are ignored, or generic emitter requires D1-specific branches.

## 5. Counterfactual analysis

Kill criterion: actual probe failure is input conversion/build setup rather than missing carriage, or canonical writer already supports the needed path. Reassess before modifying its public input.

Counter-decision: arbitrary path/byte entries would reduce variant declarations but permit collisions and unbound capabilities; reject it. Consumer catalog derivation in writer would make apparently convenient inputs depend outward on WOS/Formspec; reject it.

Removal probe: removing proposal breaks no runtime today. Existing typed profiles remain functional; missing native member carriage stays unresolved.

Sibling subsumption: PARTIAL; existing profile/type helpers supply known mechanisms, not missing input families. Reuse shared `BundleEntry` and primitive digest/CBOR routines; no new serializer.

Six-month critic: flags inconsistent hash domains, empty vectors changing previous output, extension-member disagreement, or “all D1 evidence supported” stated after only010 passed.

## 6. Findings

**F1 — KEEP, RESOLVED by final evidence.** Initial severity BLOCKER for implementation approval; category scope/evidence. Location Status and final paragraph. Actual RED is now present: successful current-source compile, original fixture structure/integrity true, generated output structure true/integrity false, and missing payload/attachment/certificate members. Execution and independent Python receipts bind exact inputs/outputs and retained logs. No binary digest was supplied in the native receipt; qualification therefore uses recorded toolchain, compiled-source guard and build/execution log, without a reusable executable identity claim. Keep cold timeout/prerequisite refusal separate.

**F2 — KEEP, clarify exact hash domains.** Severity OBSERVATION; category named-seam. Location variant table/preparation helper. Use existing domain-separated payload content hash over ciphertext and bare catalog SHA-256. Never substitute certificate presentation hash as a payload path hash. Proposal cites appropriate Core sections but exact design should name the existing primitive calls so implementation does not infer a CBOR hash over raw file bytes.

**F3 — KEEP.** Severity OBSERVATION; category ownership. Location byte validation paragraph. Generic array/canonical-byte validation belongs here; full event/actor/catalog relationships and recipient permission remain consumer/composed-verifier duties. Supplied `inline_attachments` is not an admission result. Existing validator must reject missing referenced payloads before publication.

**F4 — RESHAPE only if exact design duplicates existing binding paths.** Severity OPTIONAL; category debt-accretion. Location shared helper. One narrow fixed-key merge helper should centralize extension replacement/pair validation; preserve non-conflicting unknown existing extensions. Do not add a second 066/067/068 path or broaden this change into wholesale writer refactoring.

## 7. Verdict and pending gate

**APPROVE exact corrected prospective design and AFTER controlled-probe/evidence scope.** Intent vs shape MATCHES; user-value SUPPORTED as native proof capability; commitments HONORED by corrected design and observed evidence; debt NEUTRAL/PAYS DOWN if shared helper removes repetition; sibling subsumption PARTIAL; confidence HIGH for source/ownership and MEDIUM for eventual correctness.

Final evidence and proposal are bound below. This review itself performs no Rust changes or Cargo; implementation remains root-routed and requires the other independent gate. All six phases completed: H1 missing-member carriage causes failure CONFIRMED by native member assertion and independent Python missing-member failures; H2 free-form extensions alone guarantee carriage REFUTED by writer inputs/emission; H3 one closed input must duplicate consumer derivation REFUTED by generic byte/path/digest responsibilities; H4 010 can prove full desired families REFUTED by distinct fixture/evidence gates. Further review follows actual output and exact design, not unrelated runtime/API work.


## Final evidence refresh and AFTER qualification

All 21 files in `registered-member-before-input-pins.json` independently match their declared SHA-256 values. Pin file digest: `8b3616c79305d0646ae89f1ac5d1dcdcf37e88d853e0bb2b23a0443fbe847868`. Exact final artifacts:

| Artifact | SHA-256 |
| --- | --- |
| Corrected proposal | `9e0e86a03016ffa839d561cc9fdabb34e14e81efa42e8485998b95df2be05c25` |
| Controlled result document | `ae9a0893c903b95d2dfdfe5c161f501f5edd2c376f294c5f9fe77bb87791d0c8` |
| Native cached-run receipt | `ef2763626a0a39a0e36d50be51089858f63125b0d7d834d0e9ae55741a9cb601` |
| Native cached-run log | `6d1b407ee1b76b9fb20344da46ee33b85e07d16ec7641bd10096e989bbd3ef80` |
| Generated controlled ZIP | `969a421696cfbb44baccb87598281a58625ab57dceac1d8acf2eee64667bbf72` |
| Generated member/verdict JSON | `2cf7a4c82af57d49f44025ea2c5d9102a7faa8caf9bd778b12ca078acec8ca38` |
| Independent Python receipt | `2cfb3b84d3bd3d28fbb916d4ce57ae49dd1a37c26694a5519145a0eef7a17758` |
| Compiled-source/fixture guard | `e59765c4b1490b3e8dd7286c91af0130cbc7d74e8e16e53172e9f399c3ca9bd8` |

The native receipt records exact argv/cwd, rustc `1.89.0 (29483883e 2025-08-04)`, successful compile followed by exit 1, empty consumed-input drift, restored starting lock and absent owned process group. The generated output misses `060-payloads/16b629b8298aca9e010970761f492a0bcd7a478d2d3284e0b4e3f0d40880e14f.bin`, `061-attachments.cbor`, and `065-certificates-of-completion.cbor` while the source fixture passed. The Python checker independently completes with process exit 0 but reports `relying_party_result: invalid`, cryptographic integrity fail, and missing attachment manifest/presentation attachment/certificate catalog. Its policy-closure finding remains advisory, not the causal blocking result.

This separates early prerequisite/cold timeout from actual writer behavior. Retained three attempts, lock snapshots and drift guard support the scoped diagnostic/evidence commit. This reviewer inspected receipts/readback and source, and did not rerun processes or certify live process/lock state independently of the retained receipt.

The final proposal resolves hash-domain clarification: payload content hashing uses existing ciphertext domain; catalog hashing uses bare SHA-256; presentation hashing stays separate. It explicitly requires composed validation of attachment completeness. Canonical catalog validation now uses maintained `encode_canonical_cbor_value` equality and duplicate-key refusal (`integrity-cbor/src/lib.rs:156–220`), rejects noncanonical input instead of rewriting accepted bytes, and calls out nested-map/duplicate tests. Open-clock count derives from the native array using existing format-only `serde_json` parsing; Core §28's `open_clock_count` and §18.3 pair/digest obligations remain authoritative. This adds no clock semantics or serializer. AFTER implementation must verify native open-clock emission, stale count replacement and signed-count tampering alongside 010/006/007 and empty-input001 parity.

No architecture blocker remains for the exact closed input proposal. Generic implementation, its simplification evidence, all-family verification, live D1 history/custody/creator/disclosure, trusted agency key, service runtime and full39 Done fulfillment remain unaccepted. Core owns the native window; this approval does not activate it. A changed proposal/source/evidence requires requalification.
