# Native provenance consumer: whole-ZIP successor AFTER architecture review

**VERDICT: APPROVE the bounded successor result.** The previously deferred actual-runtime-ZIP verification and tamper-refusal gate is now exercised by the maintained full-window test. This closes that specific gate for the controlled fixture and embedded signing registry. Independent agency trust, genuine program-case evidence, current production authority and full D1 remain outside qualification. No source adoption or deployment is approved by this certificate.

Reviewer `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied. Retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs read-only Rust inspection. This incremental review inherits the source/lineage analysis of `native-provenance-consumer-after-architecture-review.md` (SHA-256 `21a132337bee99e58a3ac9d3438f9f4db4762fa7e7966a61d715e21cdb193fca`) and explicitly updates its remaining ZIP gate. No Cargo, executable, service or adoption operation was run by this reviewer; only this certificate was written.

## 1. Artifact summary

Snapshot `/private/tmp/core-form-pin-zip-inputs-v2-20261009`; retained `execution/qualification-receipt.json` SHA-256 `e0b1613b0e020cecf4368cfa7a9002723ddd9e69f9567130bb0f5f040d61c66d`; `frozen-final-source.json` SHA-256 `0297b3c02d64c752464d7dfc6f5884100bb136fedc077d96c21fbe87a2de741b`. Receipt identifies Core base `2f712020b9255168395e814c5209f493c585af16` and Trellis `eda346c166a71c7b8df55afd8549247456229277`.

Category: proof infrastructure. Decision under review: feed the actual router-produced full native custody ZIP to maintained `trellis_verify_wos::verify_export_zip`, require complete positive verdicts, and require refusal after changing a generic payload while retaining its signature and other archive members. Beneficiary: the independent reviewer who must check exported native custody after the live service disappears. Scope is this result and unchanged Trellis consumers, not approval of Core's separate form-pin design.

All 7,869 final guarded file hashes match the snapshot. All 15 previously qualified nonmanifest consumer source/spec files match their packet hashes. Seven auth-related Rust files (six server files plus server-ports) independently match the exact private Trellis `eda346c` commit. This demonstrates source continuity, not repeated authentication qualification.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Root goal and philosophy | Buyer proof must survive the live server | `GOAL.md:Product Claim`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Approved routing proposal | Preserves native facts through shared owner and closed generic route | `native-provenance-routing-proposal-v2.md`, SHA `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| Prior consumer AFTER | Defers exact runtime ZIP verification/tamper | `native-provenance-consumer-after-architecture-review.md:§6/F3` |
| Normative byte/domain seams | Signed bytes separate from domain findings and external authority | snapshot `trellis/specs/trellis-core.md:§9,§18–19`; `specs/wos-trellis-verification.md:§1,§7` |
| Successor executed test | Closes actual ZIP gate within controlled context | snapshot `work-spec/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:160–227` |

| Named seam | Owner | Input → output | Dependency boundary |
| --- | --- | --- | --- |
| Custody appender / actual router | Core runtime + Trellis | Native persisted records → signed ZIP | Existing client/server/writer |
| `verify_export_zip` | Trellis WOS verifier / Integrity proof | Exact generated ZIP → structure/integrity/domain verdict | Maintained verifier, no live readback |
| Shared native helper | Core wos-events | Generic payload bytes → validated full original JSON | Same owner as admission |
| Agency trust and production auth | Deployment owners | Independent trust/grants → authorized reliance | Outside controlled registry fixture |

## 3. Invariants and commitments

- **Actual exported evidence — PRESERVED.** Test lines160–169 passes `head_before`, obtained from the real local router/client, directly into owning `verify_export_zip`; it asserts `structure_verified`, `integrity_verified` and `relying_party_valid()`. It does not substitute a separately authored fixture ZIP. Core final log records the exact test name passing at line601.
- **Original facts/order/receipts — PRESERVED in the tested window.** Test lines170–194 continues to decode the actual events, compare complete original JSON and IDs in order and check sequence. Lines228–244 retain receipt-only enrichment, replay equality, 409 conflict, stamped retry and unchanged head assertions. Generic custody does not gain specialized signing/notice/filing authority.
- **Tamper refusal — PRESERVED.** Lines195–225 clone the events, change one generic `recordKind` to `unknownFutureKind` inside existing signed bytes, retain original signature and all other archive members, and verify the rebuilt archive. Both relying-party validity and integrity must fail. This is a strong archive-integrity negative; because hashes/signature also fail, it does not alone isolate the native-kind validator. The separate 63-test verifier suite supplies domain-specific coverage.
- **Original ZIP unchanged — PRESERVED.** Lines162 and227 hash the original ZIP before and after mutation and assert equality. The mutation test works on a separate archive.
- **Explicit trust limits — RELIED-UPON.** Lines164–165 and receipt `trustLimit` identify embedded signing-registry verification only. This is not independent agency-root trust or authority to rely legally on a case.
- **Source continuity and execution boundaries — PRESERVED.** Exact guard/source comparisons above bind unchanged consumer and auth code. Commands in receipt cover Core authoring/core/events/runtime and Trellis admission/client/verifier libraries. They do not run `trellis-server` tests or the 14 auth tests. Production-source presence in a dependency graph cannot replace those tests.

## 4. User value and simplicity

This successor removes the evidentiary gap between “runtime exports a complete history” and “the owning offline verifier accepts that exported history.” One maintained runtime test now checks the same returned ZIP with the maintained verifier, then proves altered evidence is refused. It reuses the existing writer, archive model, generic validator and local workflow; no new serializer or parallel proof path is introduced.

No speed/resource improvement is claimed. The smaller separate-suite approach could establish component correctness but left the actual artifact crossing untested. The new assertions are the smallest adequate addition. Value would be refuted if a fresh runtime ZIP fails owning verification or altered bytes remain relying-party valid.

## 5. Counterfactual analysis

Kill criterion: test verifies a replacement artifact, signs the mutation again, drops other members, skips integrity checks or silently uses live state. Source inspection refutes these cases. Removing these assertions reinstates the prior F3 gap. Existing verifier subsumes all new verification logic; adding a bespoke validator would duplicate authority. Six-month critic: “638 PASS” may be mistaken for independent agency trust or an auth rerun. Preserve explicit counts and exclusions below.

## 6. Findings

**F1 — KEEP; OBSERVATION; named-seam/user-value.** Actual head ZIP goes through owning complete verifier and retained-signature tampering is refused. Close prior consumer AFTER F3 only for this controlled runtime fixture. Evidence: test lines160–227 and passing exact test name in final Core log.

**F2 — KEEP; OBSERVATION; ownership.** Unchanged consumer source, shared native helper and maintained verifier preserve the approved ownership. No RESHAPE or REVERSE correction is required for this bounded successor.

**F3 — DEFER; OBSERVATION; scope/trust.** Agency trust, accepted real program evidence, actual host current-authority/grant configuration and full D1 remain separate gates. Previous 14-test auth qualification remains separate; do not claim this successor reran it or established combined authentication behavior.

**F4 — DEFER; OBSERVATION; integration.** Private Trellis lock reconciliation adds an existing `rand_core 0.6.4` edge to `stack-common-typeid`; it is not part of the earlier qualified consumer adoption lock. Preserve that distinction and separately authorize any eventual lock/source adoption. No packages are added/removed by the successor reconciliation. Evidence: `execution/lock-reconciliation.json:Trellis` and source-transition receipt.

## 7. Verdict and exact evidence boundary

**APPROVE this incremental result.** Intent MATCHES actual-artifact verification; user value SUPPORTED; commitments HONORED within controlled trust/source scope; conceptual debt PAYS DOWN an untested seam with shared machinery; sibling subsumption PARTIAL; confidence HIGH for source and retained execution evidence. This review did not rerun execution or independently inspect a persistently retained ZIP: exact ZIP acceptance is evidenced by the pinned executed test, whose `head_before` bytes are generated in memory. No standalone archive digest/readback claim is made.

All six reasoning phases applied. H1 actual generated ZIP reaches full owning verifier CONFIRMED by test and log. H2 mutation is re-signed REFUTED by source. H3 tamper refusal isolates native schema REFUTED: integrity also fails; domain suite remains relevant. H4 auth suite was rerun REFUTED by receipt argv. H5 consumer code drifted REFUTED by exact source comparison. No phase is skipped.

Final locked Core success comprises 53 core +183 authoring +32 events +289 runtime; final locked Trellis success comprises11 admission +7 client +63 verifier, totaling638. Failed form-pin RED, first Core GREEN fixture-pin failures and first Trellis locked-metadata failure are retained. An unlocked successful consumer run reconciled metadata before the final locked rerun; this is not a first-run-pass claim. Receipt records cleared process groups and private reused target. Separate Core form-pin semantic acceptance belongs to its owning reviewers.

Exact inspected runtime test SHA-256 `6494818071d50787f3a9819e572df2f3b6d792abf6b243f3dc0a3e675eb3d01e`. Independently computed final Core log SHA-256 `5a072da8c3010c45e1107ad2554d33a616845cf99b725443166f54bb7ada3c22`; final locked Trellis log `4fe93b379ff4848123816a6eacbb52b55986e0852a126a751f34fb9facf6bc16`. Source-transition receipt SHA-256 `d3a8bc6ed15aea0f66e387e7431d6e812beac3e91ebd1b7b0fa6015e9c0c11b0` distinguishes planned Core changes from execution-only signature fixture/lock repair. Prior consumer16-file pins remain in the inherited certificate and packet `8982b06ef40dbdd2d5e33ce5f1840566224f2d8ea139d326a6f5224bd7066079`; this successor verifies15 nonmanifest matches explicitly.
