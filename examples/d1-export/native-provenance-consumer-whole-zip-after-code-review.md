# Native provenance consumer — successor whole-ZIP execution review

Review ID: TRELLIS-NATIVE-PROVENANCE-WHOLE-ZIP-AFTER-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Bounded incremental AFTER review under the full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, retaining the preceding full consumer source review and applicable Rust/repository guidance. Only this certificate was written. No Cargo, tests, native binaries, live calls, adoption, source or lock mutations were performed by reviewer.

## Findings

No blocking finding in the requested successor consumer/result scope. **APPROVE controlled whole-ZIP verification and tamper-refusal evidence.** The whole-ZIP gate explicitly left open in the preceding consumer AFTER certificate is now satisfied for the actual controlled runtime window, under its embedded signing registry.

F1 — RESOLVED / test-coverage / Core `crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:162–169,195–225`. The actual router-produced ZIP now enters `trellis_verify_wos::verify_export_zip`, asserting structure, integrity and relying-party validity. One generic recordKind is then changed to unknownFutureKind inside the signed event while preserving its original signature and all other members; the same verifier refuses the archive and integrity_verified is false. Original ZIP hash remains unchanged. This closes the prior missing combined path; it does not claim every possible mutation or independently trusted agency key.

F2 — OBSERVATION / test-coverage. Commands do not include trellis-server tests or the earlier14 auth boundary tests. Six auth server source files match the previously reviewed source, and runtime's controlled router test compiles/uses that server, but this does not establish an auth14 rerun against the successor graph. Previous auth evidence remains separate; actual host current-authority/grant composition, deployment and D1 remain unqualified here.

F3 — OBSERVATION / provenance / `execution/lock-reconciliation.json`. Final Trellis lock differs from private commit's lock only by existing stack-common-typeid→rand_core0.6.4 dependency edge; there are no added/removed package identities. This edge is part of this actual qualification closure, not a new consumer implementation change. Do not describe final locked evidence as using the earlier unchanged lock or copy unrelated lock bytes into an adoption scope without review.

## Scope, summary and source identity

Snapshot `/private/tmp/core-form-pin-zip-inputs-v2-20261009` records Core base `2f712020b9255168395e814c5209f493c585af16` and Trellis private commit `eda346c166a71c7b8df55afd8549247456229277`. All15 nonmanifest consumer files match the earlier qualified consumer packet. All six auth server files (lib.rs, auth.rs, auth_boundary_tests.rs, append.rs, state.rs, http.rs) are byte-equal to the reviewed private parent/integration. Consumer production code is unchanged; this successor adds Core form-definition pin behavior and the Core-owned whole-ZIP test. This bounded consumer certificate does not duplicate acceptance of Core's form-pin implementation.

The final source guard contains7869 files, all matching current snapshot bytes. Initial-to-final changes exactly match source-transition.json; that transition includes planned Core source/schema/test changes, both locks, and the controlled signature-runtime fixture correction. The final guard is not falsely described as equal to the RED guard. Prepared-green execution-only changes are Core lock and fixture; Trellis's lock reconciliation is separately visible. No unreported consumer source change was found.

## Function and caller trace

Paths below resolve inside the successor snapshot.

| Function / seam | File:line | Input → output and verified behavior |
|---|---|---|
| native_provenance_full_window_preserves_every_original_record_and_replays | work-spec/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:107 | Actual runtime records → custody appender → localhost maintained router/client → head ZIP. Existing complete-record/order/stamp/replay assertions remain. |
| full-ZIP positive check | same:162–169 | Exact head ZIP bytes → owning verifier; requires structure_verified, integrity_verified and relying_party_valid. No hand-assembled replacement positive archive. |
| full-ZIP mutation | same:198–225 | Clones exported events; changes first generic payload's recordKind; rebuilds only events member, preserving COSE signature and other members; same verifier must refuse and original ZIP hash stays equal. |
| verify_export_zip | trellis/crates/trellis-verify-wos/src/lib.rs:47–48 | ZIP bytes → integrity_verify::trellis::verify_export_zip_with_validator(zip, &WosRecordValidator), converted into WOS report. Thus actual structural/crypto and owning domain pipeline are used. |
| WosRecordValidator.validate_events | trellis/crates/trellis-verify-wos/src/validator.rs:22 | Retains canonical clock/rescission checks and generic strict native validation. Unchanged qualified source. |
| validate_native_provenance | trellis/crates/trellis-verify-wos/src/native_provenance.rs:10 | Generic payload bytes → owning wrapped strict decoder; absent/invalid native data → event-scoped blocking failure. Other event types bypass added native check. Unchanged source. |
| original records and receipt/replay assertions | work-spec/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:174–193,226 onward | Full original JSON remains ordered and identical; receipt stamp only, original retry references, changed-body409 and unchanged head remain required. |

## Data flow and invariants

The positive ZIP is produced by the actual maintained appender/router. `head_before` stays immutable. `tampered_events` is a clone; the test replaces only canonical payload bytes in one existing generic COSE item. It does not re-sign or recompute the rest of the signed history. Other archive entries are cloned unchanged. As intended, refusal may occur at cryptographic integrity before domain semantics; this test proves complete verifier refusal for tampered exported bytes, not isolated schema rejection under a valid replacement signature. Separate native validator tests already cover semantic refusal classes. Embedded registry trust is the test's stated boundary (`:164–165`).

## Tests inspected versus executed

Executed by reviewer: **none**. Inspected new whole-ZIP assertions and retained logs/binaries; reused unchanged consumer source/test assertions from the full AFTER review after verifying exact bytes.

The successful locked core-green-2 log reports53 authoring +183 core +32 events +289 runtime tests. The whole-window test is explicitly PASS in that log. The final locked trellis-consumer-green-3 reports11 admission +7 client +63 verifier tests. Sum638 includes each successful suite once. Earlier consumer-green-2 also passes but is unlocked and is not counted twice. The failed locked first consumer attempt reports lock update needed, not behavioral success. All receipts remain retained.

The four intended form-pin RED failures and nine initial GREEN signature-fixture failures are visible in their logs; Core subsequently corrects the controlled form definitionVersion fixture and repeats successfully. This review checks result identity and consumer seam, not the full Core form-pin implementation. No HTTP-schema/OpenAPI rerun or full Trellis suite claim follows from638PASS. All recorded process groups are clear according to retained receipts; reviewer did not make a fresh process-liveness observation.

All seven retained binary hashes match the qualification receipt. Every final guarded file matches. The seven logs exist and their summaries agree with receipt statuses/counts. The qualification receipt itself supplies no log hash fields, so exact independently computed log hashes are recorded below rather than claimed as receipt-provided pins.

Core lock reconciliation adds no packages/removes none; it includes auth ports edges and wos-runtime→trellis-verify-wos. Trellis reconciliation adds no packages/removes none, only the existing typeid rand_core edge. Final consumer `--locked` PASS establishes the resolved closure used for that run. No adoption or wholesale lock replacement is authorized by this certificate.

## Exploration record

H1 prior whole-ZIP gap remains. REFUTED: actual head ZIP reaches owning verify_export_zip and all three positive assertions; mutated exported payload reaches same entry and refuses.

H2 result may cover changed consumer production bytes or imply auth tests reran. REFUTED/REFINED: all15 consumer source files and six auth files are equal, but actual commands omit auth14; prior auth evidence stays separate.

H3 test might reconstruct a synthetic positive bundle or re-sign the mutation. REFUTED: positive bytes come from client.head_bundle; mutation preserves original signature and other members. This tests integrity refusal; it does not isolate generic domain rejection under newly valid signatures.

H4 final source/lock scope is unstated. REFUTED: complete final guard matches and source-transition exactly enumerates RED→final differences; final Trellis lock's one sibling edge is explicit.

## Exact evidence pins

| Input | SHA-256 |
|---|---|
| execution/qualification-receipt.json | `e0b1613b0e020cecf4368cfa7a9002723ddd9e69f9567130bb0f5f040d61c66d` |
| frozen-final-source.json | `0297b3c02d64c752464d7dfc6f5884100bb136fedc077d96c21fbe87a2de741b` |
| frozen-red-source.json | `2c3c9ae9d4fb81e62e1ca946db532c47eb0ff5e034d1620bfa54d3b68e89feb9` |
| execution/source-transition.json | `d3a8bc6ed15aea0f66e387e7431d6e812beac3e91ebd1b7b0fa6015e9c0c11b0` |
| execution/lock-reconciliation.json | `fccfb8159ea5a98f273102e12735b5159c0ea41550e7ade1ebdcebdfabc5d6c7` |
| whole-window test source | `6494818071d50787f3a9819e572df2f3b6d792abf6b243f3dc0a3e675eb3d01e` |
| final Trellis Cargo.lock | `9efb326b6582efa6892e2ff0dd15d6be5cb246ed682d9a9b21586469c3f4299e` |
| final Core Cargo.lock | `0c68c20526fc7e3f645065571ce80f20238add5f32896224c40479bc28e90325` |
| `core-green-1.log` | `0667f6bb2035f21eb27312077a20c2588295799796b06d7aa860c2dfba8647b2` |
| `core-green-2.log` | `5a072da8c3010c45e1107ad2554d33a616845cf99b725443166f54bb7ada3c22` |
| `form-pin-red.log` | `5b9755ddee5aad899982272274d0b72c36871dfbdeb1eb1c273b5988a23f22fd` |
| `trellis-consumer-green-1.log` | `aec7fb4bda5f5e68ba449228df8e253029f0a7eb869a677fc48de93fbf251109` |
| `trellis-consumer-green-2.log` | `35fc92d873ef59b8c9472fc4f55a123624b8bb8a1c53d10b9b49c68619415e8a` |
| `trellis-consumer-green-3.log` | `4fe93b379ff4848123816a6eacbb52b55986e0852a126a751f34fb9facf6bc16` |
| `trellis-lock-reconcile.log` | `72ea4e2343316d82aa7f345ae7b2a2d1b4e46980ae3e7953fbff582a6c26a175` |

Retained binaries (all independently hash-matched):

| Binary | SHA-256 |
|---|---|
| `wos_authoring-9aa88e4b5a0fb3cf` | `7dc41cda3d5eb5230ea1deea0254b4e4cbd888d646b9b5deb2786d9d49e584d5` |
| `wos_core-12692bc4f2588f92` | `6d9b25ae932f611cda4a9bc19be8361325524592d9d03a9a73ec2a9c145a0629` |
| `wos_events-b7660ed0d0b49b65` | `5a72a3c2e4cd87b02261848908c3d1aa9b29376c6e243e90b0ec949304063be1` |
| `wos_runtime-20cffe9f9b79a650` | `224f2b00672cef1ca6c23a303054906fd4a3353c77556dfec8f78a035cb27577` |
| `trellis_admission_wos-437e7ea103a0d9fd` | `fc8cfdd03402020c6fff43042655e8fa857a7aeda5fe445f99008f00fe4d2169` |
| `trellis_service_client-2ab42845777e61fb` | `0f2b7a7a0c87197d4f662774ce867bd1a4e0d5466686026b0d693d93a4f263ba` |
| `trellis_verify_wos-39e9ee3164ab3ef7` | `b790d8511fdfc3c65c0482f07a2ec0a48dbb46c73cc7b2adf1787bb76415afde` |

## Conclusion

VERDICT: APPROVE — successor consumer result/source gate and controlled whole-ZIP verification/tamper refusal.

Justification:
- The previously missing actual native ZIP→owning verifier path is exercised successfully, and its altered generic payload is refused.
- Coverage of this incremental scope: ADEQUATE. Whole auth runtime suite, independent agency trust, full D1 and adoption remain outside coverage.
- Confidence: HIGH for static trace, source/evidence identity and retained results; execution was inspected rather than reproduced.
