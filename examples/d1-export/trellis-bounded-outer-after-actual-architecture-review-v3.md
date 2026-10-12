# Actual bounded first startup: AFTER architecture review

**VERDICT: APPROVE closure of the selected first-start qualification at the retained observation point.** Retained evidence supports empty selected database → maintained migrations1–4, zero event/publication rows, actual configured process and successful maintained readiness. It does not establish current liveness, positive OpenID Connect authorization, acknowledged archive publication or restart retention.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-09. Applied full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` to this bounded result successor. Only this certificate written. Read retained files and approved source; no live process inspection, DB/network/provider/native command, prepared-script import/invocation or secret output.

## 1. Artifact summary

Category: operations qualification/proof infrastructure. Actual retained directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1/bounded-start-82c98432-cdbe-4d25-a445-f145a543fd7b`. Root reports executing approved start-only mode. Retained result records operator73745, servicePID/PGID74338, status `started`, resident supervisor and32MiB service log limit. This review independently verifies receipt contents/digests and traces their production through approved source, without observing the live processes.

| Retained input | SHA256 |
| --- | --- |
| Exact `run-trellis-bounded-v2.py` | `11429bab85631f43c7ec86acdd6c39de579a9cda50ebb368bb4d1f15148c1958` |
| `startup-result.json` | `590f4746f1add0e300dc1de62974a5ede1f34c853f0e2b68efbdd5a87463372c` |
| `started.json` | `0a0272dcf5b8c69d2a3c1ac7cff65fc14257a2bcea51c2a4b78444d893d6c190` |
| `database-before.private.json` | `ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356` |
| `database-after.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `actual-process.private.json` | `1443990f80dc1da2fb8b9398405fc1f251f583217c3c09faaf7da2891b29c4f8` |
| `old-process-before.private.json` | `bcaec1fcebf2422c9185176778c2ae38afc9cd61e4224ac0a56c568dd4a3e388` |
| `process-auxiliary-diagnostics.json` | `b0f41fde5d31516cee2e7106409b174979528e79cc13b84f668aaf84a88771d2` |
| `readiness.json` | `2f4be33db05ad997c7629ebc0e9a93630bc9e83568307282e702d7c271d59115` |
| `launcher-preflight.json` | `61f89bf5b724dfb2d1a17ce6e9a2f8e1886a6c63840668b06f7ee7b795ad7d55` |
| `launcher-preflight.stdout` | `7c5bb339719fa291c437a9db7bbc33d91d870c797e928ff8feb7f47edb112334` |
| `launcher-preflight.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `service.private.log` at review,520bytes | `b6279a582f14fc9ddfbd32cdfced9539294671a3d15c7835a373c40474cb0d76` |

Service log can grow under the resident operator; this hash is only the reviewed snapshot. Selected private Trellis binary lineage remains qualified HEAD `e9f5af9e7eaa1de3fca38be7018220a604e3d0c6` and binary SHA `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7`, inherited from the approved source certificate and confirmed in retained preflight output. No binary was executed by this reviewer.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| `trellis-bounded-outer-before-architecture-review-v1.md` | Full unchanged seam/helper/invariant trace | §1–7 |
| `trellis-bounded-outer-after-architecture-review-v2.md`, SHA `507a1cae1689ace5d209b3db2df3df3452790d8ce08a10e640e11cae6e7ca083` | Exact successor and start-only recipe approval | §1,§3,§7 |
| Passing SDK recovery receipt SHA `c8ea70d60d88f569dd2e0b35c08d689864e8b37208e8a31906926a00a468d819` | Reused selected artifact prerequisite | Retained preflight `artifactQualificationSha256` |
| `GOAL.md` / development philosophy | Evidence must survive service lifetime | `GOAL.md:28`; `DEVELOPMENT-PHILOSOPHY.md:384–388` |

| Named seam / owner | Actual retained observation | Remaining boundary |
| --- | --- | --- |
| Root/Trellis startup | Pinned deployment, empty grants, local18198 process | Point-in-time receipt, not current process observation |
| Existing read-only DB helper | Empty before; maintained tables/migrations after | No application custody yet |
| Maintained Trellis readiness | HTTP200, DB list + configured artifact put/get | No immutable export/restart proof |
| Current identity/grants | Selected profile, deny-all intentional | Fresh case + explicit case/action grants required |
| Maintained Common provider / Trellis client | Reused startup implementation only | Actual positive current-token→client readback pending |

## 3. Invariants and commitments

**Database initialization — PRESERVED / OBSERVED in retained snapshots.** Before is exactly `{}`. After contains exactly `trellis_events:[]`, `trellis_bundle_publications:[]` and four migration rows whose versions sort to1,2,3,4. These match approved wrapper assertions at188–192. The helper uses read-only repeatable-read bounded snapshots; maintained server applies migrations. This supports startup migration closure, not application-case custody.

**Exact deployment and deny-all — PRESERVED in evidence.** Preflight exited0, no supervisor error/truncation, owned preflight group empty; retained stdout/stderr sizes and SHA values independently match its receipt. It names selected binary/profile/artifact/grants/qualification pins, grantRows0 and S3 RustFS. At review, selected profile SHA `ad47c7186758c9adfefb9974a863124de48ea3d5cb40259857da594267a8f6f3`, database SHA `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983`, artifact profile SHA `18068348904f79b7191951741e2eb4040dcce7678541ac87f318aced157b2885`, grants SHA `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` independently match retained preparation. Actual process evidence matches selected DB/bind/key/profile/bucket/credentials without exposing values. Wrapper184–187 gates success on binary, complete environment and input-pin checks.

**Old service preservation — RELIED-UPON checked assertions; bounded claim.** Retained old-before argv/env/binary/config evidence exists. Wrapper193 must compare final old listener, argv/environment, binary and referenced-file digests before emitting successful result. Four auxiliary captures identify old16414 three times and new74338 once, each with metadata unmerged. However final raw old argv/env/file snapshot is not saved separately; this reviewer can trace the asserted comparison, not independently replay the old-after equality from two raw retained snapshots. Result appropriately sets `oldMemoryRowsReadbackCompared:false`. No claim about old in-memory rows or present liveness follows.

**Readiness — OBSERVED receipt with retained write disclosed.** Receipt status200 and body hash `88e6e2d81b00405c964f4c2dc37d756cd5da9f91f505bda84ced13f03693ee4e` are retained; raw response is not retained for independent body replay. Maintained `trellis-server/src/state.rs:519–543` checks repository list and writes/reads static `trellis-health-probe` at selected `trellis/__healthz__/artifact-roundtrip`; wrapper172–176 records it. This is configured artifact-adapter health roundtrip evidence, while `artifactAdapterQualified:false` conservatively leaves actual export/restart qualification open. Zero application rows supports no application publication at this point.

**Limits and trust — PRESERVED.** Result reports `positiveOidcQualified:false`, resident supervisor/log limit and intentional zero grants. Receipt was emitted only after source's deadline/pin/migration/preservation checks; there is no independently retained elapsed-time measurement. Resident state and future owned cleanup are not certified by the startup result. Historical SDK and health success do not establish agency trust or whole D1 completion.

## 4. User-value analysis

The selected isolated persistent deployment now has retained first-start evidence instead of only an approved command. This removes startup/configuration uncertainty before fresh custody work while preserving explicit admission authority. The small operator reuses maintained implementations and adds no protocol or framework. The value is falsified if later authorized exact-case work cannot be admitted or acknowledged bytes fail pinned retrieval after restart; those observations remain outstanding. No speed or resource performance claim is inferred.

## 5. Counterfactual analysis

Kill criterion: a retained snapshot contradicts migration/empty-row claims, selected pins differ, old service comparison fails, or health200 is presented as archive proof. Removing result review leaves deployment claims resting only on dispatch success. Opposite decision grants broad cases or implements handwritten OAuth to obtain a positive response, increasing authority and duplication. Existing Common token provider and Trellis client already own the required next seam. A future critic would flag raw old-after and raw readiness-body absence; narrow the claim to checked source assertions/retained status, as done here, instead of manufacturing independent readback evidence.

## 6. Findings

**F1 — KEEP; OBSERVATION; conformance.** Close the selected first-start gate: before/after database snapshots, preflight receipts, selected actual process environment and readiness receipt agree with exact approved wrapper. Root's actual execution remains the evidence producer; reviewer independently checks retained consistency.

**F2 — KEEP; OBSERVATION; evidence limits.** Report old-service binary/config preservation as successful wrapper assertions supported by old-before evidence, not independently reconstructed two-snapshot comparison. Preserve explicit absence of old memory-row comparison and avoid current-liveness claims.

**F3 — DEFER; OBSERVATION; authority/user-value.** Next bounded positive test requires Root-selected genuinely fresh case and explicit principal/resource/action grants, including separate exporter Read/Administer if publishing head. Use maintained `stack_common_auth` client-credentials provider and `TrellisServiceClient::with_token_provider` for current token on each call; exact-case positive readback must be real. Do not infer authorization from health200, replace intentional deny-all with broad grants, reuse historical case456, add handwritten OAuth or introduce another framework.

**F4 — DEFER; OBSERVATION; durability/trust.** Actual fresh custody append/readback, same acknowledged immutable export after restart, conflict refusal and owning offline ZIP verification remain separate gates. Startup health is insufficient. No blocking RESHAPE or REVERSE applies to retained first-start closure.

## 7. Verdict

**APPROVE bounded actual first-start qualification at its recorded point.** Intent MATCHES; user-value SUPPORTED; commitments HONORED within retained evidence; conceptual debt PAYS DOWN operator uncertainty; sibling subsumption PARTIAL/reused; confidence HIGH for receipt consistency and static source trace, MEDIUM for runtime facts available only through operator assertions.

All six phases applied. H1 selected database has no application custody CONFIRMED in retained snapshots. H2 health200 proves positive authorization/archive REFUTED by maintained health path and result flags. H3 old-after can be independently replayed REFUTED by missing raw after snapshot; claim narrowed. H4 successful dispatch establishes current liveness REFUTED by point-in-time evidence boundary. No phase skipped. This reviewer performed no live/native action; any further execution remains Root-selected and separately bounded.
