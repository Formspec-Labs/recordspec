# Source-native profile activation: BEFORE architecture review

**VERDICT: APPROVE corrected exact static activation operator.** Same-binary/profile-only restart preserves full retained database state and confines cleanup to owned processes. Corrected rollback verifies original configuration independently of failed prospective profile/grants and retains structured cleanup/manual-inspection evidence. No actual restart or positive Source custody is qualified here.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-10. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied. Only this certificate written. Static source/AST/digest inspection only; no prepared-script import/invocation, live process, HTTP/provider/database/native action or secret-value output.

## 1. Artifact summary

Private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`.

- `activate-source-native-restart-v1.py` SHA256 `b87a07b3ad36afccf8fdeb85d1e641d043de5836d7a40d20dff312edded1e042` (final corrected source; initial reviewed draft SHA `6805f2faccfcb7444749432009f6efe5d76a4f311d7c135848ae8f15048f2034` retained here as review history).
- `activate-source-native-restart-config-v1.json` SHA256 `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec`.
- All15 selected config pin values independently match their files at review; Python AST parses.

Category: operations scaffolding. Root explicitly selected restart activation of inactive Source-native v8 receiving configuration. The old service74338/group74338 and owned supervisor73745 are selected; old18088 service16414 must remain unchanged. The retained baseline process environment changes only `TRELLIS_OIDC_CONFIG_FILE`; original DB/key/S3/binary environment is reused. New native grants/profile remain those approved in `trellis-source-native-config-before-architecture-review-v1.md`, SHA `984011fc92511d201755350cdafb4f2f0eaedfe45ebd6cab2563d14b21fb7a7e`.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Inactive Source-native config certificate | Constrains identity, native scope and service actor | §1–7 |
| Actual bounded first-start certificate | Establishes retained baseline process/config; no current liveness | `trellis-bounded-outer-after-actual-architecture-review-v3.md:§1,§3` |
| Approved bounded v2 wrapper | Helpers and original ownership lifecycle reused | `run-trellis-bounded-v2.py`; parent review §2–3 |
| Product goal/philosophy | Preserve evidence through service lifetime | `GOAL.md:28`; `DEVELOPMENT-PHILOSOPHY.md:384–388` |

| Seam / owner | Input → output | Limit |
| --- | --- | --- |
| Operator selected restart / Root | Exact baseline service/supervisor → stopped owned group | Live identity must be checked at execution |
| Maintained auth / Trellis | Same binary + new selected profile → current grant authority | Positive Source custody still pending |
| Existing DB helper / Root | Read-only full bounded snapshots → equality check | No data restore; concurrent writes invalidate equality |
| Health / maintained Trellis | DB list + retained artifact write/read → readiness | Not immutable export/restart archive proof |
| Rollback / operator | Original environment → resident replacement | Must be independent of failed candidate integrity |

No platform auth language, OAuth flow, repository format or framework changes are proposed. Helpers/binary/key/secret/config selection remains pinned. Existing first-start wrapper is imported only for reusable helpers; its empty-database main path is not invoked.

## 3. Invariants and commitments

**Deployment identity — PRESERVED in static shape.** Config baseline is pinned. Execution checks selected listener/group74338, actual baseline argv/env, and supervisor73745 argv containing reviewed bounded-v2/start (`operator:101–105`). It records original process/supervisor. New env differs only by profile selection (`:36–39`); launch compares actual argv/full real environment exactly (`:67–88`). This is not a live ownership observation by the reviewer.

**Existing custody — PRESERVED by comparison, never restored.** Full bounded database before snapshot is saved and exact maintained table inventory required (`:111–112`); after must equal before (`:120`). No mutation/restoration/deletion call exists in operator. A changed database causes failure/manual inspection rather than hiding changes. Root must keep concurrent application writers quiescent during this bounded equality gate.

**Old service scope — PRESERVED in design.** Old18088 argv/environment/auxiliary snapshot and binary/config hashes are checked by preserved(), with raw before/after snapshots now saved (`:89–93,106–110,121`). Only selected73745 receives TERM and newly launched groups receive cleanup. Ten-second old service-group wait refuses overlapping launch (`:115–118`). Supervisor identity guard is narrower than generic process-name matching but does not independently prove current parent-child relationship; baseline execution receipts and exact selected identities remain Root's responsibility.

**Bounds/evidence — PRESERVED at stated levels.** Activation180s, readiness30s with64KiB response and no redirects/proxies, restoration90s, cleanup3s and per-service32MiB/maxcombined64MiB stream cap are explicit. Readiness timeout catch checks monotonic deadline (`:74–84`), and activation checks it again before success (`:122`). Resident lifetime remains intentionally unbounded. These limits are not a universal memory or OS scheduling guarantee. Health writes stay in selected backend; raw readiness bodies are now saved. Later TERM cleans new group without invoking rollback (`:145–152`).

**Original availability on failed activation — PRESERVED in corrected source.** `preserved(candidate=False)` excludes only prospective profile/grants while retaining original binary/key/DB/backend/profile/grants/helpers and old18088 checks. Rollback uses this original-only predicate; candidate observations are saved separately, including read/hash errors. Original environment/readiness/exact process and full database equality remain required. Final rollback also checks monotonic deadline, service still running and exact listener before recording restored success. A candidate drift no longer kills a healthy original replacement merely because that rejected input remains drifted.

**Failure evidence — PRESERVED in corrected source.** `cleanup()` now returns success/failure and saves uniquely numbered structured cleanup-error receipts on kill errors or surviving owned group. Activation stops if cleanup fails; rollback/resident failure receipts explicitly include ownedGroupEmpty and manual inspection. Original group still present forbids rollback launch; no clean release is inferred. Disk failure can still prevent receipt writing; this ordinary operational limitation is not hidden.

**Log restoration capacity — PRESERVED with clarified bound.** The corrected source resets the32MiB stream allowance for each new service attempt, while total records the activation plus rollback accepted bytes, at most64MiB. This avoids exhausting rollback capacity when candidate startup fails at its log cap. Resident restored service continues its own32MiB cap. No third launch exists; limit names in receipts correctly distinguish per-service and combined allowances.

## 4. User-value analysis

Root can activate the selected genuine Source identity without changing binary or existing custody. Reusing maintained helpers removes duplicate process/database/network implementations. The smaller profile-only environment delta is appropriate. The debt is a bounded operational restart state machine; its fallback must keep old availability when prospective config fails. No speed or resource improvement is measured apart from enforced stream cap.

Falsifier: failed prospective validation leaves no healthy original-profile replacement despite original inputs remaining intact. The initial draft violated that condition on candidate-file drift; the corrected original-only rollback predicate resolves it. Avoid broad storage rollback or a new supervisor framework.

## 5. Counterfactual analysis

Kill criterion: mismatched selected process, altered baseline storage/key, changed DB rows, failed new readiness, or candidate failure killing an otherwise valid rollback. Opposite decision launches candidate alongside current service or restores database data, increasing risk. Removing this operator leaves the selected first-start script unsuitable for nonempty state and no bounded activation path. Existing maintained helpers subsume underlying mechanics. Future critic will ask whether “rollback” means restoring only service configuration or undoing custody; source correctly chooses configuration-only restoration, but must retain failed cleanup evidence and not condition that restoration on candidate files.

## 6. Findings

**F1 — RESHAPE completed; OBSERVATION; intent-vs-shape/availability.** Initial draft required prospective pins for rollback. Final source distinguishes original-required integrity from prospective checks, preserves strict candidate checks for activation, and records candidate drift separately. Keep this separation; restoring original authority must not depend on rejected candidate files.

**F2 — RESHAPE completed; OBSERVATION; evidence/ownership.** Initial cleanup exceptions could suppress structured manual-inspection evidence. Final cleanup returns status, saves numbered failure/group receipts and prevents further launch when cleanup fails. Rollback/resident failure record ownedGroupEmpty. Per-service32MiB/maxcombined64MiB limits also preserve bounded rollback capacity.

**F3 — KEEP; OBSERVATION; scope/simplicity.** Profile-only restart, exact environment, preserved full database snapshots, no data restore and owned groups are the smallest correct activation scope. Retain actual raw old-after/readiness evidence and operation deadlines.

**F4 — DEFER; OBSERVATION; user-value/evidence.** Actual selected activation/rollback receipts and positive current-token Source native append/readback/archive qualification remain pending. Service health does not prove authorization, legal human signing or immutable archive retention. No REVERSE recommendation applies to the overall narrow shape.

## 7. Verdict

**APPROVE corrected exact static operator.** Intent MATCHES; user value SUPPORTED; commitments HONORED in inspected source; conceptual debt PAYS DOWN rollback ambiguity and reuses maintained pieces; sibling subsumption PARTIAL; confidence HIGH for static paths, runtime unobserved.

All six phases applied. H1 profile restart changes storage REFUTED by same original environment. H2 rollback survives prospective pin failure was REFUTED in initial draft and CONFIRMED in final original-only preservation predicate. H3 cleanup failure is retained was REFUTED in initial draft and CONFIRMED by final structured cleanup status paths. H4 restart proves Source custody REFUTED by explicit pending append gate. No phase skipped. This certificate binds final corrected source digest above; any further change requires another digest-bound review. Earlier line references describe the initial traced structure and retained paths; final corrections are identified by exact function/branch names above.
