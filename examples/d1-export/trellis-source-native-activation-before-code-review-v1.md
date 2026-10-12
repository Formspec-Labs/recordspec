# Source native receiving activation — static BEFORE code review

Review ID: TRELLIS-SOURCE-NATIVE-ACTIVATION-BEFORE-V1-2026-10-10. Independent nonauthor `/root/oidc_code_review`. Full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` applied. Only this certificate written. No script imported/invoked, process/network/DB/Docker/native action. File/AST/hash inspection only; credentials not printed/copied.

## Findings

**Original snapshot REQUEST CHANGES; final corrected snapshot APPROVE static readiness (see final disposition below).** Exact selection and no-data-restore approach are sound; rollback needs a log budget it can use after an activation overflow.

F1 — BLOCKER / correctness / activate-source-native-restart-v1.py:40,44–50,67–88,129–141. One total log counter spans activation and rollback. When activation exceeds its32MiB cap, total is exactly LIMIT and drain raises. Failure cleans activation then launches rollback; first rollback log byte again exceeds remaining0, aborts rollback and kills the restored original service. This defeats promised automatic restoration for a concrete bounded-log failure. Reserve a bounded rollback share and refuse activation before exhausting it, or give rollback a separately bounded allowance with honestly updated aggregate cap. Keep both outputs bounded; do not drop rollback logs silently.

F2 — WARNING / correctness / rollback:132–139. Activation has final monotonic time check122; rollback does not recheck operation_end before declaring restored. Add the same check after DB comparison/before rollback-result. The inherited one-shot alarm can be caught by launch's TimeoutError handler83; monotonic checks guard that branch but final success should not depend solely on alarm delivery timing.

F3 — OBSERVATION / cleanup:51–60,129,141. Owned-group cleanup refuses if absence cannot be established; that exception can bypass a later rollback-failure receipt. Initial activation-failure is retained, so no false success follows. Retain explicit manual-inspection/group-ownership diagnostics if cleanup fails, and preserve original failure rather than obscuring it. This is evidence quality, not authority to restore data or kill foreign groups.

F4 — OBSERVATION / tests. No isolated operator tests supplied/executed. AST passes. Meaningful tests should model activation overflow then successful rollback, expired rollback deadline, failed group absence and repeated stop during rollback. Existing source/native auth evidence does not exercise these operator branches.

## Patch summary and traces

Full operator and closed frozen selection config read. It prepares selected original argv/env from retained actual-process receipt, changes only TRELLIS_OIDC_CONFIG_FILE to V8, verifies current old service/supervisor, captures complete bounded DB rows, terminates selected supervisor, then launches same binary under new profile. Failure restores original environment after owned new cleanup; no data rollback, Docker changes or first-start empty-DB guard. Successful activation or restored original remains resident with logs bounded.

| Function / caller | File:line | Inputs → behavior/output |
|---|---|---|
| main/module guard |19,154 | flags+config/source pins → dry-run or explicit execute. Checks all15pins before helper loads; default returns before live actions. |
| process_state |41 | PID → pinned capture_process argv/env/auxiliary, exact equality; no normalization. |
| drain |44 | merged nonblocking pipe → bounded combined log; counter shared across attempts (F1). |
| cleanup |51 | owned Popen group → kill/reap/poll3s and close streams; absence required; no old/foreign group killed here. |
| launch |67 | env/label → same retained argv/new session,30s readiness within operation deadline, exact listener/argv/env saved. Proxies/redirects refused. |
| preserved |89 | baseline old18088 plus source pins → exact process/binary/config and all inputs unchanged. Includes auxiliary equality, a stronger potentially conservative check. |
| cancelled |94 | stop signal → ignore repeat then interrupt; cleanup/rollback protected from repeated stops. |
| activation |99–124 | current selected identities/full DB → TERM supervisor73745, old group74338 absent, new launch and DB exact equality → success subject to180s check. |
| rollback |125–144 | activation failure → clean new group,90s original-env launch, preserve DB → receipt/resident. Log/deadline findings above. |
| resident |145–152 | either successful env →32MiB drain; intentional later TERM stops owned group without rollback. |
| helpers | existing pinned Root sources | process reader bounded sysctl parsing; database snapshot read-only repeatable-read with admission caps; finite group_exists; timer deadline. Prior full helper reviews retained. |

## Data flow and invariants

BaselineProcessFile is pinned1443990f… from actual startup, config supplies selectedPID74338/supervisor73745. Actual argv/env must match before stop; supervisor must contain exact reviewed wrapper path and start mode. Selected_env is shallow copy of original with only profile path replaced. Current V8 grants remain Source resourceRead/Append service actor only; no case/Administer elevation. Pins cover old/new profiles/grants, key, binary, introspection secret, artifact/DB and helpers; all currently match.

DB snapshot before/after must be exact rows including migration ledger, so first-start migrations cannot be inferred as permissible new business mutations. Maintained readiness does write/read its known selected artifact health key; full ZIP/restart proof remains separate. Old18088 is read/preserved only, no old memory rows queried. Failure intentionally retains all DB/object state; rollback restores configuration with a newPID, not oldPID resurrected. Counter total is never reset, causing F1. operation_end changes180→90 for rollback; should gate final rollback success as F2.

## Tests and exploration

Reviewer executed none. AST parse and all15 current input digest comparisons pass. Static cases: incorrect config/pin dry refusal; current old process/env/supervisor mismatch refuses before TERM; new readiness/env/DB/preservation mismatch cleans new group then attempts original-env rollback; later intentional stop cleans resident without rollback. Activation log exhaustion currently makes rollback exhaust immediately; expired final rollback success lacks explicit guard. No current liveness/provider/DB fact observed.

H1 operator changes data/restores snapshots: REFUTED by read-only snapshots and no write/restore SQL. H2 original service ownership is guessed: REFINED, selected fixed PIDs plus exact live identity required by source, not observed by reviewer. H3 bounded activation logs leave rollback capacity: REFUTED(F1). H4 rollback deadline has equal final guard: REFUTED(F2). Next: bounded correction and exact successor freeze; no execution needed to repair.

## Exact pins

| Input | SHA-256 |
|---|---|
| `activate-source-native-restart-v1.py` | `da6e0cd660f1afcbf50beb7137433b6368919d551a6d1fca157f6ed0198537a5` |
| `activate-source-native-restart-config-v1.json` | `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec` |
| `run-trellis-bounded-v2.py` | `11429bab85631f43c7ec86acdd6c39de579a9cda50ebb368bb4d1f15148c1958` |
| `oidc-profile-source-native-v8.json` | `55589b8ee357064b9eb648411253d5cacb27b559e2e8017fe4593f8ccc3492bf` |
| `current-grants-source-native-v8.json` | `ec5b8c592da9bc620d41b7c3c85836c8c4fa071f8045585539e19be9ae531cd9` |
| `oidc-profile-exporter-v6.json` | `ad47c7186758c9adfefb9974a863124de48ea3d5cb40259857da594267a8f6f3` |
| `current-grants.json` | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |
| `database.private.json` | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |
| `artifact.private.json` | `18068348904f79b7191951741e2eb4040dcce7678541ac87f318aced157b2885` |
| `actual-process.private.json` | `1443990f80dc1da2fb8b9398405fc1f251f583217c3c09faaf7da2891b29c4f8` |
| `process_identity_v1.py` | `2143e3f6a0053da79fca6300037e7a095b5c9368c75af9eab1285596f817b9a0` |
| `publish_configured.py` | `fd4ed96ad03927c20e1acd962ab313c232da7bfc590f6418e5f5f7175e8cdaf0` |
| `adopt_reload_hotfix.py` | `796603c1c87122910b9c82cb44125e421238dd0f1bcd04d3db3ac3360d15e949` |
| `qualify_readback.py` | `c94f4d8f71bc4fd654626998789cc11ab5a8fc64a0e69739cd93324d601e4679` |
| `introspection-client.secret` | `a772be620d675530952ab98dccdf76bb06e047fb6fc6825e11561978f720a4d5` |
| `trellis-server-oidc-qualified-v4` | `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |
| `trellis-local-memory-signing-v1.cose_key` | `62644accd6ef7af276945418ee794ce6428ac63a0a79f78180addd372b053608` |

All15source/config/input pins independently match. Private config contains no secret values in this certificate; secret file digest only.

## Conclusion

VERDICT: REQUEST CHANGES.

The proposed owned restart/configuration restoration is appropriate, but current shared log exhaustion blocks restoration on its own overflow path. Coverage: ADEQUATE static traces; INSUFFICIENT isolated rollback/signal/operator tests. Confidence: HIGH for source/pins/findings. No operator execution or activation approval granted until corrected pins reviewed; runtime Source append/export and current liveness remain separate.

## First corrected snapshot review (not final)

Current source snapshotda6e0cd660f1afcbf50beb7137433b6368919d551a6d1fca157f6ed0198537a5 reviewed in full relevant changed paths. F1 resolved: current_log_bytes resets per launch, each service32MiB with total64MiB maximum for activation+rollback stated in receipts; total stays actual admitted bytes. F2 resolved: rollback final monotonic guard added. F3 improved: cleanup returns bool and structured private cleanup-error, refuses rollback if cleanup fails, includes group status on rollback/resident failures. Architecture-identified prospective input dependence resolved: preserved(candidate=False) excludes only new profile/grants for rollback while retaining original inputs and old18088 checks.

One remaining final rollback admission check requested: after DB snapshot/deadline and before rollback-result, require process.poll() is None and selected listener equals rollback PID. Unlike activation, this snapshot can report restored while child exited during DB snapshot; resident loop catches it only after success output. Final verdict remains pending that bounded guard and exact successor hash. No tests/live calls executed.

## Final corrected source disposition

Final independently verified operator SHA `b87a07b3ad36afccf8fdeb85d1e641d043de5836d7a40d20dff312edded1e042`; unchanged selection config SHA `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec`; all15current input pins rechecked and match. AST passes; no operator/helper import or execution. Original source findings remain above as history, not unresolved final blockers.

All identified findings are resolved or bounded observations: separate per-service32MiB log accounting leaves fresh rollback capacity, aggregate activation+rollback64MiB cap accurately stated; cleanup failures retain explicit ownedGroupEmpty/manual-inspection receipts and gate rollback; original configuration validation during rollback excludes only failed prospective profile/grants; final rollback requires deadline, process.poll None and exact18198 listener before success. Candidate profile/grant observed digests or read errors are saved separately at147–151 and do not prevent restoration merely because prospective files changed. Resident later termination continues to stop only its owned group without another rollback.

Final source trace at140–155: cleaned candidate group → original group absent → launch original_env with reset per-service budget → preserve original pins/18088 → full DB rows equal before → deadline and child/listener live-at-admission check → bounded candidate diagnostics and restoration result. Failed cleanup/rollback retains evidence and manual-inspection status; no data restoration or foreign-group kill introduced. Configuration restoration creates a newPID; it does not promise resurrection of oldPID. Guard/parser/runtime behavior remains unexecuted by reviewer, and current service identity/DB state are operation prerequisites.

FINAL VERDICT: APPROVE exact corrected b87a07b3… static activation preparation.

Coverage: ADEQUATE for full operator/source/config/caller/failure traces; INSUFFICIENT for actual restart/rollback/signal/log execution tests and live provider/Source append/export. Confidence: HIGH for inspected final source and all15pins. Root must separately authorize live window and inspect actual activation/rollback/cleanup receipts; approval is not execution or current-liveness proof. Only this certificate edited; original/private/active configuration unchanged by reviewer.
