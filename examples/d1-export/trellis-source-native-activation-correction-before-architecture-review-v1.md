# Source-native activation stop correction: focused BEFORE architecture review

**VERDICT: APPROVE exact static v2 operator and command.** The correction addresses the observed failure to stop the original bounded operator, without changing auth profiles, grants, database, signing key, binary or provider configuration. Graceful stop remains first; force stop requires revalidated exact owned identities and parent relationship. Both old groups must be absent before any replacement or rollback launch. Actual corrected activation is not yet qualified.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-10. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied proportionally to this bounded delta. Only this certificate written. No prepared-script invocation/import, live process, network/provider/database/native/build operation, append or secret output. Python used only for read-only digest/JSON/AST inspection.

## 1. Artifact summary

Private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`.

| Exact input | SHA256 |
| --- | --- |
| `activate-source-native-restart-v2.py` | `45d849a3c90810e2b7bf342aff019914598ec0491b9b3455616030c5e7c9d0be` |
| `activate-source-native-restart-v2.command.txt` | `1e1c6d254bfe6df07a76c9ffa96e85f6ab43050fc2c54232c76c379c1e78590d` |
| Existing `activate-source-native-restart-config-v1.json` | `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec` |
| Failed attempt `activation-failure.json` | `f5f7dabcafbc2ab1b545a91ab1424bd57a9f94ee2a300ea76e60a8ace4f30320` |
| Failed attempt `rollback-failure.json` | `d57020b2af9f8614b1a79c11a9c804ebe767e862fe40dd0dce0425446c462aeb` |
| Failed attempt `diagnostic-result.json` | `21184fe53af0ef87afa695fb528f7e436df8483d6d06e61d898fccbe7e924945` |
| Failed attempt DB before and diagnostic after, identical bytes | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |

All listed hashes independently verified; config's15 file pins still match. V2 AST parses. Failed attempt directory is `source-native-activation-e9a11ca0-70dc-4fce-98ea-b6b58ac2f111`. Category: operations correction. The command pins v2 source before detached dispatch, retains private0600 bootstrap log and reports dispatch only, not success. It invokes no alternate build, token implementation or application operation.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Approved corrected v1 operator SHA `b87a07b3ad36afccf8fdeb85d1e641d043de5836d7a40d20dff312edded1e042` | Baseline; original-only rollback/data/log/pin boundaries retained | `trellis-source-native-activation-before-architecture-review-v1.md:§1–7` |
| Actual failed attempt | Failure at old-supervisor stop; replacement refused | `activation-failure.json:phase`; `diagnostic-result.json:replacementLaunched,sourceProfileActivated` |
| Python3.12.9 KqueueSelector | Explains cancellation propagation defect | `/Users/mikewolfd/.pyenv/versions/3.12.9/lib/python3.12/selectors.py:558–568` |
| Existing Source-native configuration | Unchanged exact identity/native scope grants | `trellis-source-native-config-before-architecture-review-v1.md:§3` |
| Product goal | Preserve durable evidence through service lifecycle | `GOAL.md:28`; `DEVELOPMENT-PHILOSOPHY.md:384–388` |

| Seam / owner | Correction | Unchanged boundary |
| --- | --- | --- |
| Python signal → selector → operator cleanup | `OperatorStopped(BaseException)` avoids selector's InterruptedError catch | Outer owned cleanup catches BaseException |
| Root-selected old process lifecycle | Exact revalidation before force stop | Only74338 service group and exact73745 supervisor |
| New service/rollback launch | Both old groups absent | Same binary/env apart from selected OIDC profile |
| Maintained database/auth/provider | None | Full DB equality, original-only rollback, fixed profiles/grants |

Upward lineage and outward ownership retain the fully traced parent certificate. No new platform seam is introduced.

## 3. Invariants and commitments

**Cancellation propagation — RESHAPED correctly.** Original wrapper stop handler raised InterruptedError after ignoring later stop signals. Installed Python KqueueSelector catches exactly InterruptedError and returns empty ready list (`selectors.py:566–568`); this can leave the resident loop alive with later stops ignored. V2 defines `OperatorStopped` directly under BaseException (`operator:9–10`) and raises it in the handler (`:104–108`). It bypasses the selector's catch and reaches existing outer BaseException cleanup. Reviewer inspected source; isolated reproduction is Root-reported and was not executed here.

**Selected force-stop authority — PRESERVED with explicit escalation.** After original TERM and10-second wait, v2 only escalates if selected service group remains. Before killing group74338 it rechecks exact listener, service PGID/complete process state, supervisor PGID/complete process state, actual parentPID via bounded ps, old18088 and all retained pins (`operator:129–143`). Only then does it save verified-force-stop receipt and signal the selected service group. Three-second group-empty wait refuses further work if it survives. There is no process-name sweep or arbitrary process kill.

**Old supervisor ownership — PRESERVED.** If supervisor group73745 remains after service stop, exact supervisor process state/PGID must still match before killing that supervisorPID (`:144–148`). It does not kill the supervisor group indiscriminately; any surviving group members cause refusal. Both service and supervisor groups, plus18198 listener, must be absent before new activation (`:149`). Rollback repeats both-group absence gate (`:165`). PID/process changes reject rather than expanding authority. Snapshot checks and signals are separate OS operations, so ordinary small race windows remain; exact selected identities and immediate revalidation reduce scope, they are not an atomic process-identity guarantee.

**Custody and original availability — PRESERVED.** V2 diff adds only cancellation class/raise, exact force-stop path and stricter absence gates. No database/profile/grant/backend/key/binary change occurs. Original-only rollback integrity, candidate diagnostics, actual rollback listener/process/deadline, no data restore and structured cleanup failures remain. Activation180s/readiness30s/rollback90s,32MiB per-service/max64MiB two attempts are unchanged. Health still writes the disclosed selected artifact-probe key; no application append is added.

**Failure claims — NARROWED to actual retained evidence.** Failed attempt receipt records failure in `stop old owned supervisor`; diagnostic says original service74338/supervisor73745 remained, no replacement/profile activation/application append/readiness by failed attempt,15pins and old18088 preserved. Reviewer independently matches retained before/diagnostic-after database bytes and current15pins. Service liveness/parent/environment in diagnostic are producer observations, not reviewer-live verification. Rollback-failure `ownedGroupEmpty:true` describes no new owned replacement group; it does not establish that original service/supervisor groups exited. Those original groups remained according to diagnostic. Preserve that distinction.

## 4. User-value analysis

Root can retry the selected activation with a concrete explanation for prior safe refusal and an exact bounded fallback for stopping the already selected operator. The change stays within private operational lifecycle, reuses maintained auth/storage/helper paths and preserves custody. It does not add service framework, custom OAuth or native application semantics. Value is falsified if mismatched process identity is killed, a replacement launches over a surviving old group, or later resident cancellation is again swallowed. No performance claim applies.

## 5. Counterfactual analysis

Kill criterion: drifted service/supervisor/parent/listener/pins at escalation, surviving original groups at launch, changed custody rows or failure to reach owned cleanup on custom cancellation. Opposite decision repeatedly sends TERM to the signal-ignoring old handler, leaving a known ineffective stop path; an unguarded broad kill would widen authority. Removal leaves exact observed failure unresolved. Existing selector behavior cannot be changed by application profile configuration; the private custom exception is the smallest local correction. Future critic should challenge interpreting “ownedGroupEmpty” in failed v1 as original host stopped; v2 explicitly distinguishes original group gates from newly launched group cleanup.

## 6. Findings

**F1 — KEEP; OBSERVATION; intent-vs-shape.** Custom BaseException cancellation directly avoids the installed selector's exact catch while preserving outer cleanup. It addresses actual lifecycle behavior without altering application/auth interfaces.

**F2 — KEEP; OBSERVATION; ownership.** Graceful-first, exact identity/parent/pin revalidation, bounded selected force stop and both-groups-empty gates are proportional to Root's selected restart authority. Keep refusals on drift and manual-inspection evidence on cleanup failure.

**F3 — KEEP; OBSERVATION; evidence.** Failed attempt is not successful activation: no replacement, same retained database, original live service producer-observed. Report its failure honestly and retain all evidence. Prior static approval did not establish selector cancellation behavior; this successor corrects that runtime limitation.

**F4 — DEFER; OBSERVATION; user-value.** Actual corrected stop/activation or rollback receipts, full DB comparison/old18088 preservation, current-token Source append and actual archive/readback remain outstanding. No blocker, RESHAPE or REVERSE remains for this exact static delta.

## 7. Verdict

**APPROVE exact static v2 correction and pinned dispatch command.** Intent MATCHES; user-value SUPPORTED; commitments HONORED within inspected source; conceptual debt PAYS DOWN cancellation ambiguity; sibling subsumption PARTIAL/reused; confidence HIGH for static ownership/cancellation paths, actual corrected behavior unqualified.

All six phases applied. H1 InterruptedError reaches outer cleanup REFUTED by installed selector source. H2 custom exception is swallowed by that same catch REFUTED by inheritance and catch type. H3 force stop may operate on arbitrary old names REFUTED by exact revalidation/parent/pins. H4 failed original attempt activated profile REFUTED by retained result and missing replacement evidence. No phase skipped. No live operation was performed or independently authorized by this reviewer.
