# Source native activation cancellation correction — static BEFORE review

Review ID: TRELLIS-SOURCE-NATIVE-ACTIVATION-CORRECTION-BEFORE-V1-2026-10-10. Independent nonauthor `/root/oidc_code_review`. Full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` applied incrementally with pinned original full review. Only this certificate written. No scripts imported/executed, process probes, HTTP/network/DB/Docker/native/compiler actions. Read-only source/diff/hash/AST inspection and retained receipt comparison only.

## Findings and verdict

**APPROVE exact V2 operator45d849a3… and recipe1e1c6d25… for bounded static readiness. No blocking source issue found.** Actual previous activation failed before replacement; the correction retains that failure and does not report Source activation or append success.

F1 — RESOLVED / correctness / V2:9,106. Cancellation now raises custom OperatorStopped(BaseException). I inspected installed Python3.12 KqueueSelector.select: it catches InterruptedError and returns ready[], confirming the mechanism that could swallow the old cancellation after signals had been ignored. BaseException subclass is not caught by that handler and reaches operator's existing except BaseException cleanup/rollback. Repeated-stop ignore-before-raise remains intact. Reviewer did not execute the supplied isolated subprocess reproduction.

F2 — OBSERVATION / authority / V2:128–148. Escalation expands explicit mutation to SIGKILL of the originally selected service group and, if still present, original supervisor PID. Before force stop it revalidates exact retained listener, service argv/env/auxiliary, PGID, supervisor argv/env/auxiliary/PGID, parent relationship and all pins/old18088 preservation. This matches Root's explicitly requested bounded owned-resource correction. PID reuse/concurrent mutation between check and signal is not eliminated by static checks; single-writer live-window custody remains an operational prerequisite. No generic discover-and-kill behavior or old18088 target introduced.

F3 — OBSERVATION / tests and scope. No operator tests executed by reviewer. Source and embedded recipe AST parse. Retained diagnosis reports original74338/supervisor73745 unchanged and no replacement, but this is point-in-time owner evidence, not current liveness. Actual force-stop/new activation/rollback and Source append/export must be evidenced later.

## Patch summary and function traces

Exact diff against reviewed V1b87a07b3… adds only custom cancellation, bounded identity-checked old service/supervisor escalation, and both-group-absence rollback requirement. Frozen config remains8d1aee61… and all15current pins match. No credentials/config/Rust changes or data restore. Existing180s activation,30s readiness,90s rollback,32MiB/service64MiB aggregate and owned cleanup remain unchanged.

| Function / seam | V2 location | Inputs → behavior/output |
|---|---|---|
| OperatorStopped/cancelled |9,106–108 | SIGINT/SIGTERM → ignore repeats and raise BaseException subclass; bypasses selector InterruptedError catch. |
| Original stop/escalation |125–147 | TERM selected old supervisor, wait10s → if service group remains, exact identities/parent/pins verified → retained force-stop receipt → SIGKILL selected oldPGID, wait3s. |
| Supervisor cleanup |148–153 | Remaining original supervisor group → exact PGID/identity recheck → kill only selected supervisor PID and wait3s. Both group absences and empty18198 required before new activation. |
| Activation/rollback |154 onward | Same selected_env/DB preservation/new launch; rollback requires both old groups absent; no collision/replacement over old live service. |
| Existing cleanup/drain/launch |unchanged reviewed functions | Owned new group only, explicit cleanup errors/manual inspection, independent per-service log capacity, exact new env and live-at-admission check. |
| Recipe | v2.command.txt:5–10 | Unconditional exact operator digest → absolute Python, detached narrow-env/DEVNULL new session, private O_EXCL0600 bootstrap log; reports dispatch only. |

Important callees read previously and retained: pinned capture_process2143e3f6… supplies bounded real env/auxiliary separately; finite.group_exists treats inaccessible group as present; base.listener bounded lsof; preserved checks old18088/config; read-only snapshot helper captures bounded complete rows. Parent relationship query uses fixed /bin/ps argv,3s timeout; its small expected stdout is never used to choose arbitrary targets. No subprocess shell.

## Data flow and invariants

Old PID/PGID and supervisor selection originate in unchanged frozen config and baseline actual-process receipt. Force-stop uses those fixed values only after original process equality and supervisor-parent identity checks. Original data/key/binary/profile/artifact/introspection pins are revalidated; old18088 remains preservation-only. New Source grants remain exact resourceRead/Append with service actor and no Administer/case authority. Old process-group absence is required before activation and rollback, preventing concurrent old/new listener ownership.

OperatorStopped propagates through selector to outer BaseException handling; late intentional stop still cleans owned resident without rollback. Original supervisor's old InterruptedError behavior is deliberately not patched on disk or reinvoked; bounded escalation handles its observed stop failure. If identity changed, group survives after bound or listener remains, operation refuses and retains manual-inspection failure rather than killing a newly discovered resource. Partial DB/object state is never restored/deleted. Same signed key and binary reused; Source append qualification remains false.

## Retained actual failure evidence / tests

Read activation-failure.json: phase stop old owned supervisor, RuntimeError, no data restoration. rollback-failure records manualInspectionRequired and no owned new group. Diagnostic receipt reports replacementLaunched=false, sourceProfileActivated=false, applicationAppendPerformed=false, no readiness probe and original listeners/process preserved. Independently compared database-before.private.json and database-diagnostic-after.private.json: exact row equality; empty events/publications and4migration rows. Rehashed all15current inputs: match. These owner-retained facts establish failed attempt preservation, not current state.

Reviewer executed no tests/reproduction. Installed KqueueSelector handler source supports failure mechanism. Source-derived edges: wrong listener/PGID/argv/env/parent/pin prevents force kill; vanished service naturally skips force stop; remaining supervisor requires exact recheck; surviving group refuses activation/rollback; custom cancellation reaches existing owned cleanup; failed activation restores original only if both old groups absent and final readiness/DB/deadline checks pass. No positive provider/D1 inference.

## Exploration updates

H1 InterruptedError cannot be swallowed in resident select: REFUTED by installed implementation and retained failure, corrected by OperatorStopped. H2 escalation kills arbitrary listeners: REFUTED by fixed selection/exact identity/parent checks. H3 previous failed activation mutated DB or launched replacement: REFUTED by retained row equality/diagnostic receipt. H4 corrected source establishes current activation: REJECTED; no reviewer execution. No unresolved blocker within bounded static scope.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-source-native-activation-before-code-review-v1.md` | `d36a1f951697bb786df9946de249d60214e075c342b0dab3d4a199686e3db134` |
| `activate-source-native-restart-v1.py` | `b87a07b3ad36afccf8fdeb85d1e641d043de5836d7a40d20dff312edded1e042` |
| `activate-source-native-restart-v2.py` | `45d849a3c90810e2b7bf342aff019914598ec0491b9b3455616030c5e7c9d0be` |
| `activate-source-native-restart-v2.command.txt` | `1e1c6d254bfe6df07a76c9ffa96e85f6ab43050fc2c54232c76c379c1e78590d` |
| `activate-source-native-restart-config-v1.json` | `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec` |
| `activation-failure.json` | `f5f7dabcafbc2ab1b545a91ab1424bd57a9f94ee2a300ea76e60a8ace4f30320` |
| `database-before.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `database-diagnostic-after.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `diagnostic-result.json` | `21184fe53af0ef87afa695fb528f7e436df8483d6d06e61d898fccbe7e924945` |
| `isolated-stop-handler-proof.json` | `050a603c83028be9ad93a1293078a3caffef543a4865837102c62b8c664dc4ad` |
| `old18088-before.private.json` | `c514d798552fc0c4b7d6c42c102331f41b438885326373e9064c9f1e023cc974` |
| `original-process.private.json` | `e8e32e1e3e857d2f48e9ea91be6e8f32bb8264d3eb7f43bd1b4142cf2e7f02dc` |
| `original-supervisor.private.json` | `6e427e3e3b60203b99cec5877b981b4d57ef6fa2d49d291cba33dfa6924d7206` |
| `rollback-failure.json` | `d57020b2af9f8614b1a79c11a9c804ebe767e862fe40dd0dce0425446c462aeb` |

Current15input hashes match config; no secrets printed/copied. Source, command/config hashes equal supplied exact values. Prior reviews preserved.

## Conclusion

VERDICT: APPROVE exact V2 static correction and dispatch recipe.

Coverage: ADEQUATE for bounded source/caller/cleanup/failure evidence review; INSUFFICIENT for actual force-stop/activation/rollback execution or current liveness/provider/append/export. Confidence: HIGH for inspected source and hashes. Root's separate live-window execution and actual receipts remain required. No live action or Rust/private configuration edits by reviewer.

## Retained isolated cancellation proof addendum

Read isolated-stop-handler-proof.json SHA `050a603c83028be9ad93a1293078a3caffef543a4865837102c62b8c664dc4ad`: owner records old KqueueSelector self-signal handler ran/select returned normally/TERM now ignored, corrected custom cancellation escaped selector, each subprocess timeout3s. Reviewer did not execute proof or signal any live process. This corroborates the library-source mechanism; causal diagnosis of the live failure remains an inference rather than instrumented live traceback. Exact static verdict unchanged.
