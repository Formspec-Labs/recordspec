# Source native receiving activation — actual V2 AFTER evidence review

Review ID: TRELLIS-SOURCE-NATIVE-ACTIVATION-AFTER-V2-2026-10-10. Independent nonauthor `/root/oidc_code_review`. Full semi-formal-code-review method applied incrementally from pinned complete BEFORE source/config and correction reviews, `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`. Only this certificate written. Retained files/source inspection only: no operator import/invocation, live process/DB/network/provider/Docker/native/compiler action. Private secrets/DSN/env values not printed or copied.

## Findings and decision

**APPROVE retained actual V2 configuration activation evidence for its recorded point in time. No blocking receipt inconsistency.** Exact Source receiving profile/grants were selected by the replacement process; no Source application append or archive/restart qualification is established.

F1 — OBSERVATION / scope / closure sourceAppendQualified=false/archiveQualified=false and result positiveSourceAppendQualified=false. These exclusions are correct. Healthy readiness demonstrates maintained repository/artifact health probe, including known artifact write/read, not current-token Source admission or immutable full ZIP export/restart/trust.

F2 — OBSERVATION / evidence. Old74338/service group and73745/supervisor absence, active listeners/new supervisor and released window are owner-retained diagnostic facts. Reviewer performed no current process query; this report cannot establish continued liveness after the receipt. Unlike earlier first-start evidence, old18088 raw before/after snapshots are both retained and independently byte-identical.

F3 — OBSERVATION / execution coverage. Identity-checked force-stop/activation success path actually ran; rollback, log-limit failure and new BaseException cancellation paths were not exercised in this activation. Prior static/isolated cancellation evidence remains applicable, but this success is not a claim all recovery branches are runtime-qualified.

## Patch summary, calls and evidence trace

Reviewed actual closure f33397d6…, all ten named evidence pins, original process/supervisor snapshots, current exact approved operator45d849a3…/recipe1e1c6d25…/config8d1aee61… and all15config pins. Private output directory is source-native-activation-38a4960b-c8fb-45f1-94d7-73c053145005 under the selected local-demo directory. No source change occurred during this review.

| Reviewed source / retained input | Trace → verified result |
|---|---|
| V2 original selection before stop | Exact original process/env and supervisor snapshots retained. Fixed old service74338/PGID74338 and supervisor73745 match configured selection. |
| V2 force-stop125–153 / verified-force-stop.json | TERM path did not empty old service group; recorded exact identities revalidated, then selected service group force-stop with3s bound. Closure reports both old groups empty and original supervisor removed. No arbitrary discovered listener killed. |
| V2 launch / activation-started.json | Replacement service16071/PGID16071 under new resident supervisor15442,32MiB/service64MiB maximum aggregate. |
| activation-process.private.json | Independently compare original and actual argv/env: argv identical, env differs only TRELLIS_OIDC_CONFIG_FILE, exactly selectedV8. Secrets privately equal; key/bin/DB/artifact settings unchanged. |
| V2 readiness / activation-ready.raw.json | Retained raw healthy response matches88e6e2d… hash; repository and artifact store reachable, known artifact put/get. |
| V2 full DB preservation / before+after | Same exact bytes and parsed rows: three expected tables,0events,0publications,4migration rows; no application mutation/data restoration. |
| V2 preserved / old18088 before+after | Raw argv/env/auxiliary snapshots byte-identical. Current source/key/config pins remain exact; no old memory rows readback performed. |
| V2 final admission / result.json | Activated result matches public closure, new profile55589b8e…/grants ec5b8c59…, DB/old18088 preservation true; Source append false. |
| closure-diagnostic | Recorded exactV2supervisor, active selectedV8, old groups absent, no transient owned processes; retained resident service/supervisor and historical18088 explicitly listed. |

Function implementations/callers/callees, data-flow invariants and refusal branches are preserved in complete original and correction BEFORE certificates, pinned below. Actual result acceptance is bounded by those source guards and saved private inputs; no prospective test description is treated as execution.

## Data flow and preservation

Selected_env originates as the captured exact original env with only profile path replaced. Independent raw comparisons confirm this actual flow. New grants referenced by V8 authorize Source stable principal on formspec.managed-single-cell Read/Append with service/formspec-server, payloadActors empty, no Administer/case grant. Profile selection alone is not successful token or append proof.

Original signed key, binary, DB/artifact/introspection selections and receiving configs remain bound to all15unchanged pins. Complete DB before/after rows equal; no snapshot restored. Old18088 raw snapshot equal, not all old memory records compared. Forced stop changes original selected process lifetime; replacement creates newPID rather than resuming oldPID. Retained supervisor remains responsible for bounded logs/owned cleanup. Activation log is resident and may grow: hash below binds readback bytes only, not future log immutability.

## Execution inspected versus performed

Reviewer executed no tests/operators or live probes. Independently rehashed public closure, all named evidence and current15inputs; compared full DB bytes/objects, raw old process snapshots, result equality and private actual environment. Actual owner operation reached activated result after reviewed guards. No rollback-result/failure receipt appears in this successful output. Claimed mutations correctly include old TERM/force-stop, original supervisor removal, new launch and health artifact write; exclude application append, DB row change, data restore/delete and rollback.

H1 activation used a different operator/config: REFUTED by exact source/config/evidencepins. H2 restart changes DB/key/artifact settings: REFUTED by env delta and complete rows/pins equality. H3 old process preservation depends only on a success boolean: REFUTED for this snapshot by retained before/after bytes. H4 success qualifies Source append/current liveness/archive: REJECTED; false flags and no such execution evidence. Coverage gaps explicit, no unresolved blocker in retained activation scope.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-source-native-activation-before-code-review-v1.md` | `d36a1f951697bb786df9946de249d60214e075c342b0dab3d4a199686e3db134` |
| `trellis-source-native-activation-correction-before-code-review-v1.md` | `2b3fab2a67e55d77d350e1ce2121379ff11cf4bb9a1ed34a4512e1c96c78f021` |
| `trellis-source-native-activation-actual-closure-v2.json` | `f33397d64282af55cfe59cb65faf4999ff8fad2a911712b9b68e76b0d0d905b6` |
| `activate-source-native-restart-v2.py` | `45d849a3c90810e2b7bf342aff019914598ec0491b9b3455616030c5e7c9d0be` |
| `activate-source-native-restart-v2.command.txt` | `1e1c6d254bfe6df07a76c9ffa96e85f6ab43050fc2c54232c76c379c1e78590d` |
| `activate-source-native-restart-config-v1.json` | `8d1aee614df411f9d726af72ea30104760529a8835aeeff7ae950b76590ddcec` |
| `activation-process.private.json` | `0ca5195e005809bc618147c4cfc682e915c323cda92a5d70d97d44ceadd2835d` |
| `activation-ready.raw.json` | `88e6e2d81b00405c964f4c2dc37d756cd5da9f91f505bda84ced13f03693ee4e` |
| `activation-started.json` | `f2a7b02ffdae5cf0e7298ab20d1d058493fe987e51ef2d961ce524145304c579` |
| `activation.private.log` | `9e7c850b0fc955be367e05cd3575cfca5f9582ad4a60348726f42d7043926776` |
| `closure-diagnostic.json` | `d0261ea964d7a310b07943d52cb2ac3455b198e0216070a3d72643ab70a32fff` |
| `database-after.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `database-before.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `old18088-after.private.json` | `c514d798552fc0c4b7d6c42c102331f41b438885326373e9064c9f1e023cc974` |
| `old18088-before.private.json` | `c514d798552fc0c4b7d6c42c102331f41b438885326373e9064c9f1e023cc974` |
| `original-process.private.json` | `e8e32e1e3e857d2f48e9ea91be6e8f32bb8264d3eb7f43bd1b4142cf2e7f02dc` |
| `original-supervisor.private.json` | `6e427e3e3b60203b99cec5877b981b4d57ef6fa2d49d291cba33dfa6924d7206` |
| `result.json` | `ae9b0a1002c55d6d6ddef55d5dd95b9c712c08ed32a6bc02d7796fbb60e0fd8f` |
| `verified-force-stop.json` | `db1d940b98905e7a6a5b706f5a9fb6ab5e0ed6a89d4ad8697768bdf2c90b446d` |

All supplied closure/evidence hashes match; all15config pins match unchanged. Log hash is point-in-time observation only. Secrets not included.

## Conclusion

VERDICT: APPROVE recorded actual V2 receiving activation and preservation evidence.

Coverage: ADEQUATE for successful force-stop/replacement/configuration/DB preservation/readiness closure; INSUFFICIENT for rollback/failure execution, current liveness, positive Source current-token append, immutable archive/restart and agency trust. Confidence: HIGH for retained evidence equality and inspected source boundaries. No live actions performed; subsequent owning Source/admission/export qualification remains pending.
