# RustFS recovery and persistent Trellis startup: static BEFORE architecture review

**VERDICT: APPROVE the bounded operator design.** Recover the exact existing container, qualify only the selected new bucket and isolated key with maintained SDK calls, then require a pinned positive receipt before preparing persistent Trellis startup. Preserve the distinction between raw provider412 behavior, Common byte-comparison semantics and actual Trellis export/restart proof. This is static design acceptance; this reviewer performs and authorizes no operational action. Root's explicit selected recovery authority governs execution.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied. Only this certificate written. No script invocation, Docker, provider/DB/native/network command, SDK request or service mutation occurred. Python used only for read-only JSON/digest inspection; no prepared script was loaded or run.

## 1. Artifact summary

Proposal `trellis-rustfs-recovery-persistent-startup-proposal-v1.json` SHA `8f72c95c721026fd245bb7f272709c63ce582145fb26e8b29e7595e3a8e757af`. Private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`; private artifact profile SHA `18068348904f79b7191951741e2eb4040dcce7678541ac87f318aced157b2885` mode0600. Recovery script SHA `3a9e2dc2d544ffccd28b55b7f3bd7736455062b10837b44bf26cea48852dac8f`; persistent launcher SHA `aba250439f1203accdb2afc77e33aada33516a65448de51c2d7f4bc8136b72f7`, each0700. All independently match the proposal.

Category: operator recovery and persistence qualification infrastructure. Beneficiary: a reviewer needing acknowledged export bytes to remain retrievable after the Trellis process restarts. Proposed recovery is Root-selected stopped→running transition of the same cached RustFS image/container and named volumes, not recreation. New bucket is `trellis-full-d1-20261009-v1`, prefix `trellis`; existing buckets/keys are not named by operator S3 calls. Prior exit255 cause remains unknown.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Qualified OIDC binary | Strict current identity/resource startup | `trellis-oidc-startup-after-architecture-review-v4-final.md:§1,§3` |
| Corrected static operator prep | Exact DB/key/profile/grant binding, empty grants | `trellis-18198-static-operator-after-architecture-review-v2.md:§3` |
| Root goal/philosophy | Durable proof survives live service | `GOAL.md:Product Claim, Target Deployment Profile`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Maintained artifact startup | Selects S3 adapter from nonempty environment configuration | private `trellis-server/src/state.rs:479–489` |
| Common absent-only byte primitive | Create or compare existing exact bytes | `stack-common-object-store/src/lib.rs:136–179` |
| Trellis artifact adapter | Delegates immutable writes/readback to Common | private `trellis-server-ports/src/lib.rs:319–358` |

| Named seam | Owner | Input / output | Limitation |
| --- | --- | --- | --- |
| Existing container recovery | Root/operator, Docker | Fixed container/image/mounts/ports → running same resource | Root-authorized mutation; existing data remains |
| Conditional provider qualification | Maintained boto3/botocore | New bucket/UUIDkey → raw statuses + saved exactGETs | SDK semantics, not Trellis execution |
| Common immutable object write | Common/object_store | Create; AlreadyExists → exact-byte compare | Separate implementation/actual-provider path |
| Trellis persistent artifact adapter | Trellis, configured operator | Immutable export bytes → S3 reference/readback | Actual sameack/restart/pinned retrieval pending |
| Current grants/export authority | Root/WOS/exporter | Fresh exactcase and separate read/administer | Empty now; no implicit elevation |

## 3. Invariants and commitments

- **Preserve selected container and storage — PRESERVED in design.** Recovery `inspect_selected:58–79` saves private before/after inspect then verifies exact ID/name/image, exact `/data` and `/logs` named RW mounts, exact loopback19000/19001 ports and selected credentials. `main:119–137` permits exited/running only, starts exact ID only if exited and rechecks running identity. No pull/create/recreate/remove/volume command exists. Provider process startup can inspect its own persisted state; the narrower supported preservation claim is that operator commands do not target old buckets/keys, not that recovering a storage server internally touches no old metadata.
- **New bounded operator storage — PRESERVED with explicit prior-run reuse.** SDK calls name only selected bucket; if already present, a matching private owner receipt is required (`:173–190`). Otherwise create bucket, retain owner receipt and never delete it. Every run uses one UUID isolated key; no oldobject list/get/put/delete path exists. No automatic stop or cleanup occurs after failures. Prior partial/retry evidence stays available.
- **No fabricated immutable-provider success — PRESERVED.** `:201–249` sends IfNoneMatch* via installed SDK; initial create must200/201, identical and conflicting attempts must412. Each GET is bounded, saved privately and compared with original bytes. A provider that acknowledges identical retry200 fails this qualification; successful reads alone do not manufacture absent-only enforcement. Common's separate `write_object_bytes_once` handles AlreadyExists by actual byte equality; SDK script does not execute that helper or claim it did.
- **Receipt before persistent startup — PRESERVED.** Launcher `:29–37` requires pinned artifact profile plus pinned private passed receipt for that profile, original bytes preserved and server running. Later checks retain exact binary/profile/grant/DB/key pins; `:56–64` sets nonempty bucket/prefix/endpoint/region and narrow explicitAWS credentials/HTTP/pathstyle/conditional-put environment. Maintained `state.rs:479–489` therefore selects S3 instead of memory. Actual lazy backend connection/writes still require execution qualification.
- **Current authority unchanged — PRESERVED.** Empty grants require explicit allow-deny-all selection; strict OIDC and exact selected database/key remain. Fresh case/readappend/human grants and separate exporterReadAdminister remain pending. Root-selected recovery does not authorize arbitrary case grant changes or old456reuse.
- **Secrets and private evidence — PRESERVED in source.** Profile/receipts use opened-fd owner/private-mode/regular checks with bounded reads; full inspect containing credentials is saved0600 under0700directory. SDK credential arguments are in-process, not CLI argv; logging is suppressed and provider errors sanitized. Launcher supplies credentials in a narrow child environment, not output. No handwritten signing/OAuth implementation exists.
- **Bounds — PRESERVED at declared per-call level; total bound RELIED-UPON.** Docker timeout30s, SDK connect2/read5/retry1, readiness20attempts/sleep1, GET4096byte bound and one isolated key are explicit. Docker's1MiB check follows capture_output, so it is not a streaming memory cap. Recommended300s overall limit is not enforced by script; network read timeout is not an absolute whole-operation deadline. Root should use an external bounded runner when requiring a strict total deadline. No hard total/memory-bound claim follows current source.

## 4. User value and simplicity

This reuses Root's exact cached service and volumes, maintained SDK signing/model and existing Trellis/Common storage adapters. It avoids new storage infrastructure and protocol code while checking the specific provider feature needed for immutable export publication. Costs are an explicit service-state mutation, new isolated bucket/key and retained private evidence. No speed/resource improvement is measured.

The qualification intentionally distinguishes raw412 rejection from Common's idempotent same-byte acceptance and different-byte refusal. That distinction makes later restart proof falsifiable. Smaller “put/get worked” evidence would not test conditional creation and could hide overwrites. Broader oldbucket inspection/cleanup would increase scope without helping the named proof.

## 5. Counterfactual analysis

Kill criterion: inspect mismatch, prior bucket without owner receipt, any retry acknowledged instead of412, changed exactGET, or launch before pinned positive evidence. Opposite decision recreates storage and risks losing existing custody; removal leaves persistent artifact readiness untested. Existing SDK subsumes S3 signing; Common/object_store subsumes maintained byte compare; neither can substitute for actual Trellis export→ack→restart→samecheckpoint retrieval. Six-month critic: SDK receipt may be mislabeled end-to-end persistence or recovery may be mistaken for diagnosis of exit255. Preserve both limits.

## 6. Findings

**F1 — KEEP; OBSERVATION; ownership/preservation.** Pinned samecontainer/image/mounts/ports/credential verification and selected newbucket/UUIDkey provide the smallest authorized recovery scope. No oldbucket/object operations or automatic cleanup are needed. Keep private before/after evidence and explicit stopped→running transition.

**F2 — KEEP; OBSERVATION; conformance.** Require raw412 for both retry cases plus saved exactGETs; then report Common comparison semantics separately. Do not replace raw provider failure with local same-byte success or claim the actual maintained helper ran.

**F3 — OPTIONAL; scope/bounds; RESHAPE if hard overall bounds are required.** Use Root's external300s runner/watchdog and bounded subprocess-output capture, or label current Docker size check as post-capture validation. Current proposal correctly says overall limit recommended; it must not be reported as enforced. This does not require a new architecture or storage change.

**F4 — DEFER; OBSERVATION; user-value/evidence.** Actual Trellis S3 acknowledgement, restart of the same service with same DB/profile/key/backend, exact pinned export retrieval, negative conflict behavior and owning offline ZIP acceptance remain mandatory successor gates. SDK-only qualification does not prove them. Current-token positive admission, fresh exactcase grants/exporter scope, independent agency trust and fullD1 remain separate.

No blocking RESHAPE or REVERSE finding applies to this exact bounded design.

## 7. Verdict and limits

**APPROVE static operator design within Root's selected recovery scope.** Intent MATCHES persistent-artifact preparation; user value SUPPORTED by absent-only provider requirements; commitments HONORED in source with operational assumptions; debt PAYS DOWN protocol duplication and deployment mismatch; sibling subsumption PARTIAL; confidence HIGH for static path/pin checks, actual provider/recovery behavior unverified.

All six phases applied. H1 recovery recreates resources REFUTED by exactstart-only path. H2 equal SDK retry counts as raw immutable success REFUTED by412 requirement. H3 SDK runs Common/Trellis helper REFUTED and separate semantic statement verified against Common source. H4 receipt alone proves restart retention REFUTED by pending sameack/retrieval gate. H5 recommended300s is enforced REFUTED by source. No phase skipped.

Static package versions/model qualification are owner-reported preparation facts, not reviewer-executed SDK evidence. No Docker/provider/DB/network operation or script dryrun was performed. Source package pinning does not establish container liveness, ownership of new bucket, credential validity or actual artifact persistence. Any script/profile correction or changed actual grant freeze requires a successor digest-bound review.
