# Trellis bounded operator — actual startup AFTER evidence review

Review ID: TRELLIS-BOUNDED-OUTER-ACTUAL-AFTER-V4-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Full semi-formal-code-review method applied incrementally with exact approved wrapper and previous source certificates under `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`. Only this certificate written. Retained files/source read only; no live process capture, DB/network/provider/Docker/S3/native/compiler or prepared-script invocation.

## Findings and decision

**APPROVE retained point-in-time startup evidence for exact approved wrapper11429bab…. No blocking inconsistency found.** This accepts the recorded selected server startup/migration/readiness checks, not current liveness, positive OIDC access, full immutable export or restart retrieval. Intentional zero-grant configuration remains in effect at the pinned evidence inputs.

F1 — OBSERVATION / evidence / startup-result.json and wrapper:193–198. Old18088 preservation is supported by the exact wrapper's successful equality assertions and retained before snapshot/config hashes. No raw old process after snapshot was saved. I can trace the success claim, but cannot independently reconstruct its after-state equality from saved raw values. Current read-only file hash comparisons against retained old binary/config pins match; no live process claim is inferred. oldMemoryRowsReadbackCompared explicitly false.

F2 — OBSERVATION / scope / readiness.json. Maintained readiness200 exercises repository list_scope and artifact put/get at trellis/__healthz__/artifact-roundtrip. It records reachable artifact adapter behavior, not immutable full ZIP create/retry/export/restart qualification. positiveOidcQualified and artifactAdapterQualified remain false in startup result; these conservative flags are appropriate for their broader pending qualification scopes.

F3 — OBSERVATION / custody. service.private.log belongs to the resident supervisor and may grow after this readback. Its listed hash/size binds only observed bytes, not a frozen future log. No current listener/process inspection was performed.

## Scope, traces and data flow

Evidence directory: `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1/bounded-start-82c98432-cdbe-4d25-a445-f145a543fd7b`. Source wrapper remains exactly11429bab… approved in V3; launcher remains V6 source pinned98101f0a… with profilead47c718…, artifact18068348…, DBd15d5c86…, grants2ee96972… and passing recovery receiptc8ea70d6….

| Source / evidence | Trace and verified disposition |
|---|---|
| wrapper:142–155 / launcher-preflight | Dry launcher through finite helper; receipt exit0, no truncation/supervisor error, groupEmpty true. Saved649-byte stdout and zero-byte stderr hashes/lengths match receipt. |
| launcher:35–64 / preflight stdout | Receipt/profile/grant/artifact/DB/key/binary pins checked; dry-run reports zero grants and selected S3 backend. No secret values emitted. |
| wrapper:163–187 / started and actual-process | Owner records operator73745/servicePID and PGID74338. Captured argv is exact saved qualified server. Independently compared all actual env entries with reviewed launcher/profile/artifact/DB selections, including credentials privately: exact match. PATH is retained actual value; original parent PATH is not separately saved, so its intended equality rests on wrapper's successful exact-env assertion. No keys normalized/excluded. |
| wrapper:173–178 / readiness | Recorded200 plus body hash, maintained health-object write disclosed; raw HTTP response body not retained. |
| helper snapshot and wrapper:148,188–192 | Retained before{}; after exactly trellis_events[], trellis_bundle_publications[], trellis_schema_migrations versions1–4. Migration rows carry applied_at2026-10-09T22:33:26.339191+00:00. This is saved read-only snapshot evidence, not a fresh query. |
| process helper/wrapper:144,160,183,193 | Four auxiliary diagnostics correspond to old PID16414 three captures and newPID74338 one; mergedIntoEnvironment false. Old before argv/env retained, equality checks precede success result; limitation F1. |
| wrapper:195–199 | Final monotonic deadline check precedes success save; result status started, deny-all/no business rows, resident log cap32MiB. |

Private credentials/DSNs/environment contents were not printed or copied to this certificate. Current profile/grants/private DB hashes match retained startup selections. Actual environment uses only reviewed explicit entries; artifact bucket/prefix/endpoint correspond to selected new RustFS bucket. Signing/export trust validity remains independent of this startup/authority configuration.

## Tests/evidence inspected versus executed

Reviewer executed none. Read all named retained receipts and exact wrapper source, compared private actual environment and preflight output hashes, inspected DB snapshots and auxiliary diagnostics, and rehashed old binary/config paths without accessing service/DB. Owner preflight/startup are actual retained results; no tests described here are substituted for execution.

Point-in-time facts accepted: dry preflight successful and cleaned; recorded actual selected process/environment; new DB initially no public tables then expected migration inventory with zero application rows; readiness200; success path asserts old process/binary/config preservation and exact final source/input checks. Expected refusal cases remain statically reviewed in V3; not rerun. No authenticated exact-case200, old in-memory row readback, actual export, restart or independent agency trust demonstrated.

## Exploration updates

H1 receipt refers to different wrapper/config: REFUTED by exact wrapper/current input pins and actual env comparison. H2 startup writes application records: REFUTED by retained empty events/publications snapshots. H3 old process after equality independently replayable from raw evidence: NOT ESTABLISHED; F1 distinguishes source-asserted success from independently retained after values. H4 recorded start proves current liveness/provider admission: REJECTED; no live query and result explicitly excludes positive OIDC. No further static/evidence blocker.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-bounded-outer-after-code-review-v3.md` | `fadbb35af201ed95c90a56facddfc7b930031281b2b5a4fd9abe6611b31b4a37` |
| `run-trellis-bounded-v2.py` | `11429bab85631f43c7ec86acdd6c39de579a9cda50ebb368bb4d1f15148c1958` |
| `start-trellis-persistent-reviewed-v6.py` | `98101f0ae2426167679897b264929571a3f0b985a58fb7d48030c076fef1bf54` |
| `oidc-profile-exporter-v6.json` | `ad47c7186758c9adfefb9974a863124de48ea3d5cb40259857da594267a8f6f3` |
| `current-grants.json` | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |
| `actual-process.private.json` | `1443990f80dc1da2fb8b9398405fc1f251f583217c3c09faaf7da2891b29c4f8` |
| `database-after.private.json` | `eef93e13149ada2228b8d58cb3ca37148ed04a5d0654c10b0b0a37285fb15bb5` |
| `database-before.private.json` | `ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356` |
| `launcher-preflight.json` | `61f89bf5b724dfb2d1a17ce6e9a2f8e1886a6c63840668b06f7ee7b795ad7d55` |
| `launcher-preflight.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `launcher-preflight.stdout` | `7c5bb339719fa291c437a9db7bbc33d91d870c797e928ff8feb7f47edb112334` |
| `old-process-before.private.json` | `bcaec1fcebf2422c9185176778c2ae38afc9cd61e4224ac0a56c568dd4a3e388` |
| `process-auxiliary-diagnostics.json` | `b0f41fde5d31516cee2e7106409b174979528e79cc13b84f668aaf84a88771d2` |
| `readiness.json` | `2f4be33db05ad997c7629ebc0e9a93630bc9e83568307282e702d7c271d59115` |
| `service.private.log` | `b6279a582f14fc9ddfbd32cdfced9539294671a3d15c7835a373c40474cb0d76` |
| `started.json` | `0a0272dcf5b8c69d2a3c1ac7cff65fc14257a2bcea51c2a4b78444d893d6c190` |
| `startup-result.json` | `590f4746f1add0e300dc1de62974a5ede1f34c853f0e2b68efbdd5a87463372c` |

Startup result SHA matches supplied590f4746…. All hashes above were independently read back. Mutable service log is observation-only as F3; other files are retained execution inputs/results.

## Conclusion

VERDICT: APPROVE bounded actual startup evidence and closure for the recorded point in time.

Coverage: ADEQUATE for selected configuration, preflight, migration inventory/zero business rows and recorded readiness; INSUFFICIENT for current liveness, independently raw-after old process equality, all old memory rows, positive OIDC or immutable archive/restart. Confidence: HIGH for retained bytes and private configuration comparison; narrower source-success reliance for old preservation is disclosed. Root's subsequent operations and owning provider/export/trust qualification remain separate. No live action performed by reviewer.
