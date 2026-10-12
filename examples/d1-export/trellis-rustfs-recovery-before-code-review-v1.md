# RustFS recovery and persistent Trellis startup — static BEFORE review

Review ID: TRELLIS-RUSTFS-RECOVERY-BEFORE-V1-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` applied. Only this certificate written. No operator script, Docker, network, provider, database, Cargo or native command invoked. Read-only source/digest inspection and AST parsing only.

## Findings and decision

**APPROVE exact frozen proposal and scripts for bounded static execution readiness. No blocking source finding.** This does not report successful recovery, authorize execution, or qualify Trellis export durability. Root's separate operational grant and serialized window remain required.

F1 — OBSERVATION / evidence / recovery:239–244 and launcher:34–37. SDK absent-only writes and subsequent exact GETs are correctly distinguished from the maintained Rust adapter. A passing pinned SDK receipt gates launch, but does not establish that Trellis's own artifact helper/export/restart retrieval succeeded. The proposal explicitly leaves those checks pending.

F2 — OBSERVATION / bounds / recovery:50–55,152–170. Docker commands have30s timeout, SDK calls2s connect/5s read and one total attempt, readiness20 attempts with1s intervals, GETs4097 bytes with4096 acceptance limit. Docker stdout/stderr are checked after capture, not streamed with a hard allocation bound. The suggested300s overall limit is advisory, not a script watchdog. Fixed Docker operations and small expected outputs make this nonblocking for the bounded selected-resource operator; do not describe these as hard whole-process memory/time bounds.

F3 — OBSERVATION / tests. No script tests or executions inspected. Both scripts parse successfully and contain zero Assert AST nodes. Approval is source-only; live receipt and owning adapter checks remain necessary. Relevant prior native tests qualify server/client implementation, not this recovery operation.

## Patch summary and scope

Read all of `recover-rustfs-reviewed-v1.py`, `start-trellis-persistent-reviewed-v5.py`, frozen proposal and private artifact configuration. Credentials were read only for private input consistency/nonempty checks; no values printed or copied. Profile mode0600 and scripts0700 match. Inherited startup inputs and prior static operator review remain separately pinned. New behavior restarts the existing selected RustFS container, creates/reuses only the selected new bucket under a retained owner receipt, probes one fresh UUID key, and injects explicit S3 configuration into the already qualified server. No production source changes or replacement writer/auth/signing framework.

## Function traces

Private Python files live under `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`.

| Function / caller | File:line | Inputs → output | Verified behavior |
|---|---|---|---|
| require/private_bytes | recovery:27,32 | condition/private path → refusal/bounded bytes | Open no-follow/nonblocking; fstat regular file, effective owner/private mode;1MiB bound; explicit checks survive -O. |
| save | recovery:43 | owned path/value → private JSON | O_EXCL0600; existing evidence not overwritten. |
| docker | recovery:50 | fixed argv → captured stdout | Absolute CLI, no shell,30s timeout, generic sanitized failure. |
| inspect_selected | recovery:58 | pinned profile/container → inspect | Full inspect saved privately; exact ID/name/image, only selected named RW mounts and exact loopback ports, exact credentials checked before start. |
| sdk_error | recovery:82 | ClientError → status/code | Provider message/header/body excluded; code reduced to alphanumeric or other. |
| main/module guard | recovery:89,255 | flags/private pinned config → dry-run or retained recovery receipt | Dry-run returns before Docker/SDK client. Explicit execute creates private UUID evidence directory, inspects, starts only same exited container or accepts already running, re-inspects. Unexpected state refuses. |
| readiness/new bucket | recovery:143–190 | explicit SDK credentials/endpoint → selected bucket | Proxies disabled, path style, one attempt per call. Only selected bucket Head/Create. Existing bucket requires exact retained owner receipt. No list/delete or old-bucket operation. |
| conditional_put | recovery:201 | original/conflicting bytes → raw result | Maintained boto3 signing; IfNoneMatch='*'; only412 accepted as expected rejection. Initial requires200/201. |
| exact_read | recovery:213 | isolated key → retained bounded bytes | Stream closed, bytes/hash saved0600; each of three reads compared with original. |
| failure/final receipt | recovery:245–252 | stage/result → qualification JSON | Partial evidence retained, sanitized error type, status failed and nonzero on ordinary exceptions; no automatic stop/delete. |
| launcher main/private_bytes | persistent launcher:12–53 | pinned private files/receipt → validated inputs | Passed receipt must match artifact profile, exact-byte-preserved flag and running state. Rechecks binary/profile/grants/DB/key and bind/database selections. |
| launcher exec branch | persistent launcher:55–73 | explicit environment → server | Dry-run default returns; only explicit execute execs absolute binary; AWS credentials/settings allowlist, no inherited legacy/storage/artifact overrides. |
| maintained artifact selection | trellis-server/src/state.rs:479–490 | artifact env → S3 adapter | Explicit bucket/prefix/endpoint/region selects maintained adapter. |
| maintained lazy store | trellis-server-ports/src/lib.rs:230,263 | config/environment → object store | Maintained build_s3_store, lazy initialized backend, scoped prefix and bucket URI. |
| maintained immutable write | stack-common-object-store/src/lib.rs:60,139–173 | PutMode::Create → evidence or error | AmazonS3Builder::from_env consumes explicit AWS config; AlreadyExists compares exact stored bytes; differing bytes refuse. This source trace is not a claim the SDK probe executes that Rust path. |

Both module guards call main only when invoked. Nested put/read functions are called only in the execute branch. Source and private configuration control the exact chosen resource; immutable receipt digest is supplied explicitly to launcher by the operator after actual qualification.

## Data flow and invariants

Pinned artifact bytes supply container/image/volume identity and credentials. They pass opened-FD custody checks, then identity validation before starting. Credentials flow only to SDK explicit parameters and child AWS environment; full Docker inspect is saved only in0600 files inside0700 output. Public diagnostic receipt excludes credentials. boto3/botocore versions are checked before dry-run/execute; no handwritten signing. SDK models' IfNoneMatch support is a proposal/preparation fact; actual acceptance/rejection remains future observed evidence.

Selected bucket is fixed `trellis-full-d1-20261009-v1`, prefix `trellis`. Existing selected bucket cannot be reused without the profile/container-bound operator receipt. New key is a UUID under operator-qualification, original/conflict bytes are distinct constants. Initial create, same retry and different retry all use absent-only create. Both retries must412 and each GET must retain original exact bytes, otherwise receipt fails. No delete/recreate/auto-stop or old object enumeration occurs. Prior255 cause stays unknown. A failure may leave a running container/new bucket/key and partial evidence intentionally intact.

Launcher consumes exact successful receipt bytes, profile and startup pins before exec. It does not dynamically elevate grants or change the default deny-all authority. Persistent artifact settings reuse maintained AmazonS3 configuration (allowHTTP/path-style/conditional put) and the current credentials; actual export acknowledgement and same-checkpoint retrieval after restart remain a separate owning check. Pins/checks do not claim immunity to concurrent trusted-operator edits; private-directory freeze/custody is assumed.

## Tests and edge cases

No script tests executed or supplied. AST parsing only confirms syntax, zero Assert nodes confirms unconditional guard structure. Source traces predict: unexpected ID/image/mount/port/credentials/state refuses before restart; unowned existing bucket refuses before object writes; unavailable S3 exhausts bounded readiness or refuses nonretryable status; unsupported absent-only semantics returning200 on retry fails; changed GET bytes fails; failed/mismatched receipt prevents launcher exec; default dry-run performs no Docker/S3 calls. Exceptions before evidence-directory creation have no recovery receipt but also no live effects. Uncatchable termination can leave partial evidence without final qualification; no success can be inferred in that case.

## Exploration record

H1 source secretly creates/replaces container/volumes: REFUTED by only inspect/start CLI operations and exact ID checks. H2 probe conflates same-byte acceptance with raw provider success: REFUTED by both412 assertions and separate maintained-comparison descriptions. H3 launcher can bypass qualification using inherited artifact env: REFUTED by pinned receipt checks and explicit allowlisted environment. H4 provider receipt proves Rust export durability: REFUTED; correct future gate remains named. H5 bounded helper calls imply hard overall watchdog/memory bound: REFINED as F2. No unresolved correctness blocker in this bounded static scope.

## Exact pins

| Input | SHA-256 |
|---|---|
| proposal | `8f72c95c721026fd245bb7f272709c63ce582145fb26e8b29e7595e3a8e757af` |
| `artifact.private.json` | `18068348904f79b7191951741e2eb4040dcce7678541ac87f318aced157b2885` |
| `recover-rustfs-reviewed-v1.py` | `3a9e2dc2d544ffccd28b55b7f3bd7736455062b10837b44bf26cea48852dac8f` |
| `start-trellis-persistent-reviewed-v5.py` | `aba250439f1203accdb2afc77e33aada33516a65448de51c2d7f4bc8136b72f7` |
| binarySha256 | `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |
| privateDatabaseConfigSha256 | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |
| selectedRetainedKeyFileSha256 | `62644accd6ef7af276945418ee794ce6428ac63a0a79f78180addd372b053608` |
| profileSha256 | `c8de0c4bfba003b93c2ef28a937a3e8bef1f21c3d12f26685af7a294c196e057` |
| grantsSha256 | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |

All three new file pins and supplied proposal SHA match current read bytes. Inherited startup input qualification is retained from the previous pinned operator/native certificates; no native reexecution performed here.

## Conclusion

VERDICT: APPROVE exact static recovery/persistent-startup preparation.

The source achieves the proposed bounded, explicit resource selection and SDK evidence gating. Coverage: ADEQUATE for static preparation; INSUFFICIENT for actual recovery/provider/Trellis durability/D1 results. Confidence: HIGH in inspected source/pins, with execution and actual installed provider behavior untested by this reviewer. Root must separately authorize live operation; owning receipts, maintained Rust helper export/restart retrieval, fresh-case authority and ZIP/agency verification remain pending.
