# Trellis 18198 operator preparation — static BEFORE code review

Review ID: TRELLIS-18198-OPERATOR-BEFORE-V1-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Applied full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and current repository/user instructions. Only this certificate written. No operator script, Cargo, native command, database, provider or network action executed; AST parsing and read-only digest/source inspection only.

## Findings

VERDICT: REQUEST CHANGES for exact V2 operator packet. The profile and deny-all grant posture are consistent with the qualified server. Three script guards require correction before an exact startup/readback recipe is ready.

F1 — BLOCKER / correctness / `start-trellis-reviewed-v4.py:24–30`. Database URL and signing-key path flow from unpinned `database.private.json` directly into execve. Only bind is checked. The public packet pins profile, grants, binary and scripts but not this behavior-critical input. An accidental edit can select another database/key despite all stated pins matching. Current private file's selected key matches the packet, but that observation does not enforce future execution. Pin its digest locally/publicly without exposing secret values; explicitly validate the selected key path and freeze the exact private DB configuration in the execution receipt. This is especially material because maintained server startup applies migrations (`state.rs:457`).

F2 — BLOCKER / correctness / `start-trellis-reviewed-v4.py:17–25`, `readback-trellis-reviewed-v4.py:13–15,27`. Python assert statements implement the pin, bind, deny-all-selection, token and bounds guards. Python optimized execution removes assert statements. Thus `python -O ... --execute` bypasses exact-source/database/bind checks; readback loses its intended input/bounds guards. Replace these with unconditional explicit validation and sanitized refusal exceptions. Do not rely on the invocation omitting optimization.

F3 — BLOCKER / security / `readback-trellis-reviewed-v4.py:18`. `urllib.request.build_opener(RefuseRedirects())` replaces only the redirect handler; it retains the default ProxyHandler. I read installed Python build_opener/ProxyHandler implementations: default ProxyHandler uses getproxies(), which accepts environment proxy configuration. A configured HTTP proxy with no effective loopback bypass can receive the bearer even though the URL is fixed to 127.0.0.1. Construct with `ProxyHandler({})` as well as RefuseRedirects. Token provenance remains the maintained provider's responsibility.

F4 — OBSERVATION / test coverage. No tests cover these two new scripts. AST parsing succeeds but proves neither refusal branches nor execution behavior. After correction, useful isolated checks mock execve/HTTP and assert wrong config digest/bind/key refuses, optimization cannot disable checks, dry-run never invokes a process, inherited proxy settings cannot route the request, redirects never forward credentials and non-200/oversized bodies fail. This review does not execute those checks.

## Patch summary and exact scope

Reviewed full four named files under private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1` plus the V2 public packet. Additionally inspected the behavior-critical private database JSON without printing or copying credentials, maintained server startup/caller code, and installed Python HTTP opener source. The launcher is a thin environment loader for the previously qualified binary; readback is secondary HTTP instrumentation, not a new OAuth implementation. Auth owner commit e9f5af9 and inherited lock-edge handling do not change these script findings; no new source/commit equivalence approval is inferred here.

## Function traces

| Function / caller | File:line | Inputs → outputs | Verified behavior |
|---|---|---|---|
| Launcher main / module guard | start-trellis-reviewed-v4.py:9,38 | CLI flags+local files → dry-run JSON or execve | Explicit --execute required; dry-run default prints no DB URL/token/secret. Guards presently optimization-sensitive. |
| digest | same:8 | Path bytes → SHA-256 | Binds binary/profile/grants only; database input not pinned. |
| execve | same:27–37 | Narrow environment → retained binary | Only PATH plus five explicit Trellis entries; inherited legacy auth/storage/artifact/proxy environment omitted. PATH remains inherited but binary is absolute. |
| Readback main / module guard | readback-trellis-reviewed-v4.py:8,45 | Scope/output path+stdin token+profile → four HTTP results and retained public registry bytes | No call at import except definitions; invocation does HTTP. Output has statuses/hash, no token. |
| RefuseRedirects.redirect_request | readback-trellis-reviewed-v4.py:6–7 | Redirect → None | Prevents redirect following; does not replace proxy handler. |
| get | same:19–30 | Exact scope/bearer → status/body | Fixed 18198 loopback URL, percent-encoded scope, WOS tenant headers, 10s timeout; HTTP errors return status/empty body; network errors abort. |
| Maintained state_from_env | trellis-server/src/state.rs:419–475 | Strict profile+key+database env → server state | Auth profile validated first, then signing key, then DB pool/migrations; no TRELLIS_STORAGE selects Postgres; absent artifact variables retain default in-memory artifacts. |
| Maintained signing_key_registry | trellis-service-client/src/lib.rs:702–714 | Scope → registry bytes | Same /v1/scopes/{scope}/registries/signing-keys endpoint; actual positive qualification still requires provider-injected maintained client. |


## Data flow and invariants

Profile declares fixed four-part deployment tuple, exact issuer/subject/client to stable principal and action scopes. Grants repeat that tuple with an empty array: no case is admitted. Identity facts are configuration, not independently confirmed provider facts in this review. Current packet does not reuse case456 and correctly leaves fresh case and exact actor/human grants pending. No administer grant is silently introduced.

Launcher profile/grant/binary digests originate in constants/CLI and are compared before exec; database/key variables originate in the private unpinned JSON and escape into the child environment. It never prints that JSON. Readback token originates on stdin, escapes only into Authorization headers, and is excluded from result files; proxy inheritance currently broadens the network destination. Readback constructs unauthenticated, invalid-token, ungranted-scope and selected-scope requests; selected 200 plus expected raw030 digest is necessary for its success. With current empty grants, selected success is intentionally unavailable.

## Tests and concrete edge cases

No script tests found in the bounded packet. Both Python files pass AST parsing only, without import/invocation. Wrong binary/profile/grant digest normally asserts before exec, but optimized Python bypasses this. Same applies to wrong bind and unapproved empty grants. Redirect refusal exists; inherited proxies remain an uncovered forwarding path. Selected403 with deny-all grants produces failed readback, not positive admission proof. HTTP/network errors do not become successful receipts. A future fresh-case grant must reserve the negative scope as ungranted. Actual database/key migration effects and current caller token acquisition are unexecuted.

## Exploration record

H1 exact launcher pins cover every child-affecting input: REFUTED by unpinned database JSON. H2 all narrow-loopback HTTP controls are explicit: REFINED; redirects are refused, environment proxies remain active. H3 guards always enforce the described safety conditions: REFUTED by assert optimization semantics. H4 empty grants can prove positive provider admission: REFUTED; packet correctly states 403 is insufficient and requires maintained client200 after fresh-case selection. Next action: correct/pin the scripts and extra input, then rereview exact successor; no live execution needed for these corrections.

## Exact pins

| Input | SHA-256 |
|---|---|
| `oidc-profile.json` | `c8de0c4bfba003b93c2ef28a937a3e8bef1f21c3d12f26685af7a294c196e057` |
| `current-grants.json` | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |
| `start-trellis-reviewed-v4.py` | `2bb14db80ce183174c775d8675c448c7e94d949b7f38087ca140cccd65a5a18b` |
| `readback-trellis-reviewed-v4.py` | `cc1339fb7564d62b00ca4d18f56f3116fa7e5f41d621dff2ac06fd55777a2c0d` |
| `database.private.json` | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |
| public `trellis-18198-static-operator-preparation-v2.json` | `a19c9989e726368ed06a120e2b238dcaeded7e8ab93189d4b004ef0cd0aed48b` |

The four declared pins and packet SHA match. Profile/grants modes are0600; scripts0700. Private config contents remain private. No secret bytes were copied to this certificate. Binary pin remains f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7 as accepted by the final V4 qualification review; this operator review does not rerun the binary.

## Conclusion

VERDICT: REQUEST CHANGES.

The intended thin startup/readback preparation is feasible, but current source does not enforce all exact execution inputs and permits proxy/optimization bypasses. Coverage of changed paths: INSUFFICIENT for script execution; adequate to identify the concrete static blockers. Confidence: HIGH for these source traces and pin checks. Actual provider/DB/service/D1 outcomes remain pending. No source adoption, launch or live readback approval is granted.
