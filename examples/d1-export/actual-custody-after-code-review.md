# Authentication before replay — independent AFTER code review

Review ID: TRELLIS-AUTH-REPLAY-AFTER-CODE-2026-10-09. Reviewer: independent nonauthor `/root/oidc_code_review`. Method: full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`; applicable ms-rust review guidance and parent/Trellis CLAUDE instructions. Trellis AGENTS is a CLAUDE symlink. This review performs static inspection and verifies retained execution evidence; the reviewer ran no Cargo, native tests, network or live calls. Only this certificate was written. Other sources, locks and agents' edits were preserved.

## Findings

No blocking correctness finding remains for the exact scoped authentication correction.

F1 — OBSERVATION / security / state.rs:196,256 and auth_boundary_tests.rs:15,56: the qualified external path is dependency injection plus controlled current-verifier/grants. It does not install or qualify an actual host `OidcCurrentAuthority`, issuer/audience configuration, principal mapper or live resource/delegation authority. Evidence: tests return a synthetic verified identity and toggle controlled status/grant flags; state_from_env:418–517 continues its explicit local HS256 composition. Qualification accurately retains this boundary. A real host must select maintained current authority and authoritative mapping/grants before external production use; this is outside scoped local adoption.

F2 — OBSERVATION / test-coverage / http.rs:207,229,241: the selected native command exercises bundle reads and publication, but no selected test directly exercises external authorized/denied signing-key or event-type registry reads. Both call the same inspected read_authorized path. Legacy/dev branch tests and the broader workspace suite were not executed by this command. This limits coverage claims; it is not a blocker for the demonstrated replay fix.

F3 — OBSERVATION / evidence: source guards, Rust version, exact commands/environment, lock snapshots and logs are retained; no executed test-binary digest is recorded. Logs name their actual compiled private paths and Finished/Running stages. Treat this as retained local test evidence, not independently attested executable provenance or deployment proof.

Resolved review findings: actual two-principal replay-driver test, pinned-miss Administer refusal, unchanged-body delegation revocation, raw-byte conflict and JSON rejection tests are now present and passed. Read/Administer permit principal equality is enforced. The initial optional profile-verifier test counter would not run for CaseCreated; final v3 counts actual ArtifactStore writes instead (auth_boundary_tests.rs:413–475, lib.rs:288). This supersedes earlier static preflight expectations about that counter.

## Patch summary and exact scope

The baseline returned cached append responses before authenticating the current request. The eight-file patch moves current authentication, bounded body validation and exact host authorization outside replay middleware; passes the same parsed body to the handler; partitions the actual replay driver by admitted principal/full tenant/resource/action; and protects publication with Read plus Administer for the same internal principal. Existing explicit local-token/dev modes remain selected separately. One existing authorizer port and maintained shared authentication/replay interfaces carry the behavior; there is no second writer or consumer policy parser.

Base Trellis revision: `ea8f547367e4d41d09395001230ccf14705af8c9`. Shared stack-common HEAD inspected: `6aaba49911d80303ee883cfdcb329dce4999432c`. Tested source is `/Users/mikewolfd/Work/formspec-stack/.trellis-actual-custody-auth-green-v3`. Final adoption patch is `actual-custody-auth-qualified.patch`, not the earlier preflight diff against a RED-test baseline. I reconstructed every final unified-diff hunk against git-show of ea8f547 in memory; all eight resulting files equal the tested candidate, including both original RED tests. Private workspace/path repairs and temporary lock amendments are outside that production patch.

## Function traces

Relative paths in this section resolve beneath the tested candidate unless a shared path is stated. Inputs and output descriptions reflect code read, not names alone.

| Function / method | File:line | Inputs → outputs; verified callers and behavior |
|---|---|---|
| ScopeAuthorizer::authorize / AuthorizedScope | crates/trellis-server-ports/src/lib.rs:516–559 | Identity, exact full requested tuple and borrowed append body → host principal/tuple/action or error. Port result replaces unit; headers/scopes alone are not external grants. |
| router | crates/trellis-server/src/http.rs:26 | State → router after posture check; final route_layer wraps idempotency with authorize_append. Axum source confirms last layer is outermost. |
| authorize_append / admit_append | src/auth.rs:21,34 | State/path/TenantScope/request → refusal or next request. Calls async authenticate, validators, host action; parses once with maintained Json, inserts AuthorizedAppend and TrustedReplayPartition, restores original bytes. |
| authorize_action | src/auth.rs:87 | Verified request facts/body + requested action → exact host permit. Rejects empty principal and any foreign tenant/scope/action; forwards full original body for transport actor and payload human delegation. |
| authorize_publication | src/auth.rs:123 | Identity + admitted Read permit → same-resource Administer permit or refusal. Requires identical internal principal before publication. Called by head and pinned miss. |
| append_event | src/http.rs:89 | AuthorizedAppend extension → AppendCommand → append_runner. No reparse or alternate authorization body. |
| head_bundle / pinned_bundle | src/http.rs:119,159 | Read-authorized request → bundle bytes. Head additionally authorizes publication; existing pinned record only reads; miss additionally authorizes publication before publish_bundle. |
| signing_key_registry / event_type_registry / read_authorized | src/http.rs:207,229,241 | Scope, full tenant, headers → authenticated exact Read permit; registry outputs or identity/permit tuple. Both registry routes share this gate. |
| validation helpers | src/http.rs:288,304,320,338 | Header/body/path → error or unit. Header key must equal body key, compute sensitivity publicMetadata, attestation nonempty, scope one ASCII path segment. These helpers now run before replay. |
| Authentication / AuthenticatedRequest helpers | src/state.rs:44,59,67,74 | Explicit unconfigured/local/external selection; actor uses local subject/external subject/anonymous fallback, external identity and local scopes stay separate. |
| new/in_memory and verifier setters | src/state.rs:109,118,185,196 | State construction starts explicit dev unconfigured; setters replace authentication selection, never fall back on token rejection. with_scope_authorizer:211 marks built-in allow-all replaced. |
| ensure_serving_posture_twref022 | src/state.rs:224 | State → serving permission/refusal. External mode rejects built-in allow-all regardless of production flag; production-like mode requires injected authorizer and configured authentication. Called by router. |
| authenticate | src/state.rs:256 | Headers → request-local identity or error. Unconfigured explicit dev returns Anonymous; selected modes require nonempty Bearer. External rejection maps 401 and unavailability 503, without provider/token text. |
| reserve/record HTTP idempotency / tenant_replay_scope | src/state.rs:321,341,382 | IdempotencyCall → actual replay-store lookup/write using identical derived scope. Trusted partition uses length prefix plus HTTP route; fallback is for legacy contexts. |
| AllowAll/ScopedAllowlist authorize / legacy_permit | src/admission.rs:24,40,72 | Explicit dev/local request → copied exact legacy permit; scoped implementation requires local JWT scopes containing URL scope. External mode cannot receive these local scopes. |
| state_from_env / JWT config | src/state.rs:418,509 | Env → maintained local startup; expiration true, no issuer/audience selection. External host composition is separate and unqualified. |
| shared run_idempotency | stack-common/crates/stack-common-http/src/idempotency.rs:276 | Original bytes → hash, request extension → replay_partition at :302; actual driver reservation precedes cached return at :310; fresh request retains AuthorizedAppend extension. |
| shared AccessTokenVerifier / OidcCurrentAuthority | stack-common/crates/stack-common-auth/src/access_token.rs:16; oidc/introspection.rs:48,95 | Interface returns verified external facts; maintained current authority verifies then introspects original token each call and checks active/matching facts. Trellis injection does not prove host selected it. |
| append coordinator / bundle publication | src/append.rs:99; src/lib.rs:190,288 | Authorized command → maintained admission/Core append/publish. Service auth remains separate from signing key, event integrity and case access. Actual artifact put_immutable is unconditional after verification, enabling meaningful counter. |
| controlled verifier / grants / state | src/auth_boundary_tests.rs:15,56,125 | Test token/status/full request → synthetic identity/exact internal permit or refusal. Current mapping/grants/delegation toggles model the port; no actual identity-provider call. |
| CountingPublicationStore | src/auth_boundary_tests.rs:416 | put/put_immutable increments then forwards; get forwards. Preserves InMemoryArtifactStore behavior while observing denied-publication side effects. |
| original helpers and RED tests | src/lib.rs:1154,1170,1199,2607 | Existing public fixture signing key and actual CaseCreated/Core/router append; no real D1 history. Retry same key/body with missing or foreign-scope credentials exercises outer-cache boundary. |

## Data flow and invariants

Verified identity is created anew in authenticate per request; it is borrowed by host authorization and does not become a bearer capability. Original parsed body is created by Json in admit_append, validated and borrowed by ScopeAuthorization, then moved into AuthorizedAppend. The handler consumes that same body. Raw bytes are captured under 2 MiB and restored unchanged; shared hashing sees the original encoding, not serde reserialization. Authentication/grant failures occur before replay-store access, so a previously cached receipt cannot bypass current authority.

AuthorizedScope originates only from the configured host port. The HTTP boundary checks its nonempty principal and equality of all four tenant dimensions, scope and action. Publication gets a second permit for Administer and compares its principal to the admitted reader. TrustedReplayPartition serializes only internal principal, admitted tenant, scope and action, without bearer tokens. The driver derives the same length-prefixed scope for lookup and write. Same tuple/principal may replay; a different admitted principal reaches an independent HTTP replay partition while underlying semantic event idempotency still prevents duplicate append.

The URL scope remains the ledger/storage identity used by repositories, locks and signing. Host mapping must bind that globally unique ledger identity to its admitted tenant context; this patch does not create tenant-specific repositories or allow headers to redefine ledger identity. Authentication does not establish WOS relationship grants, payload-human delegation or export disclosure policy by itself; the injected host authorizer owns these decisions. Current verification can add dependency latency; no speed/resource improvement is claimed. RED/GREEN timings use different cache states and are diagnostic only.

## Tests and concrete edge cases

Reviewer-executed tests: **none**. Retained actual command in both candidates: `cargo test --offline --locked -j1 -p trellis-server authorized_append_replay_ -- --nocapture`, rustc 1.89.0. RED exit 101: zero passes, two intended assertion failures, cached 201 versus expected 401/403. GREEN exit 0: fourteen passes, zero failures, 89 lib tests filtered. Other binaries/integration targets run zero selected tests; no whole-workspace, Clippy or broader-regression pass is inferred.

All names below begin `authorized_append_replay_`; each full name is selected by that prefix. Source locations refer to auth_boundary_tests.rs except the two lib.rs rows.

| Test suffix / location | Inspected assertion trace and retained outcome |
|---|---|
| without_bearer_is_unauthorized — lib.rs:1170 | First actual Core append 201, retry lacks bearer →401/no replay, repository one event. RED201 mismatch; GREEN pass. |
| with_other_scope_is_forbidden — lib.rs:1199 | First201, retry valid local token missing scope →403/no replay, one event. RED201 mismatch; GREEN pass. |
| rechecks_current_identity_and_grants — :166 | Authorized replay identical bytes then controlled rejected401/unavailable503/revoked-grant403; verifier5/grants3 calls and one event. GREEN pass. |
| refuses_each_foreign_tenant_and_actor — :205 | Mutates each of four tenant headers and asserted transport actor;403, one event. GREEN pass. |
| refuses_mismatched_authorizer_result — :246 | Empty principal/foreign workspace/scope/action each403 before any event. GREEN pass. |
| head_publication_requires_administer — :265 | Read-only head403, existing pinned200, granted Administer head200. GREEN pass. |
| refuses_ungranted_payload_human — :307 | Granted actorId append201, changed human403, one event. GREEN pass. |
| external_mode_requires_injected_host_grants — :334 | External verifier with built-in allow-all fails router construction. GREEN pass. |
| external_mode_has_no_local_jwt_fallback — :348 | Local HS256 token in external selection →401/no event. GREEN pass. |
| separates_two_admitted_principals — :368 | A append, B admitted same key/body has no replay header, B subsequent replay true, A replay true, one semantic event. GREEN pass. |
| rechecks_delegation_for_unchanged_body — :394 | First201; revoke delegation, exact cached-body retry403/no replay. GREEN pass. |
| publication_refuses_changed_principal_and_pinned_miss — :413 | Actual artifact-write baseline positive; head and missing pinned Read-only403; then different Administer principal403; all leave write count unchanged. GREEN pass. |
| hashes_original_body_bytes — :479 | Semantically same pretty JSON differs in raw bytes; retry409. GREEN pass. |
| preserves_json_rejections_without_append — :501 | Text/plain415, syntax400, missing fields422, >2MiB413; no repository event. GREEN pass. |

Concrete limits: selected tests cover scoped local failures and controlled external mode; no live OIDC or grants. Registry Read calls are statically covered by the shared gate, not selected native assertions. Existing legacy authorizer tests were inspected at admission.rs:98,116,136 but filtered. Foreign tenant refusal and publication lack/mismatched grants are security-sensitive and tested; malformed-body errors are low impact and tested. Other transport read errors map through the body-capture failure path and were not independently exercised.

## Execution provenance and preserved prerequisites

The retained v1 setup failed on duplicate private/original trellis-types package paths; v2 failed on multiple nested workspace roots. Neither reached behavioral assertions. V3 excludes copied integrity-verify from outer workspace membership while preserving its bytes; metadata then required only the existing stack-common-auth→async-trait lock edge. Actual RED uses resolved lock e8db9355…; GREEN uses 2b329736… with that edge plus ports→auth/http. I compared complete parsed lock package records: only these dependency lists change; no package count, version, source or checksum change. Starting lock34de1753… remains restored in both private candidates at review time.

Actual receipts have exact argv/cwd, selected build environment, rustc version, finite600-second/log limits, full guard hashes, resolved/start locks, log hashes, group absence and restoration. Source guards currently match all1464 RED and1466 GREEN receipt entries; frozen GREEN packet1463 entries also match. Runner code verifies original lock/pin map before spawning an owned session; finally performs bounded TERM/KILL cleanup and nested unconditional lock restoration/receipt emission. Recorded groups35152 and45299 are absent in the receipts; no process check or native activity was repeated by this reviewer. Logs show Finished/Running, actual private compile paths and intended assertions. Qualification states these limits accurately.

## Exploration notes

H1 cache bypass is corrected only if auth wraps replay, not if handler repeats it. CONFIRMED by route layering plus actual RED/GREEN assertions and shared cached-return trace.

H2 admitted headers or returned permits alone could isolate tenants/principals. REFINED: exact host permit must match requested context; actual driver must consume TrustedReplayPartition. Both are traced and controlled negative/dual-principal tests passed. Global ledger identity remains a host mapping prerequisite.

H3 moved body parsing could alter replay hashes or accepted JSON errors. REFUTED for covered scenarios: original bytes are restored and raw-encoding409 plus415/400/422/413 tests passed.

H4 two publication grants could resolve different internal principals. REFUTED by explicit equality and native mismatch denial; actual artifact counter establishes no publication writes. Previous optional-profile counter expectation was wrong and is corrected here.

H5 successful injected tests qualify real current OIDC authority/deployment. REFUTED: controlled implementations only; actual host selection and grants remain outside acceptance.

## Exact evidence and source pins

SHA-256 values below bind bytes, not deployment or whole-tree cleanliness. Full transitive source/fixture maps are retained in the exact source packet and execution receipts rather than duplicated here.

| Artifact | SHA-256 |
|---|---|
| `actual-custody-auth-after-inputs.json` | `fbae264d498dd79cbea84a4b557d16be58ea9295770ed9d733bfab2c2b70dd03` |
| `actual-custody-auth-qualified.patch` | `80b7345d571730c0d23b5a7bae0b294eb0656887a762fb9def3b28cba3bac1bf` |
| `actual-custody-auth-qualification.md` | `a54736528ad928e471b1a7d36e6539e9809bea7d7b918f04bd35c6241279a8d4` |
| `actual-custody-auth-green-v3-preflight-pins.json` | `39d722dda0a8e7cfd4ecf3987e9c5beb20db8d643d989b1af148382e73cfd47c` |
| `actual-custody-auth-red-v3-run/auth-red-locked-receipt.json` | `d9044143c7d137d045134463f449cba769a6cbdb5ef29b6cc5ecea0579e774e1` |
| `actual-custody-auth-red-v3-run/auth-red-locked.log` | `90bfcaa8a751c764e66a3530e5349b7f040cd0b3e6c29e10a5ec4ff1f8727708` |
| `actual-custody-auth-green-v3-run/auth-green-locked-receipt.json` | `3da38c3d69983681d4e8b591afd33f392ff8611ecb14b11cf2d2a6c63379b903` |
| `actual-custody-auth-green-v3-run/auth-green-locked.log` | `a67cb11cf4ba2bfd9405538a9476ca30587e02a137386fa5fa899aecd7208999` |
| `actual-custody-auth-red-v3-setup/setup-receipt.json` | `f8f934b882b44bd6144163f5c4c1cc71e1703e98740aecafc31865e25f198a1d` |
| `actual-custody-auth-green-v3-setup/setup-receipt.json` | `9b058f8b236db4b8553beebca3372630cd8befecba69cac8eaa45dc56a87f6d1` |
| `actual-custody-auth-red-run/auth-red-locked-receipt.json` | `6495c1050d23dd06a3e410d8b22e2228959b179f8f6da22fd7ed0f57d284a000` |
| `actual-custody-auth-red-v2-run/auth-red-locked-receipt.json` | `5af4d7fa9c95a71a81cd772a2227bc511d51f8f9be522dafaac08066c30d97a6` |

| Tested production file | SHA-256 |
|---|---|
| `crates/trellis-server-ports/Cargo.toml` | `4e34203242c94fe6d1bb4571d802707cc057bf6badde4be6661df0eaf2603995` |
| `crates/trellis-server-ports/src/lib.rs` | `9044bbb611e496df7a1b46d00779d9d339e289253b15e9412ee1bea2f1bc8a21` |
| `crates/trellis-server/src/lib.rs` | `a7fd089cc1b5254cd656bc7400336f0933387cfe103dd945ca8b8dfbee9ca896` |
| `crates/trellis-server/src/state.rs` | `eecc34672601abc415a48ca7afedb00405f6d759ada028bf264ba4b307e84d58` |
| `crates/trellis-server/src/admission.rs` | `4878dd194aba4a4c292409d2e12d1d62c2961b537234273ade34926049d90503` |
| `crates/trellis-server/src/http.rs` | `7aa3688c7bb62977f2c8ffd9cf57fae3b33376fddc436857adf0a665d4ad1d44` |
| `crates/trellis-server/src/auth.rs` | `90a84b5690b6cedc43456fa041fd6b3f45b272d02dfaf3b1944598fc450d24c2` |
| `crates/trellis-server/src/auth_boundary_tests.rs` | `0efe45d6d67d7de21b216a7f8d4eb1ea828dcabb446b52d69dcd299a630aaba2` |

## Conclusion

VERDICT: APPROVE the exact eight-file authentication patch and scoped local checkpoint, subject to owner adoption of these exact reviewed bytes.

Justification:
- The patch achieves current authentication and exact authorization before append replay; actual baseline failures and fourteen corrected tests substantiate the changed paths.
- Coverage of the scoped replay/publication/parser correction: ADEQUATE. Broader legacy/registry regression coverage and actual host OIDC/grants/deployment/full D1 qualification: INSUFFICIENT and explicitly outside this verdict.
- Confidence: HIGH for the scoped implementation and retained local results; no production or full-custody claim.
