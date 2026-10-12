# Trellis OIDC startup and current-token client — independent AFTER static review

Review ID: TRELLIS-OIDC-STARTUP-AFTER-STATIC-V3-2026-10-09. Independent nonauthor `/root/oidc_code_review`; full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, applicable ms-rust application/universal/resilience guidance and parent/Trellis instructions. Scope is the frozen eleven-file implementation against `eda346c166a71c7b8df55afd8549247456229277` at `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`. Only this certificate written. No Cargo/compiler/metadata, test/binary execution, provider, database, live, adoption or source/lock actions performed by reviewer.

## Findings

**APPROVE exact v3 source for conditional static readiness only.** No remaining blocking source finding was identified. Compilation, dependency reconciliation, actual RED/GREEN, existing auth regressions, binary startup and isolated host qualification remain pending. This is not final implementation/native acceptance.

F1 — RESOLVED / correctness / crates/trellis-service-client/src/current_token_tests.rs:1 and lib.rs:849–850. Frozen v1 inserted a file starting with an inner doc comment through include!, a likely E0753 compile failure. V2/V3 use an ordinary comment, matching the server included test file. This is static resolution; no compiler result is claimed.

F2 — RESOLVED / test-coverage / crates/trellis-server/tests/oidc_cli_startup.rs:34 onward. Initial two CLI tests returned at missing-profile selection and did not exercise actual legacy-setting refusal. V3 retains them and adds each legacy flag independently, empty/nonempty values, and a nonempty profile-path setting; it asserts legacy refusal before key/storage. This directly reaches oidc_startup.rs:41–46 without requiring real credentials or storage.

F3 — RESOLVED / correctness / crates/trellis-server/src/lib.rs:24–26,1089 and production-posture assertions. Stale CLI HS256 prose and assertion strings conflicted with the new path; bounded V2 changes align them with strict OIDC/exact grants. Programmatic local DI remains available and its tests remain meaningful.

F4 — OBSERVATION / test-coverage. New tests are all unexecuted. The existing14 auth tests have not been rerun; no whole graph or actual Okta/Keycloak provider/DB startup is qualified. Existing shared protocol tests support API feasibility, not execution acceptance. Exact dependency lock is still unprepared. These are explicit next gates, not PASS evidence.

F5 — OBSERVATION / security boundary / oidc_startup.rs:430–464 and OIDC_STARTUP.md. Unix opened-descriptor checks enforce regular file, effective-user ownership and no group/other mode bits; final symlinks refuse. Parent-directory control and atomic whole-grant-file replacement remain operator obligations. Other platforms fail closed. Permanent dedicated DB/profile tuple is documented rather than persisted or migration-enforced; shared DB across deployment tuples is unsupported. No no-swap, agency trust or D1 claim follows.

## Patch summary

StartupAuth now prepares required strict auth before signing-key reads or DB pool/migrations. It composes maintained RS256 verifier and original-token current introspection, then installs an exact resource-grant authorizer through existing ports. Immutable profile holds issuer/audience/client/base scope, fixed deployment tuple, stable external identity map and action scope policy. Each authorization reads a new complete grant file, validates its whole authority set, then grants the exact principal/resource/action/actor/delegation or refuses. No business-event branching or new generic authorization port was added.

The outbound client adds one optional maintained ClientCredentialsTokenProvider. It acquires once per request at the shared request builder, rejects mixed static/provider credentials, caches no local tokens, disables redirects and redacts configured bearer Debug. All five SubstrateClient public signatures remain unchanged. Server Cargo enables existing shared oidc feature and Unix rustix fs/process APIs; client Cargo adds shared auth with its default-empty feature set. Lock preparation is pending.

## Function trace

Paths below are within the private source root unless explicitly marked shared. Every touched file, implementation, test and documentation was read; unchanged behavior-critical callees were traced in the preceding reviews and checked here as relevant.

| Function / seam | File:line | Inputs → outputs; verified behavior |
|---|---|---|
| state_from_env / main | crates/trellis-server/src/state.rs:417; main.rs:14 | Calls StartupAuth::from_env before key read and storage; builds existing state then applies strict verifier/authorizer. Removed CLI memory/permissive/HS256 branch. |
| StartupAuth::from_env | crates/trellis-server/src/oidc_startup.rs:37 | Requires profile setting, refuses either legacy variable even empty; constructs maintained HTTP/clock deps then load. No key/DB effects occur first. |
| StartupAuth::load / apply | same:57,111 | Closed profile→validation→bounded private secret→StaticClientSecret→OidcAccessTokenVerifier→OidcCurrentAuthority; validates initial grants, injects both ports and production posture. No custom token parser. |
| Profile::validate / Deployment::validate,tuple | same:190,164,156 | Nonempty bounded fields; unique scopes/clients/identities; exact configured issuer/client; complete actionScopes; fixed tuple conversion. Duplicate identity mapping refuses. |
| CurrentGrants::load_grants / validate_current | same:297,304 | Closed bounded file; exact profile tuple, known principal, unique principal/resource/action, validated scope. Append requires unique kind+subject actors and unique valid selectors; other actions refuse append rules. Empty grants revoke all. |
| CurrentGrants::authorize | same:354 | Requires verified external identity and exact deployment; resolves immutable principal; action scope must match verified scopes; fresh spawn_blocking read and whole-file validation; exact row plus actor pair/payload selector check; returns exact AuthorizedScope. Missing grants403; malformed/unavailable file503. |
| read_private | same:431 | rustix open RDONLY/CLOEXEC/NOFOLLOW/NONBLOCK; metadata/read use same descriptor; regular file/private mode/effective uid check, capped1MiB+1 read. Sanitized refusal. Non-Unix:461 always refuses. |
| nonempty / unique_nonempty / validate_pointer | same:466,474,488 | Bounded nonblank/control-free strings, duplicate rejection, slash-prefixed pointer with only ~0/~1 escapes. Optional malformed selector refuses at load before lookup. |
| Action::port / invalid / denied | same:255,502,505 | Exact action conversion and sanitized400/403 errors; no raw profile, token, secret or payload in diagnostics. |
| admit_append / authorize_action | crates/trellis-server/src/auth.rs:34,87 | Existing auth-before-replay boundary passes exact parsed original body, checks returned tuple, creates trusted partition and restores raw bytes. New adapter plugs into this unchanged path. |
| authorize_publication | crates/trellis-server/src/auth.rs:123 | Existing Read then Administer check requires same internal principal. Static identity map cannot change principal between the current grants checks. |
| state posture / old allowlist | crates/trellis-server/src/state.rs:230; admission.rs:38 | Posture rejects AllowAll/unconfigured auth. Former scope-label authorizer becomes test-only; AllowAll/manual verifier DI is retained for explicit programmatic use. |
| config/client Debug | crates/trellis-service-client/src/lib.rs:489,536 | Config bearer formatted only as REDACTED; client prints provider configured marker, not provider internals. No Debug requirement added to token-provider trait. |
| TrellisServiceClient::new / with_token_provider | same:553,580 | Shared reqwest client disables redirects, retains timeout; Some(static) rejects provider even empty static. Otherwise provider stored as Arc; cloning shares provider, no token stored. |
| request | same:597 | Tenant headers+method/path→builder; provider.access_token awaited once then expose_secret for Authorization; any failure sanitized and returns before send. Static-only compatibility else branch retained. |
| append_event / event_type_registry / bytes_get | same:634,719,758 | All actual request-builder call sites await? before send; bytes_get serves head/pinned bundle/signing registry. Thus all five public methods acquire per attempt and non-2xx refuses. |
| shared maintained adapters | stack-common-auth oidc/verifier.rs:133, introspection.rs:32,47; transport.rs:98; credentials.rs:117 | Fixed issuer/profile/scope/client, real RS256/JWKS, original-token current introspection with no positive cache; bounded TLS/no-redirect transport and redacted fixed secret. Local rustix1.1.4 open/geteuid signatures match usage. |

## Data flow and invariants

Profile and credentials are loaded before key or database work. Private read checks the descriptor it actually reads, avoiding check-one-file/read-another final-component substitution. NONBLOCK allows FIFO/device descriptors to be rejected before reading; only regular files proceed. Content is bounded even if file grows. Immutable profile holds identity/deployment/action policy. Grant data is request-local and discarded; no admitted grant survives for a later retry. Whole-file invalidity refuses rather than selecting a valid-looking row from malformed authority.

External verified issuer/subject/client map to one stable principal. Requested four-component tuple must equal static profile; grant document must equal it too. OAuth action scope and exact local row are independently required. No token scope alone grants a case. Append must match exact asserted actor kind+subject; required selector absent/null/nontext/foreign subject refuses, optional absent accepts. Selectors are relative to opaque payload and never rewrite it. Producer owners remain responsible for selecting all required human fields; Trellis does not infer application semantics.

Existing auth middleware runs before replay and passes the same parsed body to handler; raw replay bytes are restored unchanged. A newly revoked actor/grant/delegation fails before cached response. Read and possible publication are separate current authorizations for the same stable principal. Canonical signing validity/export evidence and user authority remain independent.

Outbound request holds no prior token. Provider owns acquisition, identity/audience/scopes/renewal and its own safe cache. Client obtains its returned current token for every attempt; failure cannot fall back to static or last-success token. Validation occurs before acquisition where existing methods validate inputs. Redirect policy prevents all credential forwarding to a second URL. The HTTP timeout covers the HTTP request; provider acquisition timing remains provider/application responsibility. No performance claim is made for grant-file reloading; spawn_blocking avoids synchronous file I/O on async workers, while bounded parsing/validation stays request-local.

## Test behavior and edge cases

Reviewer executed: **none**. No retained native results for this patch exist. Tests below are source assertions and predicted intent, not PASS reports.

Server tests `oidc_startup_tests.rs` use actual RSA signed JWT, injected discovery/JWKS/introspection and fixed AuthClock through the same StartupAuth::load used by CLI. They do not substitute a preverified identity. ProtocolHttp checks introspection POST/header, returns matching current facts, and counts introspections; shared tests additionally assert exact original-token/Basic body and redaction.

| Test | File:line | Assertion path / expected behavior after patch |
|---|---|---|
| changed_actor_kind_grant_blocks_the_same_cached_body | crates/trellis-server/src/oidc_startup_tests.rs:162 | First append201; grant kind changes only; identical body retry403 before replay. |
| required_payload_selector_refuses_missing_nontext_and_foreign_human | same:184 | Required selector; missing, integer, foreign text all403. |
| head_requires_current_read_and_administer_grants | same:207 | Append then head200; remove Administer; next head403 despite Read. |
| real_protocol_rechecks_token_and_current_case_grant_before_replay | same:246 | Actual signed append201; empty grants retry403; inactive provider401; introspections count3. |
| protocol_refuses_wrong_issuer_audience_client_or_base_scope | same:279 | Signed bad issuer/audience/client/base scope/expired token401. |
| action_scope_is_required_beyond_base_oauth_access | same:303 | Valid provider/base but absent append scope403. |
| refuses_foreign_tenant_component_scope_and_actor_kind | same:318 | Mutates each tuple component, case resource, then actor kind; all403. |
| revoked_payload_delegation_blocks_unchanged_cached_retry | same:355 | First delegated append201; allowed human removed; exact bytes retry403. |
| closed_profile_and_current_grant_validation_refuse_ambiguous_authority | same:379 | Foreign grant tuple, unknown principal, duplicate row, malformed optional pointer, nonappend actor rule, repeated subjects, unknown field, duplicate identity all startup error. |
| unavailable_or_invalid_current_grants_fail_closed_after_admission | same:416 | After state composition, malformed then missing current file gives503. |
| rejects_duplicate_fields_in_profile_and_grants | same:440 | Duplicate known top-level fields fail typed serde loading. |
| private_files_reject_shared_permissions_and_symlinks | same:463 | Unix secret0644 and final grant symlink refuse. |
| CLI profile/legacy selection tests | crates/trellis-server/tests/oidc_cli_startup.rs:13,23,34 | Actual child binary: missing profile fails before key; legacy flags cannot bypass; each empty/nonempty legacy flag with profile setting reaches explicit refusal before profile/key/storage. |
| all_five_operations_acquire_changed_current_tokens_once_each | crates/trellis-service-client/src/current_token_tests.rs:55 | Real local HTTP fixtures see five different token values on five routes, provider callcount5, valid responses. |
| failed_provider_and_invalid_input_send_zero_http_and_never_reuse_prior_token | same:140 | One successful request; invalid input skips provider; next provider failure sends zero HTTP/no old token. |
| provider_rejects_every_static_bearer_and_debug_redacts_credentials | same:176 | Empty/space/value static settings reject provider, Debug redacts, no acquisition at configuration. |
| redirects_fail_without_forwarding_credentials_or_acquiring_again | same:193 | First endpoint302, target zero hits, one acquisition, result error. |

Coverage limits: explicit oversized/private-file owner/FIFO and positive escaped-pointer cases are not new tests here; their straightforward bounded descriptor/parser branches were statically traced. Provider transport/time/cache limits have shared tests, but new startup integration still needs execution. New tests use controlled CaseCreated inputs/public RSA fixture, not actual D1 human facts or production keys. The private build closure must include the maintained sibling fixture path used by include_bytes; source test/module imports were inspected. Any compiler/framework failure remains possible until native checks. Existing14auth regression tests and complete client suite must rerun after lock preparation; fresh binary/provider/isolated DB evidence remains separate.

## Exploration record and finding history

H1 startup still opens key/DB before required auth. REFUTED in implementation: state_from_env prepares StartupAuth first and has no CLI HS/permissive branch.
H2 local grant authorizer might trust tenant headers/OAuth scopes or stale positive grants. REFUTED: immutable exact deployment/identity/action policy plus whole fresh file and exact row/body matching precede each permit.
H3 subject-only actor hole or malformed optional-pointer bypass remains. REFUTED by pair equality and load-time pointer validation; source tests target both.
H4 new client covers only append. REFUTED by all three request-builder sites and all-five-method test; failure returns before send, no token field/cache exists.
H5 v1 included test compiles as written. REFUTED statically by inner-doc include pattern; v2 ordinary-comment correction retained. Native confirmation pending.
H6 original CLI flags test covered the rejection branch. REFUTED: missing profile returned first. V3 explicit profile-path test covers branch and each flag/value independently.

V1 retained receipt922f71f2…/patchb4df1193… records original defects. V2 receipt295dfcef…/patch9feaec54… changes only serverlib docs/posture assertions and client included-test comment. V3 changes only CLI test file relative to V2. All eleven current source pins and both exact V3 packet/patch hashes match. Lock remains unchanged/unprepared; no additional source mutation performed by reviewer.

## Exact pins

| Input | SHA-256 |
|---|---|
| BEFORE v2 proposal | `85b72909bc5a52fa7d844ed60eb7ee2416b74b23409ff6a01c59e335a569a02a` |
| V3 static packet | `807d68d1ec51442d11eb4a1562977493ab5c9ea634bd6566e19a86fa1727db96` |
| V3 eleven-file patch | `be0863e1f6c8c49e4ed2385c7e4cf6997eeff0cb38f3f76047b0d5dcc0b2587a` |
| `crates/trellis-server/Cargo.toml` | `4a3e5e7c0bb6da967925532cf89358281c4ddf5ff7d40f1cf2e556639c9fc7ad` |
| `crates/trellis-server/OIDC_STARTUP.md` | `77936e19b927f3f91139f6fa14fe2e2ca3781a7aa0f835803052cfe86c9c5eef` |
| `crates/trellis-server/src/admission.rs` | `8ebfd2d5792a9673096e020d2e5aee61a12519143f0b5e84e71583fb257e60f1` |
| `crates/trellis-server/src/lib.rs` | `834670571ae2e9e5e383cd04129ebe311e6749fc106d35cad4af88cc3a87c91c` |
| `crates/trellis-server/src/oidc_startup.rs` | `71dd47b97397db3c413fae946d426a9216fdb875a9d72f083550b910d368ea63` |
| `crates/trellis-server/src/oidc_startup_tests.rs` | `da70d20f01e57a4c72177b82b6c5c0a338d994c275fe72aba2fcb417626fd5fc` |
| `crates/trellis-server/src/state.rs` | `440872a0ddbb9fb7ee663ded420db48fbd79c3516045a9d4f410cbec023e534c` |
| `crates/trellis-server/tests/oidc_cli_startup.rs` | `f795d5945dd7c161502ddb129a0b2624875c1a8a6ad65a520b14ba34478670ee` |
| `crates/trellis-service-client/Cargo.toml` | `d25b4d39ec0c051f6bf804c46e498bfe6c45f5a83f4dbee17a1107b1a33e288c` |
| `crates/trellis-service-client/src/current_token_tests.rs` | `59759695fb7d8d6fb2d7ca5ec434dceaa52eede1d69fe282b7145f8d8d988421` |
| `crates/trellis-service-client/src/lib.rs` | `13391c903ffc076bb6f23f979c8d87f79c0c1f81ed5bd6040bd6a53e8b09095e` |

Inspected sibling source identities remain those bound in BEFORE-v2 certificate: stack-common6aaba49911d80303ee883cfdcb329dce4999432c with verifierd853dc7c…/introspection368e1a19…/transport2c33b9c4…/credentials9173c38f…; its maintained API, not private missing sibling copies, supplied static source. No sibling execution or full sibling acceptance is implied.

## Conclusion

VERDICT: APPROVE exact V3 conditional static readiness only.

Justification:
- The implementation follows approved strict startup/current exact grants and thin current-token client design; identified source/test integration defects are corrected.
- Coverage of changed source paths: ADEQUATE for static review. Compile/lock/native regression/protocol/binary/host qualification: INSUFFICIENT and pending by explicit execution restriction.
- Confidence: HIGH for inspected source/data-flow/pin checks, MEDIUM for uncompiled implementation. No production deployment, actual agency trust, D1 provider completion or runtime acceptance is granted.
