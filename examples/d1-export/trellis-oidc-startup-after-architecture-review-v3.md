# Trellis OIDC startup and current-token client: static AFTER architecture review v3

**VERDICT: APPROVE the exact v3 combined architecture for native qualification.** Startup composes maintained current token verification with current host grants through existing ports; outbound calls use the maintained token-provider interface. V2 corrects the three frozen-v1 source/test issues identified during paired review; v3 adds direct CLI coverage of legacy-setting refusal. This is static conditional acceptance: no compiler, native RED/GREEN, existing14 authentication regressions, executable build, provider/database readback or deployment qualification has occurred in this gate.

Reviewer `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` applied. Only this certificate written. No Cargo/compiler/metadata/native/provider/DB/live operation or source edit was performed.

## 1. Artifact summary

Private source `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`, base `eda346c166a71c7b8df55afd8549247456229277`. Exact frozen packet `trellis-oidc-startup-static-after-v3.json` SHA-256 `807d68d1ec51442d11eb4a1562977493ab5c9ea634bd6566e19a86fa1727db96`; patch SHA-256 `be0863e1f6c8c49e4ed2385c7e4cf6997eeff0cb38f3f76047b0d5dcc0b2587a`. All11 source/document/manifest hashes independently match v3. V2 changed only server `lib.rs` and client `current_token_tests.rs` from preserved v1 packet `922f71f20ed33b8d39124340d112ba15292acb5ffa2b2f4664fc6d841fc79b71` / patch `b4df11934c2b739894617b42ca66b75824a8ac330821b04edd30fcd68b8a40fd`.

Category: executable authentication boundary, host authorization adapter and outbound credential composition. Beneficiaries: operators needing the actual receiving API to enforce current provider identity and local case grants, and service producers needing current workload tokens without hardcoded bearer configuration. The design remains provider-neutral at shared interfaces and application-neutral in Trellis.

## 2. Lineage and relationship tables

| Prior artifact | Relationship | Citation |
| --- | --- | --- |
| Approved startup BEFORE v2 | Fixed deployment, static mappings/action scopes, current resource grants | `trellis-oidc-startup-before-architecture-review-v2.md`, SHA `12f0c1c56b4e6a7d0e8371c10451cb601db6d899a002c5edadbe624d1c334a41` |
| Thin-client BEFORE constraints | Per-call provider, no cache/fallback, unchanged five public operations | Explicit paired task approval; shared `ClientCredentialsTokenProvider` |
| Root production goal | Current governed access and independent evidence | `GOAL.md:Target Deployment Profile`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Formspec startup pattern | Fixed selected preparation before repository construction | `formspec-server/crates/formspec-server/src/auth_config.rs:180–205` |
| WOS mapping pattern | Local principals/deployment membership separate from provider claims | `workspec-server/crates/wos-server/src/auth/profile.rs:157–217,245–261` |
| Existing exact authorization | Same validated body, tenant/identity/action before replay and publication | private `trellis-server/src/auth.rs:35–118,126–153`; `trellis-server-ports/src/lib.rs:514–559` |
| Shared provider primitives | Protocol and token lifecycle owner | `stack-common/crates/stack-common-auth/src/oidc/{verifier,introspection,transport,credentials}.rs`; `src/client_credentials.rs:1–73` |

| Component / named seam | Owner | Depends on | Consumed by |
| --- | --- | --- | --- |
| StartupAuth / state composition | Trellis executable host | Operator profile, shared current authority | Existing router/auth ports |
| CurrentGrants / ScopeAuthorizer | Trellis host/operator | Fixed identity+quad/action policy; fresh resource/delegation file | Pre-replay append and read/publication |
| Current authority / AccessTokenVerifier | stack-common | Fixed trust, HTTP, clock and confidential introspection client | Receiving auth |
| with_token_provider / request | Trellis HTTP adapter | Maintained ClientCredentialsTokenProvider | Five SubstrateClient operations |
| OidcClientCredentials and custody startup | WOS composition owner | Issuer/client/audience/scopes/credentials and actual native facts | Outbound injected provider |
| Dedicated DB/profile association | Operator deployment | Permanent one-quad configuration | Existing scope-only ledger |
| Case-grant registration and legal authority | Application/deployment owners | Actual case lifecycle / independent accepted authority | Explicitly outside this change |

No duplicate SDK, provider protocol implementation, permission port or consumer-specific data interpretation is introduced.

## 3. Invariants and commitments

1. **Strict startup precedes side effects — PRESERVED in source.** `state.rs:415–422` calls StartupAuth before key reads/DB work. `oidc_startup.rs:37–54` requires profile and rejects any legacy env setting, even empty values. `:57–108` validates profile, prepares credential/shared verifier and validates current grants before returning. Memory CLI also takes this path. Explicit manual constructor/injection remains available; removing legacy CLI selection does not remove named programmatic test composition.

2. **One maintained current provider authority — PRESERVED.** Startup `:71–99` composes OidcAccessTokenVerifier and OidcCurrentAuthority with fixed trust, profile, transport and credential source. It never substitutes signature-only authority or a custom introspection client. Actual provider discovery/current checks occur at request time, not proven during startup. Shared maintained profiles constrain Okta custom authorization servers, Keycloak and RFC9068; source tests primarily exercise Keycloak through actual signed RS256/JWKS/discovery/introspection fixture traffic.

3. **Single deployment and stable local identity — PRESERVED / operational binding RELIED-UPON.** Profile `:189–235` validates static exact external mappings; CurrentGrants `:304–347` rejects tuple mismatch, unknown principal, duplicate row/actor/pointer and nonappend actor rules. Authorization `:358–400` enforces request quad, exact external key, static required action scope and exact current resource/action row. Dedicated DB+profile association is documented in OIDC_STARTUP.md; startup does not persist or verify that database association. Scope-only storage therefore remains safe only within the explicitly permanent one-quad deployment, not a general multi-tenant DB claim.

4. **Current grant/delegation before replay — PRESERVED.** CurrentGrants `:381–400` reads and validates the entire file for each authorization with no positive cache. `:401–419` checks exact append actor kind+subject and configured pointer text subjects; required/optional missing-value behavior is explicit. Existing auth-before-replay and trusted replay partition are unchanged. No forwarded human bearer is required by this service-producer mode: service identity, exact transport actor and owner-selected human delegation policy are separate checks. Text delegation policy does not establish legal signing assurance.

5. **Bounded privileged file authority — PRESERVED.** `:430–457` opens with NOFOLLOW|NONBLOCK, checks the actual descriptor's regular type, effective UID and private mode, then bounds read to1MiB. This avoids final-symlink and FIFO/device stalls before descriptor checking. Non-Unix refuses (`:460–463`). Parent-directory control and atomic complete replacement are operator duties, documented explicitly. JSON parsing uses closed typed structs before row selection. No no-swap/transactional concurrent-revocation guarantee follows.

6. **Current outbound token per operation — PRESERVED.** Client `lib.rs:565–584` rejects any static bearer+provider combination, including empty static values. Shared async request `:597–629` calls access_token once and attaches only its returned secret; acquisition failure returns before send. Append, event-type registry and shared bytes_get all await it (`:641,:734,:765`), covering all five public methods. Reused reqwest client retains pooling; no client token cache, stale reuse, scope escalation or fallback is added. Token renewal/acquisition correctness remains provider-owned.

7. **Redirect and formatting safety — PRESERVED.** Client builder `:554–558` disables redirects; config/client custom Debug `:489–500,535–547` redacts static bearer and does not format provider internals. Startup types do not derive credential-bearing Debug; errors are sanitized. Raw request/replay bytes are unchanged by this patch. No measured speed/resource improvement is claimed.

## 4. User-value and simplicity analysis

The actual binary now uses the existing current-identity/resource boundary instead of leaving correct injection ports uncomposed. A single511-line startup module includes typed configuration, validation, file opening and one adapter;480 lines of startup tests cover protocol and policy scenarios. The service client adds one private acquisition path shared by all requests and211 lines of focused tests. Static file authority is bounded operational policy, not a new general permission language.

The conceptual improvement is removal of CLI legacy fallback, duplicated grant-row identity decisions and fixed-token-only service composition. Shared maintained auth owns protocol/renewal; existing ScopeAuthorizer owns permits; existing HTTP methods own transport. Costs are per-request bounded file validation and privileged policy administration. A policy service or broad storage migration would add seams beyond the accepted dedicated deployment.

Root's accepted exact existing-case grant is a bounded manual authority choice. Automatic native-case→grant registration remains deferred application integration. Do not widen this patch to create grants for arbitrary new native cases. Value is refuted if revoked identical retries succeed, wrong actor kind succeeds, provider failure sends a Trellis request, or missing profile reaches storage/key work.

## 5. Counterfactual analysis

Kill criterion: any positive permission/token fallback, mixed-quad database use, bypass of current introspection or WOS-specific policy parsing in generic startup. Removal leaves strict CLI startup and current-token outbound composition unavailable. Existing shared auth fully subsumes protocol behavior; existing ports partially subsume adapter shape, but no preexisting executable composition supplies this policy. Six-month critic: source-written tests may be cited as executed qualification, or manual grants mistaken for automatic case lifecycle support. Preserve both limits.

## 6. Findings

**F1 — KEEP; OBSERVATION; named-seam/ownership.** Exact maintained verifier+current authority, existing ScopeAuthorizer and per-call ClientCredentialsTokenProvider satisfy the approved shape. Shared startup/client paths avoid a second SDK or permission stack. Evidence: §3 traces.

**F2 — KEEP corrected v2; OBSERVATION; intent-vs-shape.** Frozen v1 retained two posture assertions expecting removed `scoped ScopeAuthorizer` / `jwt_verifier` messages and stale HS256 CLI documentation; v2 updates them to actual explicit-grant/injected-verifier wording. Frozen v1 also began an include!-inserted client test file with an inner doc comment; paired code review identified the compilation issue and v2 changes it to an ordinary comment. Both changed files re-pin exactly; no production policy change accompanies these corrections. V1 is retained as historical evidence, not runnable acceptance.

**F3 — DEFER; OBSERVATION; scope/conformance.** V3 changes only `tests/oidc_cli_startup.rs` from v2: the new third test supplies a nonempty profile path, varies each legacy setting independently over empty/nonempty values, and requires the specific legacy-refusal error before profile/key/storage access. The earlier missing-profile test never reached that branch; it remains useful missing-profile coverage, not proof of flag refusal. This corrected coverage is source-only. Native execution is mandatory: preserved actual CLI RED, corrected GREEN, signed protocol tests, original14 auth regressions, all client tests, actual binary build and fresh bounded cohort readback under Root's window. Source tests cover token active→inactive, current case revoke, unchanged-body delegation revoke, quad/case/action/actor negatives, typed duplicate/private-file rejection and all five outbound operation paths; these are unexecuted assertions. No compiler/lock result is established.

**F4 — DEFER; OBSERVATION; operational ownership.** Permanent dedicated DB/profile binding remains operator-enforced; no persisted binding exists. Actual service-account subject, selected transport actor and human grants must come from authoritative external facts. Manual exact-case grant is accepted scope; automatic grant registration, independent agency trust/legal authority and full D1 remain separate.

No remaining architectural RESHAPE or REVERSE requirement applies to frozen v3. Further compiler/test findings must be resolved and re-pinned without expanding policy scope.

## 7. Verdict and limitations

**APPROVE static architecture for continued private qualification.** Intent MATCHES approved startup plus thin current-token client; user value SUPPORTED; commitments HONORED within fixed-deployment/operator assumptions; conceptual debt PAYS DOWN uncomposed DI and credential duplication; sibling subsumption PARTIAL; confidence HIGH for traced source and exact11-file binding, no executed behavior claim.

All six phases applied. H1 CLI composes current authority before key/storage CONFIRMED in source. H2 exact grant headers prove persisted DB binding REFUTED and operator limit documented. H3 every client path acquires current token CONFIRMED by shared request callers. H4 unchanged-body retry bypasses current grant file REFUTED by existing middleware and adapter placement. H5 source tests are qualification evidence REFUTED until executed. H6 frozen v1 is ready unchanged REFUTED; v2 corrects identified test/doc defects. No phase skipped. V3 directly addresses the previously unexercised legacy-refusal branch without production changes; its single-file delta and all11 final hashes were independently checked. Native plan v2 SHA `663b123f193adbd1c4eab61fc63ea47814cd6edcb01d05ec00c4a3d702fb635a` is a parent-supplied prepared-plan identifier, not execution evidence.

Packet explicitly records `cargoExecuted:false`, `lockUpdated:false`, `providerOrDatabaseActions:false`. This certificate does not approve dependency resolution, combined native behavior, deployment activation, automatic grant lifecycle or evidence-provider/full-D1 completion. Parent auth/native provenance history remains preserved as separate evidence.

### Exact frozen source pins

Paths relative to the private source root above.

| File | SHA-256 |
| --- | --- |
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
