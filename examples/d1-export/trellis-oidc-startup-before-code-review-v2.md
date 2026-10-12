# Trellis strict OIDC startup — independent BEFORE code review

Review ID: TRELLIS-OIDC-STARTUP-BEFORE-V2-2026-10-09. Independent nonauthor `/root/oidc_code_review`; full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, applicable ms-rust application/universal/resilience guidance, parent/Trellis instructions. Scope: exact proposal85b72909… against private parent `eda346c166a71c7b8df55afd8549247456229277`; prospective implementation functions do not yet exist. Only this certificate written. No Cargo, tests, builds, native/live calls, source/lock changes or deployment.

## Findings

**APPROVE the exact v2 BEFORE design.** The actor-shape blocker and parser/file warnings from v1 are resolved in the proposal. No Rust implementation, compilation, native provider acceptance or startup/readback evidence is approved here. The v1 certificate remains retained with its original REQUEST CHANGES disposition.

F1 — RESOLVED / security / proposal:10 and grantShape actors. V2 binds each transport actor to exact kind AND subject. Existing AppendActor has separate unconstrained strings (`crates/trellis-service-client/src/lib.rs:144–146,330–334`); exact pair matching now closes the v1 attribution gap. Tests require same-subject/wrong-kind refusal, including retry. This is prospective until implementation/assertions are reviewed and executed.

F2 — RESOLVED / correctness / proposal shape/tests. Pointer grammar explicitly permits only ~0/~1 escapes, rejects duplicate selectors, requires text/presence and exact delegated subjects; non-append grants cannot contain append selectors. Closed typed serde parsing refuses duplicate/unknown object fields. Invalid optional pointer refusal is explicit. Implementation must validate pointer syntax during load, not treat malformed pointer as missing.

F3 — RESOLVED / security / proposal shape/config/grants. Fixed deployment TenantScope is checked on every request and grant document. Static exact issuer/subject/client→stableprincipal bindings cannot map one identity to multiple principals. Current grant file now carries principal/resource/action, while static actionScopes prevents row-level OAuth-scope downgrade. Unknown principals, duplicate rows and tuple mismatch refuse. Config/secret/grant files are bounded private regular files, with symlinks/group/other permissions refused and errors sanitized. Per-request I/O uses spawn_blocking and no positive grant cache.

F4 — OBSERVATION / test-coverage. All new startup/grant tests remain prospective. Maintained current-authority introspection requires full matching issuer/subject/client/expiry/audience/type/scopes; sparse provider responses fail closed. Do not substitute signature-only verification or identity doubles to make qualification pass. Existing programmatic legacy DI remains separate from strict CLI startup.

F5 — OBSERVATION / deployment authority. Dedicated DB plus fixed profile tuple is a permanent deployment identity across restarts; sharing one DB across different tuples is expressly unsupported. The proposal does not provide cross-tenant shared-DB isolation, automatic tuple-migration enforcement, agency trust or no-swap guarantee. Eventual startup/config qualification must retain the selected tuple/DB/profile evidence and preserve the existing baseline process. This limitation is explicit and coherent for the authorized dedicated-host scope.

## Patch summary and existing rationale

V2 adds fixed deployment tuple, immutable external-identity map and per-action scope policy to the startup profile. Current grants independently control exact principal/resource/action and actor/delegation. This keeps membership revocation current while keeping internal identity and deployment stable. Source functions in the trace remain unchanged; new host composition/parser/authorizer functions are explicitly UNIMPLEMENTED.

The CLI currently calls state_from_env from main.rs:14. state_from_env:418 reads signing key first (:422), opens/migrates PostgreSQL (:452–460), then selects HS256/permissive startup (:476–505); it never composes external current authority. Existing programmatic state setters and exact authorization port already support external identity. The proposed adapter belongs at host startup, leaving byte primitives, WOS vocabulary and the generic authorization port unchanged.

The shared primitive is preferable to custom JWT/JWKS/introspection code: OidcAccessTokenVerifier owns fixed issuer/audience/client/scope/profile and RS256 verification; OidcCurrentAuthority checks the same original token at the trusted provider on every verification; ReqwestAuthHttpClient provides bounded TLS-validating transport; ScopeAuthorizer remains responsible for exact current resource/actor authority. This removes the CLI gap without changing the established replay boundary.

## Function trace

Trellis paths below are beneath private parent; stack-common/Formspec/WOS paths beneath the workspace. Prospective rows are explicitly unimplemented.

| Function / seam | File:line | Inputs → outputs and verified/proposed behavior |
|---|---|---|
| main / state_from_env | server/src/main.rs:14; state.rs:418 | Environment → state → router; current key/DB work occurs before auth selection. Proposal must prepare strict auth first and remove CLI HS/permissive alternatives. |
| oidc_startup config/load/compose | proposal:7–8,14–28; UNIMPLEMENTED | Required closed bounded config + credentials + injected deps → maintained current verifier and grant adapter, before key/DB. No network required merely to construct shared verifier. |
| OidcAccessTokenVerifier::new | stack-common auth/oidc/verifier.rs:133–158 | OidcTrust+deps → verifier or refusal; canonical safe issuer, API audience, nonempty scopes/clients; Okta requires custom /oauth2/server path. |
| OidcCurrentAuthority::new / verify | auth/oidc/introspection.rs:32,47–92 | Fixed same-origin endpoint, confidential client+credential → current authority; original token offline verified then introspected with Basic. Every response must match original identity and required/all token scopes; no positive current-authority cache. |
| StaticClientSecret::new / credential | auth/oidc/credentials.rs:117,141 | Fixed client+secret → redacted source; matches client and bounded credential. It does not independently bind endpoint, so fixed endpoint validation remains the current-authority constructor's responsibility. |
| ReqwestAuthHttpClient::new / execute | auth/oidc/transport.rs:98,113 | Request → bounded response; redirects disabled,10-second timeout, TLS retained,256KiB cap. Tests use injected AuthHttpClient rather than bypass cryptographic verifier. |
| grant-file ScopeAuthorizer | proposal:9–10,30–58; UNIMPLEMENTED | Verified identity → static stable principal; requested tuple must equal fixed deployment. Reload grants each authorization, require exact principal/resource/action and static action scope, then exact actor-pair/delegation. Provider scopes never substitute for grant. |
| admit_append / authorize_action | server/src/auth.rs:34,87 | Authenticates first, bounds/parses original body once, passes exact body/identity/context to authorizer, verifies returned tuple, then inserts trusted replay partition and restores original bytes. |
| authorize_publication | server/src/auth.rs:123 | Same read principal/resource → separate Administer check; rejects different admitted principal. New file adapter must support both exact grants. |
| replay reserve/record | server/src/state.rs:321,341 | Actual trusted partition participates through tenant_replay_scope; unchanged implementation. New adapter denial must occur before this path even for cached retries. |
| ScopeAuthorization / ScopeAuthorizer | server-ports/src/lib.rs:516,544 | Existing identity/body/context port already exposes all required facts; no new public authorization trait needed. |
| Source PreparedAuthentication::load/from_file | formspec-server/src/auth_config.rs:186,211 | Loads fixed profile before repository construction, injects transport/time, maps exact enum profile and rejects production loopback (:540–565). Reuse composition pattern, not Source-specific business bindings. |
| WOS operation_verifiers / verify_for_operation | wos-server/src/auth/oidc.rs:20,55 | Explicit profile/transport + operation policies → maintained verifier; exact external mapping followed by actual current persisted user/authorization. Pattern does not itself prove revocation: it uses signature verifier, unlike the proposed maintained current authority. |

## Data flow and invariants

Config creates fixed trust independently of requests. StaticClientSecret retains only configured confidential credential in a redacted source. Original bearer token reaches maintained current authority; no token or positive grant becomes durable replay capability. JWKS/discovery cache is distinct from current introspection, which runs every request. Required base scope establishes API access; action-required scope plus current exact grant establishes permission. All four requested tenant components and the grant document tuple must equal fixed deployment; resource/action must match exact current row. Static issuer/subject/client bindings determine principal once, while grants can revoke every operation without changing mapping. Static actionScopes is complete for Read/Append/Administer and cannot be overridden by a row. Missing external identity/client, invalid grant file, unknown principal, zero or ambiguous match refuse.

Append uses the original already parsed body. Grant checks must authorize exact kind+subject and configured payload delegation without rewriting JSON. Middleware restores raw bytes for replay hashing, so serialization differences cannot change replay identity. Trusted partition uses internal principal plus exact tenant/resource/action; no raw bearer is retained. Grant or delegated-subject removal must refuse before cached response. Read→publication needs current Read and Administer for the same principal. Profile preparation before key/DB means malformed/missing auth has no key/DB side effect; actual test should deliberately set invalid key/DB settings and still observe auth refusal first.

Programmatic local/legacy DI remains available under explicit caller composition; state_from_env is the strict CLI path. Existing baseline18088 must remain untouched. COSE signing-key validity/registry trust and case authority are separate; strict OIDC cannot fix signing validity, missing export members or actual D1 inputs.

## Tests and concrete edge cases

Reviewer executed none. New proposal tests are UNIMPLEMENTED; prior auth14 evidence is separate. Existing maintained tests inspected:

- stack-common/tests/oidc.rs:792 signs an actual RS256 token, verifies active then inactive on the same token, counts two introspection calls, checks POST Basic and original token body, and asserts redacted Debug. This is a valid model for new startup-builder injected protocol tests.
- :813 removes/mismatches issuer, subject, client, expiry, token type, audience, scopes and other facts, requiring refusal. :830 covers dependency failure, expiry and rollback. :841 rejects foreign introspection endpoint before network. These existing assertions support feasibility, not new host execution.
- WOS profile tests at auth/profile.rs:442 onward require private bounded regular inputs; mapping/current-user tests in auth/oidc.rs:142 onward remove/change actual persisted user and identity, illustrating that provider identity is not local grant.

New required evidence: missing/unknown profile and forbidden legacy flags before key/DB; signed RS256 discovery/JWKS/introspection through the same startup builder; current grants revoked between identical append attempts; every tenant component/resource/action/client mismatch; exact actor-kind+subject mismatch; malformed pointer/nontext/null/required absence/foreign delegated subject; malformed/oversized/unavailable grant file; Read allowed but Administer absent or different principal; cached body unchanged after delegation revocation; existing14auth regression tests, actual binary missing-config refusal and approved isolated PostgreSQL startup/readback. These must remain actual native gates, not inferred from shared tests.

## Exploration notes

H1 CLI already composes shared OIDC. REFUTED by state_from_env:418–505; proposal addresses an actual startup gap.
H2 another authorization port is necessary. REFUTED by ScopeAuthorization's verified identity, exact context and borrowed append body; existing adapter port is sufficient.
H3 provider signature verification alone gives current revocation. REFUTED; maintained OidcCurrentAuthority explicitly performs original-token introspection with no positive cache. Source/WOS examples are composition patterns, not a substitute.
H4 subject-only actor authorization is exact enough. REFUTED by separate unconstrained kind field in current wire type. V2 exact actor-pair requirement resolves that v1 design defect; implementation remains unverified.
H5 injected protocol tests require custom JWT infrastructure. REFUTED by maintained signed test fixture/FakeHttp/Clock pattern; new test uses the real maintained verifier and startup builder.

## Exact pins

Private Trellis baseline `eda346c166a71c7b8df55afd8549247456229277`; stack-common HEAD `6aaba49911d80303ee883cfdcb329dce4999432c`; Formspec Server HEAD `5fefb518be50fccc30185cae4beb272e5b6e1390`; WOS Server HEAD `0bf951eacfbcc77443450ff4fb7eac4bb5b9d312`. Source digests below bind inspected working bytes even if sibling commits move.

| Input | SHA-256 |
|---|---|
| `trellis/examples/d1-export/trellis-oidc-startup-proposal-v2.json` | `85b72909bc5a52fa7d844ed60eb7ee2416b74b23409ff6a01c59e335a569a02a` |
| `stack-common/crates/stack-common-auth/src/oidc/verifier.rs` | `d853dc7ca0a3e5772933d82cae6e63a64ed0ce10b27e6ad37aa80aa67d7bffd6` |
| `stack-common/crates/stack-common-auth/src/oidc/introspection.rs` | `368e1a198a73b89b78ddfcc669ce3e36c610776ee71e91c3fd2244c3e214897e` |
| `stack-common/crates/stack-common-auth/src/oidc/transport.rs` | `2c33b9c43827d64a456266ab3a2cfb95230fabd64cd99dda2ca1511f9efe5207` |
| `stack-common/crates/stack-common-auth/src/oidc/credentials.rs` | `9173c38f1c9b7d3229c81f228bca948f2557127ac31b2ea407f7f96c83db28c5` |
| `stack-common/crates/stack-common-auth/tests/oidc.rs` | `9a6b27333f3c22e5b6c78da8cec34cbba236cfc89cdfe536f05babafffcf07d6` |
| `formspec-server/crates/formspec-server/src/auth_config.rs` | `76cffd15e4524e26984c09eab96806067265ef437815f73107d3aa8f5064b9c2` |
| `workspec-server/crates/wos-server/src/auth/oidc.rs` | `38c1af947a31b18e2774597c2c5248e83860a78f88b3fd32b20a414aa189ad3b` |
| `workspec-server/crates/wos-server/src/auth/profile.rs` | `6d146490e26dc4b7f47d6002d9351eb19f0c7844a666342bec71f37907f9dbaf` |

## Conclusion

VERDICT: APPROVE exact v2 BEFORE design; implementation/native acceptance pending.

Justification:
- Scope/identity/current-authority and replay ordering reuse maintained boundaries; v2 fixes actor attribution and separates static deployment/identity/scope policy from current operation grants.
- Coverage of existing source feasibility: ADEQUATE. New startup/grant implementation and execution: INSUFFICIENT because none exists yet.
- Confidence: HIGH for existing source/API traces; MEDIUM for prospective implementation, which still requires actual source/test review and coordinated execution. No compile, host, OIDC provider or deployment acceptance is granted.
