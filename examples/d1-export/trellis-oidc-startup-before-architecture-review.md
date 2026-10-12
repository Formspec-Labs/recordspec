# Trellis strict OIDC startup: BEFORE architecture review

**VERDICT: RECONSIDER two grant-file invariants before implementation.** Keep the maintained OIDC composition and existing authorization port. Require globally unambiguous ledger-scope ownership and consistent internal-principal mapping across grant rows. These are bounded file-validation changes; neither a storage migration nor another permission interface is needed. No implementation or native qualification is approved by this exact proposal review.

Reviewer `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs Rust inspection. Read-only source review and only this certificate written; no Cargo/native execution, startup, live identity-provider request, key/DB mutation or source adoption.

## 1. Artifact summary

Proposal `trellis/examples/d1-export/trellis-oidc-startup-proposal-v1.json`, SHA-256 `3544425907c0b23e718d4612ccd3de7bf6325de09a636d3c5522e39b3cbc1bc8`. Owner `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`, parent `eda346c166a71c7b8df55afd8549247456229277`. Category: authentication product boundary and deployment composition.

Problem: executable startup currently does not compose the external verifier/current resource authorizer despite maintained injection ports. `state_from_env` reads the signing key and builds database state before selecting legacy HS256/allow-all paths (`src/state.rs:418–505`); `main.rs:14–22` invokes it before listener creation. The proposal loads required fixed trust, credentials and current grants before that work, builds maintained `OidcCurrentAuthority`, injects existing ports, and forbids CLI fallback while preserving explicit programmatic local/test DI.

Beneficiary: operators using Okta custom authorization servers or Keycloak who need the actual Trellis executable to enforce current provider identity plus current local case permissions. This is receiving-API authentication and local authorization. It does not implement outgoing service-token acquisition or legal signing assurance.

## 2. Lineage and relationship tables

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| User/lead OIDC requirement | Fixed external authority, provider-neutral DI, separate local/legal grants | Direct task scope; previous actual-custody auth design |
| Production goal/philosophy | Governed case evidence and explicit ownership; no permissive production auth | root `GOAL.md:Target Deployment Profile, Governing Data-System Rule`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Maintained shared auth | Owns provider profiles, transport, clock, verification and current introspection | `stack-common/crates/stack-common-auth/src/oidc/{verifier,introspection,transport,credentials}.rs` |
| Existing Trellis auth boundary | Current exact authorization before replay; request-local permit | private `trellis-server/src/auth.rs:35–118`; `trellis-server-ports/src/lib.rs:514–559` |
| Formspec startup | Loads selected profile before repository construction | `formspec-server/crates/formspec-server/src/auth_config.rs:180–205` |
| WOS identity mappings | Explicit host principal mapping separate from token claims | `workspec-server/crates/wos-server/src/auth/profile.rs:157–217,245–261` |
| Core byte authority | Ledger/hash/export identity remains canonical scope | private `trellis/specs/trellis-core.md:§9,§18–19`; `trellis-server/src/http.rs:128–135,168–183` |

| Component / named seam | Owner | Input / output | Depends on / consumers |
| --- | --- | --- | --- |
| Startup profile | Trellis composition | Operator fixed JSON → verifier/authorizer | Existing state builder / binary |
| Current token authority | stack-common auth | Original access token → normalized verified identity | Maintained discovery/JWKS/introspection/clock/HTTP |
| Current grant file | Trellis host/operator | Verified identity + exact request → AuthorizedScope | Existing ScopeAuthorizer / HTTP replay boundary |
| Native human delegation | Producer owner through configured pointer policy | Validated append body → allowed asserted subjects | Host grants; no WOS semantics in Trellis |
| Case/scope ownership | Host configuration | Tenant quad + local case → canonical ledger scope | Existing scope-only storage/export |
| Service tokens / legal assurance | Existing consumer/provider/signing owners | Service credentials or signing act → separate assurance | Outside receiving startup change |

The file authority is an operator-managed adapter for the existing port. Formspec/WOS examples establish separation and early preparation, not reusable universal role/permission policy. Copying their application roles or D1 semantics into Trellis would violate ownership.

## 3. Invariants and commitments

1. **One maintained provider implementation — PRESERVED in decision.** `OidcAccessTokenVerifier::new/verify` fixes issuer/audience/scopes/clients and profiles; `OidcCurrentAuthority::verify` checks the original token offline and introspects on every call without positive current-state caching (`introspection.rs:42–105`). Bare signature/time verification is insufficient. Constructor validation refuses Okta org-server issuers and unsupported endpoints. Sparse introspection replies fail closed; provider-profile compatibility must be tested, not assumed from a name.

2. **Provider identity distinct from local resource authority — PRESERVED.** Existing `ScopeAuthorization` carries verified identity, exact requested tenant/scope/action and validated append body; `AuthorizedScope` is request-local. Proposal exact file grants correctly avoid treating OAuth scope or request tenant headers as case grants. Every retry must reload/refuse changed or missing grants before replay (`auth.rs:35–86`).

3. **Canonical scope belongs to one tenant quad — RELIED-UPON but underspecified.** Existing read lock, repository and export paths key only on `scope.as_bytes()` (`http.rs:128–135,168–183`). Exact request tuple validation does not separate stored records when two distinct tenant quads are granted the same scope. Require global scope→TenantScope uniqueness across the complete loaded grant file. Multiple identities/actions for the same scope+quad remain valid. A removed binding must not silently reassign an existing ledger to another quad: operator authority must preserve canonical scope ownership across file revisions. The host must supply canonical globally unique scopes, with local-case resolution outside Trellis; no broad storage change is proposed.

4. **Stable normalized principal — RELIED-UPON but underspecified.** `auth.rs:79–85` uses principal in replay partition; `authorize_publication:126–153` requires read/administer principal equality. Independent per-row `principal` values permit inconsistent identity mapping across otherwise distinct resource/action grants. Validate one principal per exact issuer/subject/client across all rows in each file; action/resource grants refine that identity rather than redefining it. Deliberate remapping across file versions remains operator-authorized identity lifecycle, not an accidental row-order choice.

5. **Current actor/delegation and payload ownership — PRESERVED with bounded semantics.** Append body reaches existing authorizer before replay. Exact `body.actor.subject` and configured JSON Pointer text subjects can check delegation without interpreting WOS data. Required pointers must refuse missing/nontext values; present optional values also refuse nontext/foreign subjects. Pointer rules are operator policy, not discovery of all legal human acts. Consumers must configure their required owner fields; empty rules cannot substantiate full D1 delegation assurance.

6. **Fail-closed startup and file updates — NEWLY INTRODUCED.** Require complete bounded typed configuration, current grant-file parse/validation and credential preparation before key/DB startup. Every authorization reads one bounded complete grant-file snapshot; invalid/unavailable/ambiguous data refuses without last-good positive fallback. Unknown/duplicate fields and malformed pointers should refuse deterministically. Atomic operator replacement avoids partial-update outages but is not a concurrency/no-swap guarantee. File mutation authority is privileged local administration, not token-derived policy.

7. **Secrets/deadlines — RELIED-UPON.** `StaticClientSecret` and credential types use redacted Debug; maintained HTTP disables redirects/TLS bypass and uses finite size/time bounds (`transport.rs:73–101`). Keep raw secret/token material out of config Debug/errors/logs and exported state. Maintained current-authority docs require the host to enforce its original absolute operation deadline; bounded request/file work must not reset that deadline. No new provider implementation is justified.

## 4. User-value and simplicity analysis

The executable can enforce the same current-authority boundary already available to injected callers. This closes a real deployment gap. A single closed current grant-file adapter is a reasonable small operational authority for a bounded operator-managed cell: it avoids a new policy service or hardcoded application role stack, while revocation requires no restart or positive cache invalidation.

Its cost is privileged policy-file administration and reading/validating the whole bounded file per authorization. No throughput or resource benefit is measured. Keep the schema small, impose explicit byte/entry/pointer bounds, and refuse ambiguity. If deployment requires many grants or transactional policy administration, replace this adapter behind ScopeAuthorizer rather than spreading file concerns into domain/storage code. File mutation audit/operational administration belongs to deployment owners.

Falsifier: an inactive token or revoked identical retry succeeds; unknown profile starts; tenant alias exposes another ledger; external identity changes principal by selecting another action; raw human delegation changes are ignored. Retaining HS256 CLI fallback would leave the original user-visible gap unresolved.

## 5. Counterfactual analysis

Kill criterion: shared verifier replaced by custom JWT/introspection code, current grants cached, canonical ledger ownership ambiguous, or policy embedded in WOS-specific payload parsing. Opposite decision retains programmatic-only external auth or builds a second permission stack. Removing the startup adapter leaves the actual CLI on legacy selection. Shared stack-common subsumes OIDC protocol behavior; existing ScopeAuthorizer subsumes authorization interface, but no existing generic current host-grant adapter fills the CLI gap. Six-month critic: an operator file may be mistaken for agency/legal authority or merely exact tenant checks may be mistaken for storage isolation. Explicit bounds and ownership invariants prevent those claims.

## 6. Findings

**F1 — BLOCKER; commitment-violation; RESHAPE.** Proposal `grantShape/shape` needs global canonical scope ownership across all grants and revisions, because storage identity excludes tenant. Add complete-file duplicate/conflict checks for scope→exact quad and require persistent operator-owned scope assignment. Test two tenants sharing the same textual scope refuses rather than authorizing isolated replay over shared storage. Evidence: §3.3 and actual `http.rs` storage/export calls.

**F2 — CONCERN; unstated-assumption; RESHAPE.** Enforce one principal per issuer/subject/client across all grant rows. Test cross-action/resource inconsistent principals refuse at file validation. Evidence: replay principal partition and read/administer same-principal check, §3.4. Existing request-level checks cannot establish global mapping consistency.

**F3 — OBSERVATION; named-seam; KEEP.** Compose exact maintained OidcCurrentAuthority, existing verifier/clock/HTTP/credential ports and ScopeAuthorizer. Preserve the actual auth-before-replay and publication checks. No new SDK, policy port or consumer semantics are warranted.

**F4 — OBSERVATION; scope; DEFER.** Actual signed-token/JWKS/introspection tests, grant/delegation revoke-before-replay tests, CLI early-refusal process test and auth14/build qualification remain required after the corrected design and under Root's assigned window. Fresh18198/PG18185, unchanged export key/registry pins and actual Keycloak/Okta compatibility remain intended deployment evidence, not reviewed results. Full D1/provider evidence/legal signing and independent trust remain separate.

## 7. Verdict

**RECONSIDER: add complete-file canonical scope ownership and stable external-identity mapping invariants, then re-pin before implementation.** Intent MATCHES maintained startup composition; user value SUPPORTED; commitment status DRIFTING at grant-file identity definitions; debt otherwise PAYS DOWN uncomposed DI; sibling subsumption PARTIAL; confidence HIGH for source boundary, MEDIUM for unimplemented policy details. The correction belongs inside the proposed adapter's validation and operator authority definition, not a storage migration or parallel policy abstraction.

All six phases applied. H1 external receiving DI is missing entirely REFUTED: ports exist, CLI composition is missing. H2 OAuth scopes grant case access REFUTED by existing port. H3 exact tenant match implies separate ledger REFUTED by scope-only storage. H4 per-row principal is always consistent REFUTED by permitted distinct action/resource rows. H5 local grants replace current introspection REFUTED by shared authority composition. Next action: author-correct/re-pin these two invariants before implementation, then execute exact acceptance tests under assigned native window. No phase skipped.

### Exact inspected source pins

| Absolute source | SHA-256 |
| --- | --- |
| `/Users/mikewolfd/Work/formspec-stack/trellis/examples/d1-export/trellis-oidc-startup-proposal-v1.json` | `3544425907c0b23e718d4612ccd3de7bf6325de09a636d3c5522e39b3cbc1bc8` |
| `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis/crates/trellis-server/src/state.rs` | `eecc34672601abc415a48ca7afedb00405f6d759ada028bf264ba4b307e84d58` |
| `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis/crates/trellis-server/src/auth.rs` | `90a84b5690b6cedc43456fa041fd6b3f45b272d02dfaf3b1944598fc450d24c2` |
| `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis/crates/trellis-server/src/http.rs` | `7aa3688c7bb62977f2c8ffd9cf57fae3b33376fddc436857adf0a665d4ad1d44` |
| `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis/crates/trellis-server-ports/src/lib.rs` | `9044bbb611e496df7a1b46d00779d9d339e289253b15e9412ee1bea2f1bc8a21` |
| `/Users/mikewolfd/Work/formspec-stack/stack-common/crates/stack-common-auth/src/oidc/verifier.rs` | `d853dc7ca0a3e5772933d82cae6e63a64ed0ce10b27e6ad37aa80aa67d7bffd6` |
| `/Users/mikewolfd/Work/formspec-stack/stack-common/crates/stack-common-auth/src/oidc/introspection.rs` | `368e1a198a73b89b78ddfcc669ce3e36c610776ee71e91c3fd2244c3e214897e` |
| `/Users/mikewolfd/Work/formspec-stack/stack-common/crates/stack-common-auth/src/oidc/transport.rs` | `2c33b9c43827d64a456266ab3a2cfb95230fabd64cd99dda2ca1511f9efe5207` |
| `/Users/mikewolfd/Work/formspec-stack/stack-common/crates/stack-common-auth/src/oidc/credentials.rs` | `9173c38f1c9b7d3229c81f228bca948f2557127ac31b2ea407f7f96c83db28c5` |
| `/Users/mikewolfd/Work/formspec-stack/formspec-server/crates/formspec-server/src/auth_config.rs` | `76cffd15e4524e26984c09eab96806067265ef437815f73107d3aa8f5064b9c2` |
| `/Users/mikewolfd/Work/formspec-stack/workspec-server/crates/wos-server/src/auth/profile.rs` | `6d146490e26dc4b7f47d6002d9351eb19f0c7844a666342bec71f37907f9dbaf` |
