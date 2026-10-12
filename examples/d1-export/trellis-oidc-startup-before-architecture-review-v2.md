# Trellis strict OIDC startup: successor BEFORE architecture review

**VERDICT: APPROVE the exact v2 design for owner-scoped implementation.** One fixed deployment tenant quad and its dedicated database remove the cross-tenant ledger ambiguity. Static identity mappings and action scopes separate identity from revocable resource grants. Exact actor kind/subject and configured owner-field checks close the delegation gap. This approves the design, not implementation, native execution, service startup or deployment readiness. The v1 RECONSIDER certificate remains unchanged.

Reviewer `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs read-only Rust inspection. Only this certificate written; no Cargo/native/service calls or production edits.

## 1. Artifact summary

`trellis/examples/d1-export/trellis-oidc-startup-proposal-v2.json`, SHA-256 `85b72909bc5a52fa7d844ed60eb7ee2416b74b23409ff6a01c59e335a569a02a`. Private owner `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`, parent `eda346c166a71c7b8df55afd8549247456229277`. Category: executable authentication boundary and deployment composition.

The actual CLI must compose maintained OIDC current token authority and current host resource authorization through existing injection ports. Required bounded configuration is prepared before signing-key/database work, including memory CLI mode. No legacy/permissive fallback is permitted in that startup path; explicitly constructed local/test states remain available to programmatic callers. Beneficiaries are operators using Keycloak or Okta custom authorization servers and users whose identity, tenant membership and grants must remain current before an append or cached retry.

V2 supersedes v1 grant-row identity shape. It selects one deployment TenantScope in static configuration, static issuer/subject/client→principal bindings and action OAuth scopes; a reloaded file supplies current principal/resource/action grants and append delegation policy. No WOS/D1 payload semantics enter Trellis.

## 2. Lineage and relationship tables

| Artifact | Relationship | Citation |
| --- | --- | --- |
| v1 proposal/review | Previous ambiguity corrected; review retained | `trellis-oidc-startup-before-architecture-review.md:§3.3–4,§6/F1–2`, SHA `e54a9688eea4ee6f486de0e722f234798c75a1d56a31c03a65b50d37b6ccc118` |
| Root goal/philosophy | Production ownership and current governed authority | root `GOAL.md:Target Deployment Profile, Governing Data-System Rule`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Shared current authority | Owns discovery, JWKS, profile, token validation/introspection | `stack-common/crates/stack-common-auth/src/oidc/{verifier,introspection,transport,credentials}.rs` |
| Existing Trellis auth | Exact request-local permits before replay; same principal for publication | private `trellis-server/src/auth.rs:35–118,126–153`; `trellis-server-ports/src/lib.rs:514–559` |
| Source/Formspec preparation | Prepares selected fixed trust before repository construction | `formspec-server/crates/formspec-server/src/auth_config.rs:180–205` |
| WOS selected deployment | Explicit principal mapping and deployment membership | `workspec-server/crates/wos-server/src/auth/profile.rs:157–217,245–261` |
| Ledger identity | Storage/hash/export keyed by canonical scope | private `trellis-server/src/http.rs:128–135,168–183`; `specs/trellis-core.md:§9,§18–19` |

| Named seam | Owner | Depends on | Consumed by |
| --- | --- | --- | --- |
| `oidc_startup` profile preparation | Trellis host composition | Operator profile/credentials | `state_from_env` and actual binary |
| `AccessTokenVerifier` / `OidcCurrentAuthority` | stack-common auth | Fixed trust, clock, HTTP, credentials | Existing state authentication |
| `ScopeAuthorizer` / `AuthorizedScope` | Trellis port, host adapter policy | Verified identity, fixed deployment, current grants, exact append | Existing pre-replay/publication checks |
| Dedicated DB + deployment tuple | Operator/deployment owner | Permanent selected quad | Scope-only ledger storage/export |
| Configured payload human fields | Owning producer policy | Exact JSON Pointers and delegated subjects | Host append authorizer |
| Signing/legal/agency trust | Existing consumer/Integrity/deployment owners | Separate native evidence and trust | Full case reliance; outside this startup |

No new public authorization interface, provider SDK, per-kind permission stack or storage format is introduced. Sibling application profiles establish useful preparation/identity patterns; their roles and field semantics remain application-owned.

## 3. Invariants and commitments

1. **Canonical scope ownership — PRESERVED in corrected decision.** V2 `shape[2]` fixes one deployment quad, enforces it on every request/grant and permanently binds dedicated DB+profile across restarts. Existing repository/export keys remain scope-only (`http.rs:128–135,168–183`). All canonical scopes in that database therefore belong to the same selected quad. Reusing the database for another tuple or sharing it across differently configured hosts is expressly unsupported. This operational binding is load-bearing; exact HTTP header checks alone do not prove it. No broad schema refactor is needed for the named single-deployment scope.

2. **Stable identity, separate resource grants — PRESERVED.** V2 static `identities` gives one principal per exact issuer/subject/client; duplicate/conflicting identity mappings refuse. Current grants identify principal/resource/action only, require known principals and match deployment quad. Static `actionScopes` prevents revocable rows weakening required provider scopes. Failure would change replay identity by choosing another action/resource or permit OAuth-only case access.

3. **Current provider authority — PRESERVED.** Maintained `OidcCurrentAuthority` verifies original tokens and introspects without a positive current-authority cache (`introspection.rs:42–105`); trust/profile/endpoint validation remains shared (`verifier.rs:164–207`). Keycloak/Okta/RFC9068 are explicit profiles, not interchangeable arbitrary issuers. Okta org-server issuers remain refused. Sparse/mismatched introspection replies fail closed. Actual provider compatibility remains to be qualified.

4. **Current authorization before replay — PRESERVED.** Existing `auth.rs:35–86` authenticates, bounds/parses the same append body, authorizes and installs a trusted principal/tenant/scope/action partition before the replay driver. Host grants reload for every authorization, including identical retries. Read/administer publication remains same-principal (`auth.rs:126–153`). Missing/invalid files refuse without a last-good permission cache.

5. **Actor/delegation precision — PRESERVED in corrected decision.** V2 append grants check both actor kind and subject. Configured JSON Pointers have valid `~0/~1` grammar, unique definitions, required presence and exact text-subject checks. Append selectors on nonappend grants refuse. Optional rules allow absence by explicit policy but still validate present values. Producer owners must select required human fields; generic startup cannot infer every legal actor or claim signing assurance from text equality. Unchanged-body delegation revocation must block replay.

6. **Early fail-closed startup and bounded files — NEWLY INTRODUCED.** Required configuration, credentials and current grant-file validation precede key/DB initialization (`state.rs:418–505` currently demonstrates opposite legacy ordering). Closed typed parsing rejects duplicate/unknown fields; private bounded regular files reject symlinks and group/other permissions. Request file work uses blocking isolation rather than blocking async workers. Use one opened file snapshot per authorization and sanitize failures. Operator atomic replacement supports availability; no no-swap/concurrent-revocation guarantee is claimed.

7. **Secrets and protocol constraints — RELIED-UPON.** Maintained credential objects redact Debug; transport enforces TLS/no redirects/finite timeout/size limits (`credentials.rs:97–124`; `transport.rs:73–101`). Keep profile/token/secret errors sanitized and do not persist bearer material. Shared current-authority documentation assigns the host its original absolute operation deadline; implementation must preserve bounded operation behavior. Service token acquisition and legal assurance remain separate maintained seams.

## 4. User value and simplicity

The actual CLI becomes capable of the same strict current authority already available through manual DI. Static deployment/identity/action policy plus one current grant file is smaller and clearer than per-row identity declarations, a multi-tenant scope-ownership database or a new permission service. It fits the root's named one-cell dedicated-database deployment. Reusing shared protocol code and existing ports pays down startup inconsistency.

The adapter adds privileged local policy administration and bounded file read/validation on every request. No speed/memory claim is measured. A later transactional/high-volume authority can replace this host adapter behind ScopeAuthorizer if real demand justifies it. Empty current grants should represent deny-all revocation, not an excuse to restore old permissions. A copied application role system, arbitrary JWT implementation or generic policy language would add debt without serving this scope.

Falsifier: inactive tokens succeed, missing profile reaches database/key work, foreign quad receives a permit, the same external identity maps differently by action, wrong actor kind succeeds, or revoked identical retry returns cached success.

## 5. Counterfactual analysis

Kill criterion: host tuple changes while retaining the same database, a positive grant cache survives revocation, custom OIDC replaces the shared implementation, or generic code assumes WOS actor semantics. Opposite decision retains unsafe CLI fallback or attempts broad multi-tenant storage changes. Removing the adapter leaves the executable unable to compose current external identity/resource grants. Shared auth subsumes protocol behavior; existing authorization port subsumes permission API but does not supply CLI operator policy. Six-month critic: an operator file may be described as agency authority, or explicit single-deployment scope may be quietly widened. Preserve both limits in operator documentation and acceptance tests.

## 6. Findings

**F1 — KEEP; OBSERVATION; commitment/ownership.** Fixed deployment quad and permanently paired dedicated DB resolve v1 F1 with a smaller correct scope. Test every quad mismatch; document database reuse across tuple changes as unsupported. Multi-tenant shared-DB support would require a separate durable scope-ownership design.

**F2 — KEEP; OBSERVATION; named-seam.** Static exact identity mappings and static per-action provider scopes resolve v1 F2 and keep current resource grants independently revocable. Preserve existing normalized principals and pre-replay partition; do not add a public policy port.

**F3 — KEEP; OBSERVATION; intent-vs-shape.** Exact actor kind+subject, typed duplicate rejection, strict pointer grammar and private bounded files address the paired code-review gaps. Source implementation must demonstrate these properties; the proposal does not establish their execution.

**F4 — DEFER; OBSERVATION; scope.** Qualify actual signed RS256/JWKS/discovery/introspection active→inactive behavior with injected maintained transport/clock; grant/actor/human revocation before cached retry; fixed deployment mismatch; early CLI refusal; original14 auth regressions; actual server build. Root alone assigns native window and fresh18198/PG18185 deployment. Export key/registry pin remains unchanged. No actual provider/readback, agency trust, additional evidence-provider completion or full D1 is approved here.

No remaining RESHAPE or REVERSE finding applies to this exact v2 design.

## 7. Verdict

**APPROVE the exact corrected design for owner-scoped implementation.** Intent MATCHES current external identity plus current local resource authority; user value SUPPORTED; commitments HONORED within explicitly fixed deployment; conceptual debt PAYS DOWN uncomposed DI and row ambiguity; sibling subsumption PARTIAL; confidence HIGH for architecture, implementation/native behavior unqualified.

All six phases applied. H1 exact tenant matching isolates scope-only storage REFUTED for multiple deployments, now corrected by one permanent dedicated deployment. H2 row principals/scopes can vary safely REFUTED, corrected by static mapping/action scopes. H3 actor subject alone identifies append actor REFUTED, corrected with kind. H4 current grants replace provider introspection REFUTED: both remain mandatory. H5 strict CLI mode must eliminate explicit programmatic local DI REFUTED: named manual modes remain separate. No phase skipped. Next step is bounded implementation followed by paired source review and Root-authorized qualification, not service activation from this certificate.

### Exact source binding

The v1 certificate retains exact inspected source hashes; this successor independently re-pins relevant same sources below. Source paths are absolute.

| File | SHA-256 |
| --- | --- |
| `/Users/mikewolfd/Work/formspec-stack/trellis/examples/d1-export/trellis-oidc-startup-proposal-v2.json` | `85b72909bc5a52fa7d844ed60eb7ee2416b74b23409ff6a01c59e335a569a02a` |
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
