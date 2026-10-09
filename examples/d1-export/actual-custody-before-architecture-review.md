# Actual custody/export: independent BEFORE architecture review

**VERDICT: APPROVE the bounded auth design; DEFER evidence-provider implementation and deployment selection.** The final proposal explicitly checks returned authorization context, admits service-to-event-actor delegation before replay, checks current token authority and separately authorizes head publication. Evidence input authority remains unavailable, as the proposal acknowledges. This is BEFORE design approval, not implementation acceptance.

Reviewer: `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs source inspection. Static decision/source review; no Cargo, services, builds, production edits or deployment changes. Only this certificate written. Native window remains owned by Core.

## 1. Artifact summary

Artifact: `examples/d1-export/actual-custody-export-proposal.md`, SHA-256 `2646f87ff389e8b8f3ad98e3aff4d5a4f965b0f3d6d415c30107674866d5fd69`. Trellis HEAD `ea8f547367e4d41d09395001230ccf14705af8c9`. Scope: proposed authenticated request composition and future admitted-evidence connection, not implementation acceptance.

The concrete problem is that cached append responses can precede handler authentication, while server export supplies an empty evidence list despite maintained writer support. The beneficiaries are authorized service producers and offline case reviewers. Correct auth prevents stale or foreign access to cached outcomes; a qualified evidence connection would make genuine original evidence verifiable offline. Category: security boundary and proof infrastructure. Actual application history and legal signing assurance remain external.

## 2. Lineage and relationships

| Prior artifact | Type | Relationship | Citation |
| --- | --- | --- | --- |
| Root GOAL | Parent | Independent evidence serves actual user outcome | `../GOAL.md:Critical Path 5` |
| Development philosophy / Trellis guide | Parent | Reuse maintained packages and inward boundaries | `../DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility`; `CLAUDE.md:Architecture` |
| Maintained auth interface | Shared seam | Verifies identity facts; explicitly leaves mapping/grants to servers | `stack-common/crates/stack-common-auth/src/access_token.rs:1–42` |
| Core export | Normative seam | Fixed member structure, digest binding and verification | `specs/trellis-core.md:§18.2–18.3,§19`; export-scope paragraph at line1208 |
| WOS verification | Normative sibling | Domain meaning from signed evidence; no mutable runtime queries | `specs/wos-trellis-verification.md:§1,WOS-TV-004–007` |
| Registered-member input | Implemented prerequisite | Existing closed evidence input, not a new serializer | writer `src/lib.rs:174–198,320,417–441` |

| Component/seam | Owner | Depends on | Consumed by | Named? |
| --- | --- | --- | --- | --- |
| Access-token verification | stack-common / host composition | Fixed issuer/audience/profile/clock | Auth middleware | Yes, `AccessTokenVerifier` |
| Principal and grant decision | Host application | Verified identity plus exact requested resource/action | Trellis middleware | Yes, existing `ScopeAuthorizer`; return type proposed |
| Replay partition | Shared HTTP / Trellis driver | Already authorized internal identity/context | Existing replay store | Yes, `TrustedReplayPartition` |
| Signed append | Trellis | Admission, canonical scope/events | Custody receipt and export | Existing maintained coordinator |
| Original accepted filing | Formspec Source / WOS reader | Retained acceptance, original bytes and current permit | Future evidence adapter | Existing Source seam; exact export snapshot not supplied |
| Catalog/certificate derivation | WOS / Integrity | Actual signed records and owned evidence | Existing evidence input | Normative member seams; concrete provider deferred |
| Byte publication/readback | Trellis / Integrity primitives | Frozen input, writer, verification, immutable store | Pinned bundle reader | Existing publication seam |

Current sibling HEADs: stack-common `6aaba49911d80303ee883cfdcb329dce4999432c`; workspec-server `0bf951eacfbcc77443450ff4fb7eac4bb5b9d312`; formspec-server `5fefb518be50fccc30185cae4beb272e5b6e1390`; integrity-stack `d2dd4827cd294aaecc470e6a49dd8954a48880cf`.

## 3. Invariants and commitments

1. **Current authorization before replay — NEWLY INTRODUCED correction.** Source: shared `TrustedReplayPartition` documentation, `idempotency.rs:33–54`; current Trellis `http.rs:36–39,97–112`. Middleware can presently return before the handler. The proposed outer authorization corrects this. Failure exposes a cached outcome after credential or grant revocation.
2. **Identity is not a grant — PRESERVED in intent.** Shared `access_token.rs:1–6,25–42` separates verified issuer/subject/client from internal principal. Exact host mapping is required; OAuth labels and tenant headers cannot manufacture case authority. Failure grants foreign case access.
3. **Authorized result matches requested operation — NEWLY INTRODUCED explicit validation.** Existing `ScopeAuthorization` declares actor/scope/action (`server-ports/src/lib.rs:516–530`); proposal replaces unit with an admitted context. Require nonempty internal principal and exact tenant-quad, canonical-scope and action equality before deriving replay identity or performing effects. Failure authorizes one tuple and executes another.
4. **Event actor authority remains distinct — PRESERVED explicitly.** Wire `AppendActor` exposes kind/subject (`service-client/src/lib.rs:144–164`); proposal distinguishes producer from applicant. The revised request borrows the exact bounded parsed `SubstrateAppendBody`; the host authorizer admits transport actor and application-owned human delegation before replay. The handler retains the same parsed body. Generic Trellis does not parse WOS actor semantics. Failure lets a service token assert an unauthorized human attribution.
5. **One replay implementation — PRESERVED.** Shared HTTP captures trusted extension for reserve/record (`idempotency.rs:297–310`). Trellis currently keys from caller tenant header (`state.rs:305–311`); actual storage key must consume the trusted partition. Use an unambiguous tuple/hash encoding and internal identifiers, not concatenated raw claims or secrets. Missing trusted context must refuse in external mode.
6. **One immutable publication identity — RELIED-UPON.** `server/src/lib.rs:302–320` derives identity only from ledger scope/seal/high-water. Provider bytes must be frozen before first publication and stable thereafter. Immutable store `server-ports/src/lib.rs:209–223` detects conflicts; it cannot repair an earlier incomplete archive. Failure creates inconsistent bytes or permanent publication conflict.
7. **Core plus domain verification — PRESERVED in proposal.** Current predicate only recognizes066/067/068 (`export_profile.rs:42–48`); proposal requires any supplied evidence family to trigger composed validation. Core validates structure/digests; application validators retain relationships and admissibility. Failure treats carried bytes as complete evidence.
8. **No new authority in generic writer — PRESERVED.** Core export-scope paragraph and WOS §1 keep consumer semantics external. Original filing, native provenance, notice issuance and accepted public-key authority cannot be synthesized during export.

9. **Current token state and publication effects — PRESERVED explicitly.** Final auth items1/3 select maintained `OidcCurrentAuthority` and original-token introspection per request, then current local grant/delegation checks. Shared `oidc/introspection.rs:40–91` rejects inactive/mismatched authority without a positive cache. Head retrieval requires Read plus existing Administer before its publication effect (`http.rs:138–157`); pinned/registry reads require Read. Failure treats a valid historical signature or read grant as present effect authority. Host composition must preserve bounded verification transport and the original operation deadline described by the shared adapter.

## 4. User-value analysis

Auth fixes an observable access boundary even without full D1 export. It therefore warrants its own bounded decision, rather than waiting on business history. Reusing one verifier, authorizer and replay mechanism avoids a parallel permissions stack. Replacing the authorization port's unit result is justified only to return host-resolved principal/context once; it should not introduce a second grant cache or mapping service inside Trellis.

Evidence connection enables an actual offline record only after its authoritative input exists. Existing `AcceptedIntakeEvidence` qualification (`wos-server-ports/src/intake.rs:86–100`), exact original attachment validation and current-output checks (`intake_service.rs:1257–1326`) are useful maintained boundaries, but they are not yet a specified immutable export snapshot.

Smaller shape: retain existing `ScopeAuthorizer`, add identity/tenant and asserted event actor as necessary, return one validated authorized context; insert shared trusted replay partition; populate existing writer field through one composition dependency. Avoid bespoke OIDC, arbitrary member uploads and duplicated catalog builders. No measured speed/resource claim is made. Falsifier: auth change still serves a cached response to a revoked grant, or supposedly frozen evidence differs for the same seal.

## 5. Counterfactual analysis

Kill criterion: malformed/foreign authorization context is accepted, denied delegation replays, or identical seal generates conflicting bytes. Opposite auth decision leaves handler-only checks bypassable by cache. Removing the future provider leaves writer capability unused by service. Existing shared verification, replay and ZIP machinery subsume most proposed mechanisms; sibling subsumption is PARTIAL because host grant/evidence selection remain necessary.

Six-month critic: a production claim might confuse API identity with signer assurance, operational WOS provenance with signed Trellis receipt, or rendered notice content with issuance. Governed execution stages actual native suffixes (`governed_execution.rs:65–88`); operational provenance preparation (`provenance_service.rs:161–170`) alone is not proof of Trellis append. `governance_service.rs:657–733` returns a notice view; issuance requires its owning records.

## 6. Findings

**F1 — KEEP. Severity OBSERVATION; category named-seam.** Location: final proposal, “Trellis authenticated request shape”, item3 follow-on paragraph. The boundary now explicitly rejects empty principals and foreign tenant/scope/action results before cache/effects. The proposed foreign-permit tests make this invariant falsifiable. Preserve this check in implementation; no second grant resolver is needed.

**F2 — KEEP. Severity OBSERVATION; category ownership.** Location: same paragraph. The existing authorization request borrows `SubstrateAppendBody`, already available through the ports crate's client dependency. The host authorizer admits asserted actor and required payload-human delegation; a service Append grant alone is insufficient. Current delegation runs before cached replay. Bounded parse-once and same-body handler reuse avoid a second conflicting body interpretation. Reads carry no append body. Generic Trellis retains no WOS-specific actor inference.

**F3 — KEEP. Severity OBSERVATION; category ownership.** Location: auth items1,3–4. Maintained verifier, trusted partition and explicit legacy/external selection are appropriate. External startup must refuse incomplete verifier/authorizer composition; verification unavailable and unknown/revoked mapping deny access without fallback. Current authority belongs to host composition, not JWT scopes.

**F4 — DEFER. Severity OBSERVATION; category scope.** Location: “Frozen evidence provider shape”. Its deterministic snapshot and mandatory verification rules are appropriate, but actual retained WOS input/association is absent. No evidence-provider implementation approval follows from its name or vector return type. Specify source ownership, pre-stage timing, retry/availability behavior and exact snapshot before implementation review.

**F5 — DEFER deployment selection. Severity OBSERVATION; category ownership.** Proposal expressly lacks concrete grant configuration and fresh service identity. Auth source work and deployment admission are distinct decisions. Do not invent grants or reconfigure the existing baseline. Test-only injected identity/grants must be labeled accordingly.

## 7. Verdict

**APPROVE the exact bounded auth design.** Final proposal SHA-256 `2646f87ff389e8b8f3ad98e3aff4d5a4f965b0f3d6d415c30107674866d5fd69` resolves F1/F2 and explicitly requires current-token introspection and head Read+Administer. Evidence-provider implementation and actual deployment remain DEFERRED; the proposal correctly recognizes those missing authorities. No Rust implementation has been reviewed or accepted here. There is no RESHAPE or REVERSE finding against this final auth shape.

Intent vs shape: MATCHES the explicit shared boundary and validated context/delegation shape. User value: SUPPORTED by the actual auth/cache ordering and missing service evidence connection. Commitments: HONORED in stated ownership and explicit permit/delegation validation. Debt delta: PAYS DOWN duplicate mechanisms through shared ports, with necessary context changes. Sibling subsumption: PARTIAL. Confidence: HIGH for static ordering/ownership; HIGH for the proposed auth boundary, pending executed implementation evidence; LOW for unavailable evidence lifecycle and deployment authority.

Six reasoning phases completed. H1 handler auth protects cached response REFUTED by middleware ordering. H2 shared partition already exists CONFIRMED. H3 generic writer needs more member capability REFUTED by closed enum. H4 current service supplies admitted evidence REFUTED by empty initializer. H5 immutable put alone freezes first publication REFUTED by identity/lifecycle. H6 issuer/subject alone is internal principal REFUTED by shared auth documentation. Next review should bind any implementation to actual RED→GREEN evidence under a separately authorized native window.

## Exact source binding and limitations

SHA-256 source snapshots:

| File | Digest |
| --- | --- |
| Trellis server `http.rs` | `7d8efedb29e93f4a1eb37a8c987a0c39401655f9dbd487e37f41e74d7e8752f6` |
| Trellis server `state.rs` | `e255a2d19d58e72c23860e104d47facca952a8e03fb880bc4b17b62f5580b041` |
| Trellis server ports `lib.rs` | `a4a60acc800b174925be2c1bc1c4b0c04aae6b66b955fa56261384ae726e93c9` |
| Shared auth `access_token.rs` | `c346d586ceebddf4fa64c4c112b719fd279ba26dc88eef0ce4e628f1929f84e5` |
| Shared HTTP `idempotency.rs` | `39848699e3b63fae95b3f87244a5cf5494f5071ae6593dc8ed6a986b2141e110` |
| Trellis server `lib.rs` | `c3afa4e64c22067ca4473d2da48fc85e2afc23b9d667bce462b96ef369aaa9c9` |
| Trellis `export_profile.rs` | `31c42a9eea217e1cec972bd23c20317ecfb37253e23ab15cb78a7515a835dcd4` |

This certificate binds the exact proposal and inspected source, not running services, unreviewed patches or future deployment. No actual fresh D1 custody/readback result is established. Retain the proposal's real-source, native-transition, signed-receipt, pinned-readback and offline-validator test sequence, including negative byte/authority checks, as the qualification gate.

Final refresh: read the complete revised auth/evidence sections and maintained `OidcCurrentAuthority` implementation. The prior reviewed proposal hashes `d89addc8577d6c037edc3119bc613f82a2114cec8719b869ffc2fb1753779d39` and `fde3f1324b3682e85624d70dcd5ebee48ad695fc6bcf4e8e56f0cc900810d7f3` are superseded for this verdict. Current-state introspection is stronger than signature/time-only verification but does not create local principal/grant authority or legal signing assurance. Current-authority failures remain sanitized and fail closed. No current-token capability claim is established for the explicitly separate legacy mode. The concrete external verifier, credentials, host grants and fresh service identity must be supplied before deployment admission.
