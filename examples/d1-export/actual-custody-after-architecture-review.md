# Current authorization before replay: independent AFTER architecture review

**VERDICT: APPROVE the exact bounded auth implementation and controlled RED2→GREEN14 evidence for scoped local adoption.** No architecture blocker remains. Real current-authority provider configuration, host principal/delegation grants, deployment and full D1 remain unqualified prerequisites. The evidence provider and native-provenance routing are separate decisions.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs source inspection. Static source/decision review plus independent readback of retained execution evidence. This reviewer ran no Cargo/native commands or live calls and changed only this certificate. Approval is before adoption, not an assertion that original source or running service already changed.

## 1. Artifact summary and exact snapshot

Baseline Trellis HEAD independently read as `ea8f547367e4d41d09395001230ccf14705af8c9`. Candidate `/Users/mikewolfd/Work/formspec-stack/.trellis-actual-custody-auth-green-v3`. Final patch `actual-custody-auth-qualified.patch` SHA-256 `80b7345d571730c0d23b5a7bae0b294eb0656887a762fb9def3b28cba3bac1bf`, against that baseline, includes the original two meaningful RED tests. Eight changed files comprise ports dependency/API, state/admission/router composition, one auth module and focused tests.

Final evidence index `actual-custody-auth-after-inputs.json` SHA-256 `fbae264d498dd79cbea84a4b557d16be58ea9295770ed9d733bfab2c2b70dd03`; source packet `actual-custody-auth-green-v3-preflight-pins.json` SHA-256 `39d722dda0a8e7cfd4ecf3987e9c5beb20db8d643d989b1af148382e73cfd47c`. All1463 recorded source/fixture path hashes independently checked: no mismatches. Qualification `actual-custody-auth-qualification.md` SHA-256 `a54736528ad928e471b1a7d36e6539e9809bea7d7b918f04bd35c6241279a8d4` accurately limits its claims.

Problem: cached append receipts could return before handler authentication and resource authorization. Decision: authenticate and authorize the exact operation in outer append middleware, then use existing trusted replay partition/storage; retain the parsed admitted body for the handler. Category: security boundary supporting proof infrastructure. Beneficiaries: authorized producers and case readers whose data must not be served to revoked/foreign access. This changes a verified user-visible refusal boundary; it does not itself add case history/evidence.

## 2. Lineage and relationship tables

| Prior artifact | Type | Relation | Citation |
| --- | --- | --- | --- |
| Approved actual-custody proposal | Parent decision | Fixed external identity, host grants, exact permits/delegation before replay | `actual-custody-export-proposal.md:Trellis authenticated request shape`, approved SHA `2646f87ff389e8b8f3ad98e3aff4d5a4f965b0f3d6d415c30107674866d5fd69` |
| BEFORE certificate | Independent gate | Auth approved; deployment/evidence provider deferred | `actual-custody-before-architecture-review.md:§6–7` |
| Root GOAL / philosophy / Trellis guide | Parent commitments | Independent evidence, maintained components and inward boundaries | `../GOAL.md:Critical Path5`; `../DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility`; `CLAUDE.md:Architecture` |
| Shared access-token interface | Owning seam | Identity facts do not grant case access or create internal principal | `stack-common/crates/stack-common-auth/src/access_token.rs:1–42` |
| Shared current-authority adapter | Sibling capability | Original-token introspection; no positive authority cache | `stack-common-auth/src/oidc/introspection.rs:1–4,40–99` |
| Shared HTTP replay | Existing seam | Trusted internal partition, bounded capture, same reserve/record context | `stack-common-http/src/idempotency.rs:33–67,297–310` |
| Core proof/signing | Normative boundary | API grants separate from signed evidence and offline verification | `specs/trellis-core.md:§16,§18–19`; `specs/wos-trellis-verification.md:§1` |

| Component/seam | Owner | Depends on | Consumed by | Named? |
| --- | --- | --- | --- | --- |
| External verification/current authority | Shared auth / host composition | Fixed issuer/audience/client/scopes, credentials/HTTP/clock | Trellis state authenticate | Existing AccessTokenVerifier |
| Principal/grants/delegation | Host | Verified identity, tenant quad, scope/action, exact append body | Auth middleware | Existing ScopeAuthorizer extended |
| Admitted context | Trellis ports | Host decision | HTTP boundary validation and replay | AuthorizedScope |
| Replay partition/storage | Shared HTTP / Trellis driver | Validated principal/context | Existing idempotency store | Existing TrustedReplayPartition |
| Append | Trellis coordinator | Same admitted parsed body | Signed event/export receipt | Existing AppendCommand/runner |
| Read/publication | Trellis HTTP | Read permit; same-principal Administer for publication | Existing bundle routes | Existing ScopeAction values |
| Legal/domain proof | WOS/Integrity | Actual source records/accepted trust | Offline validators | Existing; unchanged |

Trace: router `http.rs:35–45` puts auth outside replay. `auth.rs:41–85` verifies identity, captures at most2MiB, parses once, validates body and obtains exact host authorization, then inserts shared partition and admitted body while restoring original request bytes. Handler `http.rs:89–103` consumes that body. Driver `state.rs:328,348,382–391` uses trusted partition for actual storage reserve/record. Reads `http.rs:241–268` retain identity and Read permit. Head and pinned-miss publication use `authorize_publication` (`auth.rs:123–147`) before effect; existing pinned bytes require only Read.

## 3. Invariants and commitments

1. **Current authority before cached outcomes — PRESERVED.** State invokes injected verifier for each external request (`state.rs:253–300`); auth precedes replay (`http.rs:35–45`). Shared verifier dependency errors and rejections deny without fallback. Failure would expose receipts to expired/revoked authority. Real revocation requires host composition with OidcCurrentAuthority; the generic trait alone cannot guarantee it.
2. **Exact host authority — PRESERVED.** Ports `lib.rs:516–563` carry requested tenant/context, identity and borrowed body; authorization returns internal principal and exact tuple/action. `auth.rs:108–120` rejects blank principal or foreign tuple/action. Header context and OAuth scope labels remain selectors/facts, not grants. Failure would execute a different resource than admitted.
3. **Transport actor and human delegation — PRESERVED as owning host responsibility.** Exact append body reaches authorizer before replay; generic Trellis never infers WOS human semantics. Controlled unchanged-body delegation revocation test passes. Failure would allow replay after delegation withdrawal or unauthorized actor assertions.
4. **Stable, isolated replay authority — PRESERVED.** Partition JSON encodes internal principal, full tenant tuple, scope and action; driver length-prefixes it and includes method/path. Original raw body still determines request hash. Both reserve and record use that context. Two admitted principals exercise separate HTTP replay entries while ledger idempotency prevents duplicate append. Failure could disclose another principal's response or hide changed raw request content.
5. **One principal for combined Read/Administer — PRESERVED.** Read permit retained; Administer tuple checked by existing helper and principal compared (`auth.rs:123–147`). Head and pinned-miss path refuse changed principal before publication. Failure would combine two principals' separate grants.
6. **One body interpretation — PRESERVED.** Bounded JSON parsing produces one admitted body consumed by handler; original bytes restored for shared hashing. JSON415/400/422/413 tests pass without append. Failure could authorize one payload and execute another, or remove bounds.
7. **Declared legacy posture / no external fallback — PRESERVED.** Authentication enum chooses Unconfigured, LocalJwt or External (`state.rs:46–84,183–200`). External rejects allow-all startup and missing/bad verification; it never switches to local-token acceptance. Legacy authorizers retain their existing scope behavior (`admission.rs:21–81`); no real revocation capability is attributed to them.
8. **Single maintained mechanisms / proof separation — PRESERVED.** No new replay store, JWT parser, ZIP writer, business event schema or signature proof is introduced. Legal signing assurance, Source custody, disclosure selection and offline trust remain external. Failure would make API authentication substitute for actual evidence.

## 4. User-value and simplicity analysis

Observed baseline RED shows unauthorized cached201 responses. The new boundary restores401/403 refusal and preserves authorized exact replay with one ledger event. This is a concrete correctness improvement, supported by actual execution rather than an elegance claim.

One shared verification interface, one extended authorization port and one shared replay partition avoid parallel token/mapping/permissions/replay stacks. The dedicated147-line auth module centralizes body admission and exact-context checks; the535-line controlled test module contains the meaningful boundary coverage. Port changes add shared auth/tenant dependencies; this is server-boundary coupling, not an inward Core/offline dependency.

The cost is current verification, permission/delegation checks and bounded parsing on each retry. Timings124.84s RED and6.59s GREEN include different compiler cache states and establish no speed improvement. No resource reduction is claimed. A smaller handler-only change would leave shared middleware replay before authorization; duplicating a new cache or permission port would add mechanisms without fixing another observed need. Falsifier: a future revoked credential/grant/delegation can still read cached output, or the same authorized request appends twice.

## 5. Counterfactual analysis

Kill criterion: auth executes after cache, mismatched permit is accepted, publication combines principals, or hashing uses reserialized rather than original bytes. Opposite decision leaves the demonstrated bypass. Removing the correction breaks missing-bearer and denied-scope cached retries first. Existing shared primitives subsume token parsing and replay partition machinery; host principal/delegation authority cannot be subsumed by OAuth labels. Sibling subsumption PARTIAL.

Six-month critic: someone may claim controlled verifier GREEN establishes real provider revocation, or local auth adoption proves complete D1. Preserve the explicit deployment prerequisites and separate evidence-provider/native-routing gates. The current implementation supports host injection; it does not provide actual issuer/audience/client credentials or host grants by inference.

## 6. Findings

**F1 — KEEP. Severity OBSERVATION; category commitment-violation correction.** Locations `http.rs:35–45`, `auth.rs:41–85`, retained RED/GREEN evidence. Authorization now precedes both fresh and cached append paths. Original observed401/403 failures become passes; current verifier/grant/delegation checks execute on retries.

**F2 — KEEP. Severity OBSERVATION; category named-seam.** Locations ports `lib.rs:516–563`, `auth.rs:108–147`. Exact permit validation and same-principal publication resolve the earlier review defects. Keep this single existing port; no second permission stack is warranted.

**F3 — KEEP. Severity OBSERVATION; category scope.** Location qualification document and controlled tests. All14 selected checks pass; no broader suite, real IdP, service deployment or business-history qualification is claimed. The v3 publication test counts actual forwarding ArtifactStore writes, fixing v2's profile-hook counter mismatch without production changes.

**F4 — DEFER deployment admission. Severity OBSERVATION; category ownership.** Host must construct maintained OidcCurrentAuthority with actual fixed issuer/API audience/allowed client/scopes, original-token introspection credentials, HTTP/clock/deadline policy, authoritative mapping, fresh grants and actor delegation. Supplying a bare signature/time verifier does not meet the revocation promise. Controlled injected tests prove Trellis calls the boundary and handles outcomes, not that a particular provider supplies them.

**F5 — DEFER full D1 and live evidence claims. Severity OBSERVATION; category scope.** Real accepted Source history, complete native signed custody/issued notice, immutable first-publication evidence, output/resource authority and independent offline trust remain necessary. This auth patch cannot manufacture them. No RESHAPE or REVERSE finding remains for the exact reviewed auth scope.

## 7. Verdict and retained execution evidence

**APPROVE** the pinned bounded implementation for scoped local adoption. Intent MATCHES approved auth design; user value SUPPORTED by observed RED2→GREEN14; commitments HONORED; conceptual debt PAYS DOWN competing mechanisms through maintained seams with necessary checks/code; sibling subsumption PARTIAL; confidence HIGH for exercised auth/replay/publication boundary. Real host configuration and unexecuted broader/live behavior remain unqualified.

| Evidence | SHA-256 | Observed result |
| --- | --- | --- |
| RED receipt | `d9044143c7d137d045134463f449cba769a6cbdb5ef29b6cc5ecea0579e774e1` | exit101; both intended assertions fail201 versus401/403 |
| RED log | `90bfcaa8a751c764e66a3530e5349b7f040cd0b3e6c29e10a5ec4ff1f8727708` | 0pass,2fail; actual compiled boundary failure |
| GREEN receipt | `3da38c3d69983681d4e8b591afd33f392ff8611ecb14b11cf2d2a6c63379b903` | exit0; exact selected filter |
| GREEN log | `a67cb11cf4ba2bfd9405538a9476ca30587e02a137386fa5fa899aecd7208999` | 14pass,0fail;89filtered unit tests, other targets filtered |

Both ran `cargo test --offline --locked -j1 -p trellis-server authorized_append_replay_ -- --nocapture` in their respective private candidates. Read receipt/log hashes independently; this reviewer did not rerun them. Receipts record owned groups35152/45299 absent, starting lock restored and empty source/fixture drift. Starting lock SHA `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b`; RED resolved lock `e8db9355f0959eebb70c3d951168497ae579224fb7d1ee07ab71f4c90e6b8523`; GREEN resolved lock `2b329736e2602574e00236a0e354b9180ba95a39f765c61de3a49b62a3ecc294`. Minimal changes are existing dependency edges, with unchanged package versions. Cleanup is retained execution evidence, not a new live process-state assertion.

Prior REDv1/v2 metadata failures are retained separately and not behavioral RED. Earlier GREEN preflight fixes and source freezes remain retained. All six reasoning phases applied. H1 handler auth protects cache REFUTED by baseline RED. H2 trusted partition reaches driver CONFIRMED by source and two-principal test. H3 returned context can be blindly trusted REFUTED and guarded. H4 combined grants can ignore principal consistency REFUTED and guarded. H5 controlled verifier proves real provider revocation REFUTED; deployment deferred. H6 parsed-body reuse changes raw idempotency hashing REFUTED by actual conflict test.

## Exact changed-source pins

| File in private GREENv3 | SHA-256 |
| --- | --- |
| `crates/trellis-server-ports/Cargo.toml` | `4e34203242c94fe6d1bb4571d802707cc057bf6badde4be6661df0eaf2603995` |
| `crates/trellis-server-ports/src/lib.rs` | `9044bbb611e496df7a1b46d00779d9d339e289253b15e9412ee1bea2f1bc8a21` |
| `crates/trellis-server/src/lib.rs` | `a7fd089cc1b5254cd656bc7400336f0933387cfe103dd945ca8b8dfbee9ca896` |
| `crates/trellis-server/src/state.rs` | `eecc34672601abc415a48ca7afedb00405f6d759ada028bf264ba4b307e84d58` |
| `crates/trellis-server/src/admission.rs` | `4878dd194aba4a4c292409d2e12d1d62c2961b537234273ade34926049d90503` |
| `crates/trellis-server/src/http.rs` | `7aa3688c7bb62977f2c8ffd9cf57fae3b33376fddc436857adf0a665d4ad1d44` |
| `crates/trellis-server/src/auth.rs` | `90a84b5690b6cedc43456fa041fd6b3f45b272d02dfaf3b1944598fc450d24c2` |
| `crates/trellis-server/src/auth_boundary_tests.rs` | `0efe45d6d67d7de21b216a7f8d4eb1ea828dcabb446b52d69dcd299a630aaba2` |

The full1463-file source packet binds additional shared dependencies/fixtures. Review certificates are separate outputs, avoiding self-reference. Only this final certificate was written; no source adoption, commit, lock mutation or deployment was performed by this reviewer.
