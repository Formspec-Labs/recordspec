# Actual custody and export: proposed Trellis changes

Status: BEFORE review. Static source trace only; no native execution or live operations. The existing Trellis service, signing key and stored data remain unchanged. Core owns the reserved native policy slot.

## Decision and ownership

Use the existing authenticated service client, append coordinator, registered member writer, immutable artifact store and offline verifier. Fix Trellis authorization before cached replay, then connect application-owned immutable evidence through one server composition dependency. Genuine Source/WOS records remain required inputs. An applicant Submit, synthetic writer fixture or rendered notice does not establish actual custody or a complete archive.

Reviewed baseline: Trellis `ea8f547367e4d41d09395001230ccf14705af8c9`. The library supports060/061/062/063/065/open-clocks; `crates/trellis-server/src/lib.rs:260` supplies an empty list. No new ZIP writer, public arbitrary catalog upload, business event builder or certificate format is proposed.

## Exact existing inputs and their authorities

| Input | Existing type and source | Authority |
| --- | --- | --- |
| Original accepted filing | `AcceptedIntakeEvidence { source_id, accepted_response_ref, workspace_id, environment_id, snapshot }`, WOS ports `intake.rs:86–100` | Source retained acceptance, original Response/history, validation, signature and historical artifacts; WOS qualified reader checks associations. Mutable drafts/reports are insufficient. |
| Original authored artifacts | `IntakeArtifact { kind, url, version, sha256 }` | Exact retained Source artifact bytes; URLs identify admitted resources, not caller-selected destinations. |
| Attachments | `IntakeAttachment { id, response_path, media_type, sha256, byte_length }` and `IntakeAttachmentContent` | Source bytes plus current WOS case/resource permit; original digest and byte length must match. |
| Native custody record | `CustodyAppendInput` plus `ProvenanceRecord`, `CustodyAppendContext` | Committed WOS native transition, not an export-generated event. |
| Transport request | `WosProvenanceAppend { scope, tenant_scope, idempotency_key, actor, record, compute_context }` | Host-selected service identity and exact canonical case ledger scope. Applicant identity and service producer remain distinct. |
| Append receipt | `SubstrateAppendResult` / `TrellisCustodyAppendOutcome`; `CustodyAppendReceipt` retains canonical event hash | Maintained signed append and independently checked export; durable WOS receipt enrichment must retain the actual outcome. |
| Offline archive | `SubstrateClient::bundle(scope, checkpoint_digest, tenant_scope)` | Pinned immutable publication under the actual receipt checkpoint, then full Core and WOS/Integrity verification with independently accepted public-key authority. |

WOS's `TrellisCustodyAppender` currently concatenates its prefix, case ID and provenance ID into a key exceeding the normative64-byte bound with native IDs (`custody_trellis.rs:208–213`). Core owns the separate shared-hash repair and real Core/router replay test. Its server call site and durable receipt bridge remain absent/refused in the traced adapters. Those are WOS-owned prerequisites, not problems a Trellis export can conceal.

## Trellis authenticated request shape

Current `ScopeAuthorization` carries actor/scope/action/JWT scope labels but no tenant quad (`trellis-server-ports/src/lib.rs:516–522`). Built-in scoped authorization only compares URL scope labels (`admission.rs:37–60`). Header extraction expresses a request; it does not establish a grant. Append authentication currently runs inside the handler after shared middleware can return cached replay (`http.rs:36–39,97–112`). This is a concrete owning gap.

Proposed composition:

1. Inject maintained `stack_common_auth::AccessTokenVerifier` for an explicitly selected external access-token mode. The host constructs the maintained `OidcCurrentAuthority` adapter with fixed issuer, API audience, allowed clients, required API scopes and operational clock, including original-token introspection on each request. A signature/time-only `OidcAccessTokenVerifier` does not establish current revocation and cannot satisfy the promised revoked-token checks. No bespoke JWT/OIDC parsing or token persistence.
2. Resolve verified issuer/subject/client to a host-owned principal and exact allowed `TenantScope { tenant, workspace, environment, cell }`, canonical ledger scope and `ScopeAction`. Extend the existing authorization request with verified identity facts and requested tenant context. Let the existing `ScopeAuthorizer` return an authorized context containing its host-resolved internal principal and admitted tuple/action, replacing its unit result; this keeps mapping and granting in one existing port. Authentication never invents an internal principal from the external subject. Explicit configured service grants may serve a local test; their existence and exact values must be supplied by the host, never inferred from request headers or OAuth scopes.
3. Run authentication and current tuple/action authorization before idempotency reservation/replay and before reads. Build a trusted replay partition from the authorized principal and tenant quad plus route; use the existing shared `TrustedReplayPartition` mechanism. Do not trust caller tenant headers as the partition authority. Each retry rechecks current token authority and grants; a cached outcome does not bypass revoked credentials/grants. Pinned bundle and registry retrieval require Read. `GET .../bundles/head` always invokes publication and may update head, so it requires both Read and the existing Administer action before publication; Read alone does not authorize that effect. Append-authorized initial publication remains part of the explicitly admitted Append operation.
The HTTP boundary rejects an empty returned principal or any returned tenant/scope/action that differs from the exact request; tests cover foreign permits. For Append, the existing authorization request also carries a borrowed `SubstrateAppendBody` so the host-owned authorizer can admit the asserted transport actor and any required application-owned delegation from the exact payload. Trellis does not infer a human from WOS-specific JSON. A service Append grant alone permits neither arbitrary asserted actors nor arbitrary human delegation. Recheck current delegation before cached replay; parse once with a bounded body limit and retain the same parsed body for the handler. Read requests carry no append body.

4. Preserve explicit legacy local-token/development selection as its own declared posture. External-token mode fails closed and does not fall back to HS256 or permissive mode. The baseline memory service is not reconfigured by this private work.

The concrete grant resolver/configuration and selected fresh service identity are not yet supplied by the deployment owner. This is a required BEFORE-review decision. Persisted WOS human principal mapping is not repurposed as a Trellis service grant. The new request context alone cannot prove durable storage tenant isolation; canonical case scopes must be uniquely assigned and grants exact.

## Frozen evidence provider shape

Add one composition-injected provider returning the existing `Vec<ExportEvidenceMember>` for the exact immutable ledger snapshot: canonical scope bytes, signed `StoredEvent` array, seal version/event count, high-water sequence/hash, generated timestamp and existing export-attempt identity. It accepts no browser-supplied catalogs or mutable latest-case request.

The application-owned implementation must pre-stage and fix required original evidence before the first append-triggered publication for that identity and retain those same bytes for replay/head regeneration. It must refuse missing referenced bytes or an unavailable original source; it must not turn unavailable evidence into an empty successful result. No provider implementation is qualified until WOS/Source supplies its actual retained record association and snapshot authority.

The first publication cannot emit an incomplete archive and discover new members later under the same identity: `export_attempt_id` currently depends only on scope/seal/high-water event (`lib.rs:302–320`). Either the owning input is already fixed for that event snapshot, or publication refuses. Reader-specific disclosure variants are outside this identity and require a separately reviewed publication model. Existing immutable artifact storage remains the byte-conflict enforcement point.

Any supplied evidence family forces the maintained composed profile verification before immutable publication, alongside mandatory Core verification. The current066/067/068-only predicate is insufficient (`export_profile.rs:42–48`). Derivation remains in WOS/Source/Integrity-owned adapters; generic Trellis binds opaque bytes through its existing writer.

## Meaningful qualification and next runnable fresh test

Private tests first reproduce authenticated cached replay returning before handler authorization, then verify missing/expired/revoked credentials, wrong issuer/client/audience, denied tenant/workspace/environment/cell, wrong ledger scope and denied action all refuse before cache or effects. Matching authorized retries must return the same accepted result without another event. Tests use maintained verifier/identity ports and real router/Core boundaries; no live baseline or business history is fabricated.

After Core's native retry-key repair and WOS's maintained durable producer are available, Runtime coordinates the real scenario:

1. Create a fresh genuine accepted Source filing through maintained Sign/Submit and automatic handoff; retain original acceptance and exact historical associations. Do not backfill the old empty scope.
2. Execute required WOS native checks, corrections, notices and decisions; actual issuance/delivery evidence remains distinct from `render_adverse_notice` returned content. Retain committed outcomes and pending custody intents.
3. With an explicitly admitted service principal and exact tenant/scope/Append grant, invoke `TrellisCustodyAppender::append_window` through `TrellisServiceClient`; persist genuine custody receipts through the owning durable adapter. Replay the same window with no additional event.
4. Read the actual receipt-pinned bundle through `SubstrateClient::bundle`, with separately checked Read and output/resource authority. Head retrieval may publish/update state, so it is an explicitly authorized operation, not a read-only diagnostic.
5. Verify signed native record identities, counts, predecessor hashes, original accepted filing/attachments and complete requested evidence families. Retrieve identical pinned bytes again.
6. Run maintained `verify-export <actual.zip> --format json` and independent Python checks over those exact bytes without network access, using Integrity's separately reviewed external public-key acceptance boundary. Refuse missing bytes, changed source identities and revoked output access.

No passing D1 result is claimed before these owning operations execute. The current baseline's historical404/noevents and the prior synthetic writer GREEN remain separate evidence.

## Improvement and acceptance

Reuse one shared authentication verifier, one authorization port, one idempotency mechanism, one evidence-selection dependency and one existing writer. This removes the auth-before-cache gap and avoids independent per-family assembly. No speed or resource improvement is claimed. Production source changes require independent full CODE and ARCH BEFORE/AFTER reviews, an observed meaningful RED→GREEN and the next explicitly granted native window. The private proposal does not authorize service/key/data replacement.
