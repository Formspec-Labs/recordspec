# Inactive Source native Trellis configuration: BEFORE architecture review

**VERDICT: APPROVE exact inactive configuration preparation.** The new receiving identity uses Root's actual signed Source service identity, with only read/append on the native `formspec.managed-single-cell` scope and exact service actor. The outbound profile follows the existing closed schema and maintained token provider. Activation, Source adapter adoption/native qualification, receiving reload and actual custody/readback remain separate gates.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-10. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied. Only this certificate written. Read-only files/source/digest checks; no scripts, native commands, HTTP, process/DB inspection, activation or secret-value output. Files inspected are inactive preparation inputs, not evidence of receiving-host state.

## 1. Artifact summary

Private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`. Category: deployment preparation/proof infrastructure.

| Exact input | SHA256 |
| --- | --- |
| `oidc-profile-source-native-v8.json` | `55589b8ee357064b9eb648411253d5cacb27b559e2e8017fe4593f8ccc3492bf` |
| `current-grants-source-native-v8.json` | `ec5b8c592da9bc620d41b7c3c85836c8c4fa071f8045585539e19be9ae531cd9` |
| `source-trellis-service-v1.json` | `4e35471efa4b36742a30c4af131bebaf1458ca84415ab4f49256b4ccd9026e02` |
| Materialization report | `2898f72550307f50668bbababcd8d3ba630d42bb4b7be3e52184568384e0ce9f` |
| Root `external-service-identities-v1/continuation-execution-result.json` | `00697ef44c7ec1f0ac0140f7237e9370d4cac3c949fccd08fd54a9bc15d70cbe` |
| Source private `auth_config.rs` | `30905dead3147ef1c1243ec83deccdd0727f43a0a22104057ccb71fd7ef3168a` |
| Trellis private `oidc_startup.rs` | `71dd47b97397db3c413fae946d426a9216fdb875a9d72f083550b910d368ea63` |

All report/config/identity hashes independently match. Three new configuration files are0600. Selected credential file is existing regular/private0600 and nonempty; no contents exposed. This is static metadata evidence, not credential validity.

## 2. Lineage and relationships

| Prior artifact / source | Relation | Citation |
| --- | --- | --- |
| Root actual identity result | Authoritative signed-readback identity, not receiving authorization | `clients.formspec-source-trellis-dev`, status |
| Preserved exporter-v6 receiving profile | Prior WOS/exporter mappings remain | Profile `identities`, `allowedClients`; independent subset comparison |
| Existing selected first-start certificate | Receiving startup previously qualified, grants intentionally separate | `trellis-bounded-outer-after-actual-architecture-review-v3.md:§3,§6` |
| Source private auth composition | Closed service profile and maintained provider | `/tmp/formspec-task-drafts-20261009-v1/formspec-server/crates/formspec-server/src/auth_config.rs:706–756` |
| Native Source namespace | Canonical scope reused without case remapping | Same private Source `composition.rs:97,1010–1030` |
| Maintained receiving current grants | Exact issuer/subject/client, deployment, action scope and actor checks | `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis/crates/trellis-server/src/oidc_startup.rs:350–431` |
| Goal/philosophy | Durable inspectable evidence remains the outcome | `GOAL.md:28`; `DEVELOPMENT-PHILOSOPHY.md:384–388` |

| Named seam | Owner | Input → output | Boundary |
| --- | --- | --- | --- |
| Client registration/signed identity | Root/provider | Actual service subject → registration/readback receipt | Does not grant application rights |
| Source outbound credentials | Source composition/Common | Closed profile → maintained OIDC token provider | Audience membership/required scopes; native qualification pending |
| Maintained client injection | Source adapter/Trellis client | Provider → current token per request | No respondent bearer or custom OAuth implementation |
| Receiving identity/current grants | Trellis/operator | Verified identity + tenant/action/native actor → permit | Per-request grant authority; inactive until reviewed reload |
| Native payload semantics | Source | Authenticated service writes native payload | Trellis does not invent respondent/human delegation checks |

## 3. Invariants and commitments

**Actual identity — PRESERVED.** Root receipt status is actual two-client registration/signed-token readback PASS; selected client `formspec-source-trellis-dev` has subject `87af7ce6-4294-4a4b-898b-4ecd486d104f`, issuer `http://127.0.0.1:18090/realms/formspec-dev`, scopes access/read/append. New receiving binding maps exactly that triple to `source-native-producer`; no subject guess or alias. Receiving current authority independently maps the verified identity (`oidc_startup.rs:358–377`). This local development loopback policy is not production TLS guidance.

**Existing authority — PRESERVED / NEW narrow grant.** Profile differs from preserved exporter-v6 only in allowedClients, identities and selected grantsFile. All prior identity objects remain unchanged. Tenant/workspace/environment/cell tuple remains the selected single deployment. Two grants only: read and append on exact `formspec.managed-single-cell`; no Administer or WOS case scope. Existing static actionScopes remain unchanged. Receiving authorization requires exact tenant tuple, mapped principal, required OAuth action scope and exact resource/action row (`:359–398`). Identity permission and local grants remain distinct.

**Native actor — PRESERVED without new language.** Append allows only `{kind:service,subject:formspec-server}` and empty payloadActors. Current authorizer compares both transport actor fields (`:401–408`); empty payloadActors means no configured native payload human selector checks (`:410–420`). This intentionally authorizes the selected service to produce native Source records; it is not proof of individual human delegation or legal signing assurance. Root explicitly selected this scope; Trellis must not introduce WOS actor interpretation, eventType allowlist or another authorization language.

**Maintained outbound shape — PRESERVED in source/static configuration.** Service file exactly matches the closed camelCase/deny_unknown_fields version1 fields (`auth_config.rs:710–725`), endpoint18198, WOS headers, trellis-api audience, selected single allowedClient and access/read/append scopes. Trust requiredScopes are nonempty and subset of requested scopes. `registeredClient` and clientSecretBasic reuse maintained credentials/provider (`:727–756`). Source composes native namespace through `TrellisSubstratePublisher::with_token_provider` (`composition.rs:1010–1030`; adapter `lib.rs:109–118`), which delegates to maintained Trellis client. Required standard audience membership/scopes do not require audience singleton equality. No new OAuth or token cache is introduced by these JSON files.

**Inactive preservation/lifecycle — RELIED-UPON declared preparation scope.** Report states activeFilesChanged false and no execution. Existing profile/grants remain preserved. This reviewer inspected only preparation files and did not independently inspect live process selection. Subsequent reload must preserve existing DB/key/backend and native custody; the first-start wrapper requires empty public tables and is ineligible for existing nonempty DB. Do not reuse that command as a reload method.

## 4. User-value analysis

This prepares genuine Source-native custody through maintained service identity rather than using a WOS case grant or forwarding a human bearer. It adds one identity and two narrow native-scope rows, retaining established auth interfaces and Source semantics. Smaller reuse of a WOS producer identity would blur ownership; broader Administer/case grants would add authority without helping Source append. No performance claim applies. Value is falsified if qualified Source current-token appends cannot reach the native scope or resulting maintained archive bytes cannot be read/verified.

## 5. Counterfactual analysis

Kill criterion: identity receipt/config mismatch, a borrowed audience/client, changed deployment tuple, extra case/Administer grant or native actor mismatch. Removing preparation leaves genuine Source service unable to reach strict Trellis admission. Opposite decision adds custom OAuth or permissive fallback, duplicating maintained components. Existing Common provider and Trellis current grants subsume the required mechanics. Future critic should challenge conflation of service custody with authenticated human signing and inactive files with live authority; both claims remain excluded.

## 6. Findings

**F1 — KEEP; OBSERVATION; authority/ownership.** Exact authoritative Source identity, native scope and service actor satisfy Root-selected preparation. Preserve WOS/exporter maps and current actionScopes; no WOS case or Administer grant belongs here.

**F2 — KEEP; OBSERVATION; simplicity/named-seam.** Use closed Source service schema, maintained OIDC client credentials and maintained client injection. Receiving Trellis identity/grants remain the access authority. Standard audience membership and required-scope checks are the existing semantics; do not add singleton-audience rules or event allowlists.

**F3 — DEFER; OBSERVATION; evidence/lifecycle.** Source dependency adoption/native qualification, reviewed receiving reload with existing storage preserved, actual current-token Source append, native receipt/readback and owning archive validation are mandatory successors. Preparation alone establishes none. No blocking RESHAPE or REVERSE applies to these exact inactive files.

## 7. Verdict

**APPROVE exact inactive preparation.** Intent MATCHES; user-value SUPPORTED; commitments HONORED in static inputs; conceptual debt PAYS DOWN identity ambiguity/reuses maintained paths; sibling subsumption PARTIAL/reused; confidence HIGH for exact config/source comparison, execution unqualified.

All six phases applied. H1 subject is guessed REFUTED by pinned actual Root identity. H2 native grants borrow WOS/case/Administer authority REFUTED by exact two rows. H3 empty payloadActors proves human delegation REFUTED and claim limited to service custody. H4 configuration files are active REFUTED as a permitted review claim: no live-selection evidence was inspected; inactive status is author-reported scope. No phase skipped. No live/native/config mutation occurred.
