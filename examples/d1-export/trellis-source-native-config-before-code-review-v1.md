# Source native Trellis configuration — focused static BEFORE review

Review ID: TRELLIS-SOURCE-NATIVE-CONFIG-BEFORE-V1-2026-10-10. Independent nonauthor `/root/oidc_code_review`. Applied full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` proportionally to configuration materialization. Only this certificate written. No scripts imported/invoked, HTTP/native/process/DB actions, configuration activation or secret printing.

## Findings and decision

**APPROVE exact inactive files for static configuration preparation. No blocking schema/pin/grant inconsistency found.** This does not establish runtime configuration loading, current token acquisition, adapter adoption, Source append or export/restart readiness.

F1 — OBSERVATION / prerequisite / Source auth_config.rs:576–610,726–744. Service loader also requires runtime endpoint equality, nonproduction loopback permission and disjoint application trust audience/clients. These depend on the selected ServerConfig/application profile, outside the three-file packet. Struct/schema compatibility is verified; final actual Source composition and application-trust separation must be qualified before activation. No outgoing exact audience/scope-set assertion is introduced: maintained token verifier uses audience membership and required scopes.

F2 — OBSERVATION / authorization / current-grants-source-native-v8.json. Append grant intentionally has payloadActors=[]: no payload-human selector restriction is imposed by this grant. Exact service actor is still required. This implements the explicitly requested Source service authority, not a WOS human/case delegation policy. Any later need for payload-human authorization requires an explicit reviewed selector change, not inference from this certificate.

## Scope and patch summary

Read all three inactive JSON files, authoritative Root continuation receipt, original exporter profile, maintained private Source loader/schema and Trellis current-grant validator. Profile delta is exactly allowedClients plus Source identity plus grantsFile successor. Existing WOS/exporter identity entries match the prior profile byte-equivalent values. Tuple, issuer, required access scope, audience, introspection settings and actionScopes remain unchanged. New grants are exactly Source principal/formspec.managed-single-cell Read and Append, with Append actor kind=service/subject=formspec-server, no payload selectors, no Administer, no WOS case grant. Original active profile/grants are not edited by reviewer and materialization receipt states inactive.

## Function traces

| Config / function | Location | Inputs → behavior/output |
|---|---|---|
| Receiving identity profile | oidc-profile-source-native-v8.json identities/allowedClients | Root signed-identity receipt issuer/client/subject → static Source stable principal source-native-producer. Existing two identities preserved. |
| CurrentGrants::validate_current | Trellis oidc_startup.rs:304–347 | Exact tuple/known principal/resource/action and actor arrays → validated Read/Append rows. Nonappend has no actors; append has one unique nonempty service actor; empty payloadActors is permitted. |
| CurrentGrants::authorize | same:354–427 | Current verified identity/body and freshly loaded grants → exact tuple/action/OAuthscope/service actor → permit or refusal. Activation/token behavior not run. |
| trellis_credentials | Source auth_config.rs:706–754 | Closed version1 ServiceFile plus ServerConfig/endpoint → maintained current token provider and WOS HeaderConfig; rejects unknown shape, endpoint/client/scope/assurance mismatches. |
| TrustFile/CredentialFile | Source auth_config.rs:49–65,127–145 | JSON camelCase trust plus clientSecretBasic/path → exact typed shape. No borrowed intake credential structure. |
| require_separate_application_trust/check_delivery_transport | same:576–641 | Candidate trust/application profile/environment → disjoint audience/client check and development-only loopback transport allowance. Runtime prerequisite F1. |
| client_credentials | same:644–678 | Private credential path → maintained StaticClientSecret/OidcClientCredentials; values stay private; no new OAuth implementation. |
| Source composition caller | composition.rs:1021 | Selected service config/URI → trellis_credentials provider/header injection. Caller native qualification remains pending. |

## Data flow and invariants

Source identity comes from retained Root receipt00697ef4…; its Source subject87af7ce6-4294-4a4b-898b-4ecd486d104f, issuer and client agree with profile. Receipt scopes trellis.access/read/append and audiences include trellis-api; outgoing required scope set is contained in requested scope set and client is in allowedClients. Extra signed audience facts are not rejected by an exact-set rule. Service endpoint fixed18198, header vocabulary wos matches receiving mode, assurance registeredClient and clientSecretBasic credential path exists0600. Credential bytes were not displayed or copied.

Receiving grant tuple equals profile four-part tuple. Resource literal formspec.managed-single-cell is unique for both actions; service actor pair exact. No Administer is added. Profiles are inactive successors: no claim that existing service has loaded this grantsFile or that current authority admits Source. Fresh actual-token append/archive proof remains distinct from static configuration.

## Tests, edge cases and exploration

Reviewer executed no tests/loaders. Inspected loader assertions/closed structs and retained native Source tests at auth_config.rs:975–992: good version1 configuration, missing/unsupported header mode and unsupported assurance refusal. This certificate does not claim those tests ran for this file. Concrete static checks: JSON parses, known keys/method/assurance/header enum match, requiredScopes subset, fixed endpoint/trust/current scope and retained Source identity agree, two grant rows/no duplicates, preserved WOS/exporter bindings, private modes0600 and owner501, credential path exists0600. Runtime endpoint string formatting, selected application trust and environment are not evaluated by actual loader (F1).

H1 copied service shape comes from incompatible intake schema: REFUTED by maintained ServiceFile/CredentialFile comparison. H2 Source identity is guessed: REFUTED by exact retained signed Root receipt match. H3 grants elevate WOS case/export authority: REFUTED by exact two Source resource rows and no Administer. H4 static materialization proves Source adoption: REJECTED; native composition/reload/current-token qualification pending. No unresolved blocker within this inactive scope.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-source-native-config-materialization-v1.json` | `2898f72550307f50668bbababcd8d3ba630d42bb4b7be3e52184568384e0ce9f` |
| `continuation-execution-result.json` | `00697ef44c7ec1f0ac0140f7237e9370d4cac3c949fccd08fd54a9bc15d70cbe` |
| `auth_config.rs` | `30905dead3147ef1c1243ec83deccdd0727f43a0a22104057ccb71fd7ef3168a` |
| `oidc-profile-source-native-v8.json` | `55589b8ee357064b9eb648411253d5cacb27b559e2e8017fe4593f8ccc3492bf` |
| `current-grants-source-native-v8.json` | `ec5b8c592da9bc620d41b7c3c85836c8c4fa071f8045585539e19be9ae531cd9` |
| `source-trellis-service-v1.json` | `4e35471efa4b36742a30c4af131bebaf1458ca84415ab4f49256b4ccd9026e02` |

All three declared file digests and authoritative identity receipt match. All three files have0600 and effective-owner UID501. Original exporter profile delta independently compared; no secret values included.

## Conclusion

VERDICT: APPROVE exact inactive static materialization.

Coverage: ADEQUATE for schema/pins/delta/authority shape; INSUFFICIENT for loaded runtime state, actual application-trust/environment composition, token acquisition, native adapter and append/export outcomes. Confidence: HIGH for inspected static facts. Root's reviewed reload must preserve existing DB; first-start empty-DB launcher is ineligible. No active configuration or service changes performed.
