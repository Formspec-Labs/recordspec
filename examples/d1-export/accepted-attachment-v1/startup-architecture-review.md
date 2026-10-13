# Accepted-attachment startup composition: architecture review

**VERDICT: APPROVE — source repair qualified by the focused startup RED/GREEN.** No unresolved architecture blocker remains. This approval covers the exact files below; it does not qualify a running host, actual reader custody, attachment admission, download readability, or an offline export.

| Artifact | SHA-256 |
| --- | --- |
| `crates/trellis-server/src/oidc_startup.rs` | `5766e297edc145bb25ac19dba5b127ab3a87c74a2123e09f00f39f21547be0a2` |
| `crates/trellis-server/src/oidc_startup_tests.rs` | `a0babe389eae64e16c7f9ad6f88242ffae4c6bfb20ebcde19b6f704e4212e061` |
| `crates/trellis-server/OIDC_STARTUP.md` | `ca07aeb77b9e1dcbcd508e53cbf4f650c9cafde2159d1844fa3ab40545045f21` |

Paths below are relative to the Trellis repository unless explicitly prefixed with `formspec-stack/`. The reviewer used the semi-formal architecture-review skill and the Rust skill's universal, library, interoperability, resilience and API-design guidance. The reviewer performed static inspection and read the parent-run test receipts; no build, service call, configuration change, key generation or case operation was performed by this review.

## Findings first

1. **RESOLVED — explicit null must fail startup.** The initial candidate treated `acceptedAttachmentRecipients: null` as omission. The final deserializer accepts a vector and wraps it in `Some`; omission alone uses the field default (`oidc_startup.rs:158-159,202-210`). The negative test includes null and empty lists (`oidc_startup_tests.rs:538-554`); the guide explicitly distinguishes omission from null (`OIDC_STARTUP.md:112-114`). **KEEP** this fail-closed distinction.
2. **OBSERVATION — configured custody is not independent ownership proof.** Public keys and `operatorHeld` describe the operator-selected reader policy; neither verifies who controls a private key (`oidc_startup.rs:171-176,316-320`; `external_transport.rs:39-46,98-121`). The Root-authorized fresh LOCAL Jordan export-reader key is a local/demo custody selection. It must not be described as proof of an external human's independent key control. **KEEP** private reader bytes outside Trellis and Git and retain this local qualification.
3. **OBSERVATION — selection changes require deliberate retention.** The selector is immutable after startup (`oidc_startup.rs:179-198`), and existing transport fingerprints key versions, public keys and custody into replay identity (`external_transport.rs:212-235`). Replacing a profile is not an identical-authority retry. **KEEP** the restart-only selection rule and retention of historical reader keys and attachment bytes (`OIDC_STARTUP.md:128-133`). This repair adds no key-rotation or historical-key resolver.

## Artifact summary and decision frame

The existing accepted-attachment route has a recipient-selection dependency but ordinary startup never supplied it: a missing selector returns HTTP 503 after authorization (`external_transport.rs:194-209`). The repair extends the existing private OIDC profile with optional `acceptedAttachmentRecipients`, validates selected rows, and installs an immutable implementation through `with_external_attachment_recipients` (`oidc_startup.rs:59-71,129-137`). OIDC means OpenID Connect, the existing token-verification and identity-mapping setup.

This is a product-enabling composition repair with proof supplied by startup tests. It makes normal configured startup capable of supplying the already existing attachment path. It does not create a new recipient port, authorization service, environment setting, cryptographic algorithm, namespace or grants policy. The beneficiary is a deployment owner who needs the existing accepted-attachment operation to use explicitly selected reader public keys.

## Lineage and relationships

| Prior artifact | Relation | Evidence |
| --- | --- | --- |
| `formspec-stack/thoughts/adr/0072-stack-evidence-integrity-and-attachment-binding.md` | Parent decision separates originating evidence meaning and actor authority from Trellis encrypted-byte carriage | D-3, D-4, D-7 |
| `specs/trellis-core.md` | Normative parent requires ciphertext integrity and separately reported readability | §18.2, §18.3, §19; omission rule near line 1269 |
| `crates/trellis-server/OIDC_STARTUP.md` | Existing private startup file, tenant binding and fresh resource grants constrain this extension | lines 3-13,79-97 |
| `crates/trellis-server/src/external_transport.rs` | Existing recipient port, transport validation and replay identity are reused | lines 39-59,87-123,194-235 |
| `examples/d1-export/accepted-attachment-v1/handoff.md` | Earlier bounded preparation distinguishes library adoption from export wiring | preparation and qualification paragraphs |

| Component or boundary | Owner | Inputs and outputs | Declared seam |
| --- | --- | --- | --- |
| Private startup profile | Trellis deployment owner | Closed profile → validated reader rows | `oidc_startup.rs:141-176,277-334` |
| Startup composition | Trellis server bootstrap | Validated rows → installed selector | `oidc_startup.rs:129-137`; `state.rs:558-623` |
| Current authorization | Existing verifier and current-grants authorizer | Verified identity/request → append permission | `oidc_startup.rs:528-573`; `external_transport.rs:194-202` |
| Recipient selection | Existing Trellis recipient port | Exact permission → configured public keys | `external_transport.rs:48-59`; `oidc_startup.rs:184-198` |
| Protection and replay | Existing attachment transport | Selected public keys → existing custody policy and replay partition | `external_transport.rs:87-123,212-235` |
| Actual private reader key | Local/demo reader owner | Private key → later reader decryption | Not supplied to Trellis; guide `112-119` |

The originating Source/WOS attachment semantics remain outside this selector. Ignoring caller descriptor fields for key selection is deliberate: current grants separately govern admitted actors and payload fields, while the selector fixes custody for the exact authorized principal and ledger scope (`external_transport.rs:184-209`; `oidc_startup.rs:548-565`).

## Invariants and commitments

| Statement | Status | Evidence | Failure meaning |
| --- | --- | --- | --- |
| Authenticate and check fresh grants before selecting readers, including replay | PRESERVED | `external_transport.rs:194-209`; `oidc_startup.rs:528-573` | Revoked authority must not survive a cached request |
| Match exact tenant tuple, principal, scope and append action | PRESERVED | `oidc_startup.rs:191-198`; tests `628-662` | A foreign permission must not receive reader selection |
| Caller descriptors do not select keys | PRESERVED | Selector ignores descriptor, `oidc_startup.rs:186-198` | Untrusted requests must not redirect ciphertext custody |
| Validate selected configuration before signing keys/storage | PRESERVED | `oidc_startup.rs:59-76`; `state.rs:558-575` | A selected-invalid host must fail before opening protected resources |
| Omission preserves existing deployments; selected invalid data refuses startup | PRESERVED | `oidc_startup.rs:158-159,202-210,280-324`; tests `538-624` | Silent disablement would defer configuration failure to requests |
| Private keys stay outside the startup profile and server | RELIED UPON | Public-key-only fields `oidc_startup.rs:171-176`; guide `115-119` | Operator custody assertions alone cannot establish independent ownership |
| Preserve existing attachment bytes, schemas and cryptography | PRESERVED within source diff | Only startup source, startup tests and guide change | No retention or wire-format migration is introduced |

Selected rows are bounded to 1024 and recipients to 64; IDs are bounded to 256 bytes. Existing private file reads remain capped at 1 MiB (`oidc_startup.rs:28-29,283-324`). These limits make validation finite; this review makes no measured speed or memory improvement claim.

## User-value and counterfactual checks

The concrete improvement is a missing startup dependency becoming usable through an existing maintained port. There is one deployment profile, one admitted-principal mapping and one grants path. Adding a separate registry or environment-driven selector would duplicate deployment and scope authority. Reusing the profile and existing selector pays down the missing composition step without adding another framework.

- **Kill criterion:** configured selection bypasses current grants, accepts a mismatched permission, permits caller-directed keys, or opens storage before invalid selection fails. The cited source order and focused tests oppose those outcomes.
- **Opposite decision:** keep startup unchanged; a valid attachment request still reaches the existing unconfigured-selector HTTP 503 (`external_transport.rs:203-208`). The genuine focused RED compiled and failed at `StartupAuth::load` rejecting the newly selected profile.
- **Removal probe:** removing the extension makes ordinary startup unable to provide the route's recipient dependency; programmatic test injection remains available.
- **Sibling subsumption:** existing transport fully supplies authorization ordering, protection, custody interpretation and policy-bound replay. This repair adds only profile parsing and composition.
- **Future critic:** a mutable profile change cannot prove old originals readable or old keys retained. A later custody change needs explicit reader-key retention and its own end-to-end evidence. This bounded repair makes no such claim.

## Validation and final certificate

Parent-run focused RED: `oidc_startup_composes_selected_attachment_recipients` compiled and failed at the current closed profile refusal, exit 101. Receipt: `/private/tmp/trellis-attachment-startup-20261012-v1/red.json`; log SHA-256 `178b0b20014cf27c9837d4dca2d6046f6c3198325cf5b01a1f949aa4a0e7eb93`.

Parent-run focused GREEN: `cargo +1.94.0 test --offline --locked -p trellis-server --lib oidc_startup -- --test-threads=1`, exit 0, **15 passed, 0 failed, 138 filtered**, test runtime 0.22 seconds. It includes the new composition, optional/fail-closed and exact-permission controls plus existing token/current-grant/revocation checks. Receipt records the owned group absent and locks released. Receipt: `/private/tmp/trellis-attachment-startup-20261012-v1/green.json`; log SHA-256 `5b66d011cc08574cfa5b45fcad48add99372fe96022c4aa71eed40be06692681`. The reviewer read these logs/receipts and rechecked all three exact source hashes after GREEN.

**APPROVE.** Intent and shape match; user value is supported; commitments are honored; conceptual debt decreases by completing existing composition; sibling subsumption is partial and deliberate. Confidence is high for source structure and focused startup behavior. Live adoption, actual attachment admission, key custody, original readability and offline verification remain unqualified by this certificate. No current namespace, grant, ledger key, operator key or live profile was changed by the reviewer.
