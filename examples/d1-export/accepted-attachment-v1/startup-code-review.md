# Independent accepted-attachment startup code review

Verdict: **APPROVE the exact source repair**. No unresolved code blocker; compiled startup tests pass. This review covers startup composition, not a live deployment or an attachment to a real case.

## Exact selection

| File | SHA-256 |
| --- | --- |
| `crates/trellis-server/src/oidc_startup.rs` | `5766e297edc145bb25ac19dba5b127ab3a87c74a2123e09f00f39f21547be0a2` |
| `crates/trellis-server/src/oidc_startup_tests.rs` | `a0babe389eae64e16c7f9ad6f88242ffae4c6bfb20ebcde19b6f704e4212e061` |
| `crates/trellis-server/OIDC_STARTUP.md` | `ca07aeb77b9e1dcbcd508e53cbf4f650c9cafde2159d1844fa3ab40545045f21` |

Exact three-file `git diff -- <paths above>` SHA-256: `dbeae1597cde99d2733dee80f24d6a695ee089d8c54f86ba4fded183003595b9`.

Reviewed the entire applied diff and relevant callers/callees. Applied the semi-formal code-review skill and Rust universal, application, and library guidance. No Rust edits, Cargo invocation, service operations, key generation, configuration changes, or case mutations performed by this reviewer.

## Patch summary and traces

Normal startup previously left the existing recipient selector unset. The patch adds an optional closed selection to the private OIDC profile, validates it before signing/storage open, and installs it through the existing state method. It preserves omitted-field behavior and current resource grants. It adds no cryptographic implementation or dependency.

| Function/type | File:line | Input → output | Verified behavior |
| --- | --- | --- | --- |
| `StartupAuth::load` | `oidc_startup.rs:59` | private profile/dependencies → startup auth | Parses closed profile; validates recipient selection before introspection credentials; stores selector with existing verifier/authorizer. |
| `Profile`, `AttachmentSelection`, `AttachmentRecipient` | `oidc_startup.rs:143,165,173` | JSON → typed values | Closed camelCase records; public key is exactly 32 byte values. Missing new field defaults to None. |
| `deserialize_attachment_selection` | `oidc_startup.rs:202` | present field → Some rows or error | Uses Vec deserialization, so explicit null refuses; replaces detailed parser errors with fixed message. |
| `Profile::attachment_selector` | `oidc_startup.rs:277` | profile → optional immutable selector | Requires known principal, valid bounded scope, unique row, 1–64 distinct valid recipients, and at least one nonoperator reader; 1–1024 rows. |
| `ScopedAttachmentRecipients::select` | `oidc_startup.rs:186` | admitted permission/descriptor → cloned recipients | Requires Append and exact deployment tuple, then exact principal/scope. Descriptor does not choose recipients. |
| `attachment_invalid`, `attachment_denied` | `oidc_startup.rs:213,217` | failure → StackError | Fixed generic error text; mismatch returns FORBIDDEN with existing static error-code form. |
| `StartupAuth::apply` | `oidc_startup.rs:129` | auth/state → configured state | Preserves verifier/authorizer/posture; binds existing selector only when configured. |
| `TrellisServerState::with_external_attachment_recipients` | `state.rs:199` | selector → state | Stores the existing optional recipient port. |
| `state_from_env` | `state.rs:558` | startup environment → state | Loads StartupAuth before signing keys/storage, applies auth after constructing state (`:630`). |
| `external_transport::admit` | `external_transport.rs:138` | authenticated HTTP request → admitted attachment | Authenticates, validates descriptor/bytes, obtains current Append permission (`:194`), then invokes selector (`:209`) and existing custody checks. |
| `CurrentGrants::authorize` | `oidc_startup.rs:501` | identity/tenant/scope/action/body → permission | Preserved path rereads current grants per request, checks principal/action/actor and payload restrictions before returning permission. |
| `read_private`, `nonempty` | `oidc_startup.rs:578,613` | file/string → bounded input or refusal | Existing file ownership/permissions/no-final-symlink/regular-file and 1 MiB read cap; scope string capped at 2048 bytes without control characters. |
| Test helpers | `oidc_startup_tests.rs:489,498` | fixed public vector/descriptor → fixtures | Public fixture key; no deployment private key or custody assertion. |

## Data flow and invariants

1. The private profile supplies public keys and operator-held labels only. New structs have no private-key field and deny unknown fields (`oidc_startup.rs:163–177`). Detailed serde failures are discarded (`:202–210`), and validation errors reveal no key/selection values (`:213–222`). Existing private-file handling remains unchanged.
2. Validated selections become owned principal/scope/public-recipient values under one profile deployment tuple (`:316–334`). An Arc passes through StartupAuth to state (`:71,121,134–136`). Request selection clones at most 64 recipients; the immutable configuration changes only through successor startup.
3. The selector is a restriction after authentication and current-grant authorization. It cannot mint a permission or bypass actor/payload restrictions (`external_transport.rs:194–209`; `oidc_startup.rs:501` onward). Exact tuple/action/principal/scope comparisons prevent cross-tenant or cross-resource selection (`:191–198`).
4. Bounds match the existing transport's recipient count/ID/key requirements and add control/whitespace/duplicate-key rejection (`oidc_startup.rs:284–323`; `external_transport.rs:87–120`). The 1 MiB profile bound limits parse allocation; row limits bound subsequent work. The code checks key shape and zero-key rejection, not mathematical validation of every X25519 input. Existing encryption remains responsible for cryptographic refusal.
5. Validation completes before `state_from_env` reads signing keys or opens storage (`state.rs:558–566`). Omitted field preserves None; explicit null, empty selection, malformed nested records, and unsupported selection refuse rather than silently disabling protection.

## Tests and edge cases

| Test | Location | Assertion path and expected behavior |
| --- | --- | --- |
| `oidc_startup_composes_selected_attachment_recipients` | `oidc_startup_tests.rs:511` | Loads ordinary profile, calls actual apply, requires bound selector, selects exact Append permission, asserts one expected nonoperator recipient. Parent reported actual compiled RED before implementation; retained final GREEN log shows this test PASS. |
| `oidc_startup_attachment_selection_is_optional_and_fails_closed_when_selected` | `oidc_startup_tests.rs:539` | Asserts omitted field stays None. Loads each null/empty/duplicate/unknown-principal/bad-scope/empty-recipient/blank/control/257-byte-ID/zero-or-31-byte-key/operator-only/duplicate-ID-or-key/unknown-field/1025-row/65-recipient case and requires fixed invalid-selection error. |
| `oidc_startup_attachment_selection_requires_exact_admitted_append_permission` | `oidc_startup_tests.rs:628` | Mutates principal, scope, tenant, or action independently; each actual selector call must return fixed selection-required error. |

The tests cover the new parser, state-binding, and selector branches. They do not invoke an actual process via `state_from_env`, exercise a deployed current-grant revocation, or prove a live reader can decrypt a real attachment. The traced existing startup and request callers establish integration statically; compiled test results and runtime qualification remain separate gates. Oversized-row/recipient fixtures use distinct values, so duplicate validation cannot mask the intended count checks. Errors use generic text, including nested unknown fields.

Compiled evidence inspected: `/private/tmp/trellis-attachment-startup-20261012-v1/green.json` records exit 0 for `cargo +1.94.0 test --offline --locked -p trellis-server --lib oidc_startup -- --test-threads=1`, 9.548 seconds total, owned group absent, and locks released. `green.log` SHA-256 `5b66d011cc08574cfa5b45fcad48add99372fe96022c4aa71eed40be06692681` shows all 15 existing/new startup tests PASS, 138 filtered, 0.22-second test runtime, including each new test named above. This reviewer read and hashed the retained evidence without invoking Cargo.

## Findings

No blocker found. The initial explicit-null ambiguity and missing advertised-bound controls were corrected in the reviewed selection (`oidc_startup.rs:208`; `oidc_startup_tests.rs:550–609`). OIDC documentation agrees with omission/null behavior, bounds, public-key-only input, exact permission matching, and restart-required changes (`OIDC_STARTUP.md:112–133`).

Observation: parser error classification checks for a fixed custom-error substring (`oidc_startup.rs:60–68`). This can affect which generic invalid message appears; it does not admit invalid input or expose parser details. No authorization consequence identified.

## Conclusion

VERDICT: APPROVE — exact source repair, supported by compiled startup GREEN evidence.

The exact diff repairs ordinary startup binding while retaining current-grant authorization, bounded closed input, and omitted-field compatibility. Coverage of new semantic branches is ADEQUATE by inspected assertions. Confidence is HIGH for the bounded source repair; compiled evidence verifies the 15 selected startup tests. No live-deployment claim follows from this review.
