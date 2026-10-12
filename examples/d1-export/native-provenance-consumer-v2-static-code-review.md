# Native provenance consumer v2 — independent static code review

Review ID: TRELLIS-NATIVE-PROVENANCE-CONSUMER-V2-STATIC-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Method: full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and applicable ms-rust review guidance; parent/Trellis instructions apply. Scope is frozen Trellis consumer source preparation against ea8f547 plus the bounded v2 correction. Only this certificate was written. No Cargo, tests, builds, native, network, live calls or source/lock changes were performed.

## Findings

No blocking consumer-source finding remains in the exact v2 preparation. **APPROVE source preparation only**, not compiled correctness, native qualification, joint helper acceptance, adoption or full D1.

F1 — RESOLVED / correctness / specs/trellis-http-api.schema.json:460. The prior relative reference resolved against the HTTP schema's absolute $id into the wrong host/path. V2 uses the owning canonical `https://wos-spec.org/schemas/wos-native-provenance-event.schema.json`; conformance/src/native_http_schema.rs:24–39 registers that exact owning resource before HTTP schema compilation. No duplicate schema is introduced.

F2 — RESOLVED / correctness / scripts/check-http-api-schema.py:24–30,157–161,259–268. The former expected event set parsed only canonical mappings and would reject the new generic literal. V2 resolves wos-events through the admission manifest's actual path, parses the shared generic constant and adds it separately to canonical literals. The checker also requires exactly one conditional payload reference matching owning schema $id. Canonical mapping stays unchanged.

F3 — OBSERVATION / test-coverage. Rust changes and the new schema conformance test are uncompiled/unexecuted in this review. The source packet labels this honestly. Existing unit tests do not qualify the actual complete runtime custody window, signed ZIP or Source/WOS/D1 evidence. Freeze the coherent physical Core/Trellis/Integrity closure and obtain coordinated native receipts plus paired AFTER review before adoption. Core helper's implementation is outside this bounded consumer approval.

F4 — OBSERVATION / maintainability / scripts/check-http-api-schema.py:24–30. Dependency discovery intentionally supports the current explicit path-dependency layout; workspace-inherited or registry-based wos-events would need a maintained resolver update. Current admission manifests use explicit paths, including this private candidate. No present failure found.

## Patch summary and context

The retained v1 consumer review covered the new generic client branch, service-only WOS admission, independent catalog and composition dispatch, HTTP/OpenAPI literal, consumer-owned offline check, native fixture and normative mapping. V2 corrects two schema/tool integration findings and adds an offline schema conformance test with dev dependencies. The current sixteen-file patch is `70961fa2e8b082897df65e1815453697c8b122c09c10bc1c526df5a9306d5e97`; packet is `c2cadd4c74e35891258d979c071a6749c5ad3cbce957d3687380c0cabc696e86`. All sixteen exact source pins match. Existing v1 production/client/admission/dispatch/offline Rust bytes are unchanged; new Rust is the conformance module and its registration. V2 spec prose documents offline resource registration. Private manifest path substitutions are qualification setup and are not in the adoption patch.

Base Trellis revision is `ea8f547367e4d41d09395001230ccf14705af8c9`. Candidate is `/Users/mikewolfd/Work/formspec-stack/.trellis-native-provenance-v2`. BEFORE pair remains joint proposal `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` and Core API `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82`. Shared owning API calls match the inspected helper; helper closure has separate owner reviews.

## Function trace

Paths below resolve beneath the private candidate; Core helper resides at the packet's private Core path.

| Function / seam | File:line | Inputs → outputs; verified behavior |
|---|---|---|
| wos_provenance_append_request | crates/trellis-service-client/src/wos_ext.rs:37 | Typed record/context → existing canonical request unchanged, or helper.from_record validated raw wrapper + shared generic event. Kind membership comes from enum, not copied kind list. |
| append_wos_provenance | same:97 | Calls request helper then maintained SubstrateClient.append_event. Raw custody validation before typed conversion remains Core producer responsibility. |
| OpenAPI event schema | crates/trellis-service-client/src/lib.rs:93 | Canonical literals + shared generic + Formspec literals → sorted event enum. |
| wos_event_type_specs / admit | crates/trellis-admission-wos/src/lib.rs:65,130 | Adds one generic spec; generic JSON → shared from_json or400, then neutral service-only metadata. Canonical path is unchanged. |
| default_admission_policy / specs | crates/trellis-server/src/composition.rs:214,242 | Registers generic literal in actual WOS dispatch separately from catalog generation. Avoids catalog-only acceptance gap. |
| OpenAPI parity | crates/trellis-server/src/openapi.rs:129,170 | Test compares HTTP and OpenAPI enums, accepts shared generic literal separately from canonical list. |
| validate_native_provenance | crates/trellis-verify-wos/src/native_provenance.rs:10 | Generic DomainEvent bytes → shared wrapped from_dcbor_slice; absent payload or invalid helper result → sanitized Failure tied to event hash. Other events skip this added check. |
| WosRecordValidator.validate_events | crates/trellis-verify-wos/src/validator.rs:22 | Existing rescission/clock checks plus generic check; existing specialized semantics remain separate. lib.rs:21 registers module. |
| parse_wos_event_types | scripts/check-http-api-schema.py:143 | Actual owner kind.rs canonical macro plus owner native constant → expected WOS set. expected_admitted_event_types:107 adds Formspec set. |
| check_defs | same:242 | HTTP defs + owning schema → errors if conditional ref absent/duplicate/wrong or event enum drifts. Existing CLI main invokes check set; no network/schema execution is added to checker. |
| native_provenance_http_schema_resolves_owning_resource_offline | crates/trellis-conformance/src/native_http_schema.rs:8 | Reads actual dev-dependency owner schema, registers URI/resource, builds HTTP validator, asserts valid native request then four invalid variants. Registered by lib.rs:10 under cfg(test). |
| Registry/Resource / with_registry | local referencing0.46.1 registry/mod.rs:134,187 and resource.rs:40; jsonschema0.46.1 options.rs:297 | Inspected APIs support owned resource add/prepare and borrowed prepared registry; validator lifetime stays within test. Test dev dependencies declare matching0.46 versions with defaults disabled. |
| owning NativeProvenanceEvent methods | Core native_provenance.rs:44 onward | Consumer calls from_record/from_json/from_dcbor_slice match agreed implemented API. This review does not independently approve whole Core validator/schema. |

## Data flow and invariants

Typed client records select generic route only when canonical_event_literal is None; helper validation creates the wrapper while retaining complete serialized source Value. Canonical branch serialization and route selection remain unchanged. Raw original custody bytes must have passed Core bare decoder before this consumer receives generic inputs; the typed helper alone cannot recover unknown fields already lost during deserialization. Auth and custody identity remain separate prerequisites.

Admission parses generic JSON Value and validates through owning helper, then emits existing neutral metadata. Original payload is not rewritten. Offline code reads original DomainEvent payload bytes, never the inspection bridge, and routes generic data to wrapped strict decoder. Absent/invalid payload produces blocking domain failure; sanitized messages do not expose original data. Canonical event types retain specialized checks, so generic records cannot acquire signature/intake/legal meaning by containing matching nested strings.

HTTP schema keeps one owning external schema URI; the offline conformance registry owns its resource during validator use. Test resolves wos-events from the same manifest dependency it compiles against. Checker source discovery follows the admission manifest, while conformance follows its own explicit dev dependency; the coherent native freeze must keep both pointing at the same reviewed Core source. Resources have local internal references only; no new network fetch is required by the registered test. Schema remains consumer-visible and needs equivalent resource registration for other offline validators.

## Tests inspected versus executed

**Executed by reviewer: none.** Retained static-check receipt `native-provenance-consumer-v2-static-check.json` reports PASS for Python check_defs/check_operations only, errors empty, and records packet/helper/schema paths. It has no command/transcript and is supporting summary evidence, not an independently reproduced result. No retained native conformance pass is claimed. Inspected v1 tests: client native full-record equality and all28 canonical route/payload equality at wos_ext.rs:137,158; admission preservation/serviceOnly/catalogcount and unknown/canonical/missing-kind refusal at admission/lib.rs:344,380; real dispatch test at composition.rs:497; offline tests at native_provenance.rs:98–284 exercise original OnEntry/NoticeSent values, unavailable payload blocking verdict, malformed fields, all28 canonical bypasses, duplicate/trailing/tag/byte/nontext/depth refusal and mixed-event hash attribution. These are meaningful prospective tests, not actual full-window qualification.

V2 conformance test: starts from the bounded native JSON fixture, constructs a complete HTTP body, expects validity; mutates recordKind to unknown and canonical, removes it, and adds unrecognized structural field, expecting invalidity. Each mutation is restored from original before the next independent class. Format assertions are enabled. Local library signatures support the code; compiler/runtime confirmation remains pending. Full offline schema compilation checks the prior reference defect directly instead of merely comparing enum strings.

Concrete edge limits: helper/schema construction failure is not mocked here; Core owns its tests. Strict signed-i64/-0/depth and bare timestamp-tag boundaries remain Core gates. Consumer tests alone cannot establish original-byte immutability or complete runtime ordering/receipt stamping. Future non-path dependency layouts would make the checker fail visibly rather than silently derive a stale table.

## Separate owned authentication lock check

Reviewed `actual-custody-auth-owned-lock.patch` SHA `48d18faf20c38603d4580b2a6460201205c0e6fc5c698fe0fdb1fe610ac1ace0`. It contains only the three previously qualified edges: stack-common-auth→async-trait and trellis-server-ports→stack-common-auth/http. Current cached Cargo.lock diff contains only those. Working-tree diff separately retains the foreign stack-common-typeid→rand_core0.6.4 line. No package/version/source/checksum replacement appears in the owned patch. APPROVE this exact owned lock hunk scope alongside the already reviewed auth patch; this is independent of the generic consumer's unqualified dependency closure. No index/lock mutation by reviewer.

## Exploration notes

H1 relative HTTP ref is valid as a repository path. REFUTED in v1 because absolute schema $id governs URI resolution; v2 canonical ID and offline registration resolve it.

H2 enum parity checker already follows every admitted event. REFUTED in v1 by canonical-only macro parser; v2 reads actual owning generic constant separately, preserving28canonical mappings.

H3 new offline conformance uses unsupported library APIs or wrong owner path. REFUTED statically by local0.46.1 API inspection, declared existing toml/wos-events dependencies and two-parent root/schema path. Compile and assertion outcomes remain unresolved until native window.

H4 generic consumer can establish full original custody by itself. REFUTED: Core raw bytes/producer equality, real complete window, coherent closure, signed ZIP and AFTER receipts remain necessary. No user/source facts were invented.

## Exact source pins

| Input | SHA-256 |
|---|---|
| `native-provenance-consumer-v2-static-check.json` | `814c8ae52e93a2e0f1de2be2f9d15b89a1b229f6941293490a8a438739da8105` |
| `native-provenance-private-preparation-v2.json` | `c2cadd4c74e35891258d979c071a6749c5ad3cbce957d3687380c0cabc696e86` |
| `native-provenance-private-preparation-v2.patch` | `70961fa2e8b082897df65e1815453697c8b122c09c10bc1c526df5a9306d5e97` |
| `actual-custody-auth-owned-lock.patch` | `48d18faf20c38603d4580b2a6460201205c0e6fc5c698fe0fdb1fe610ac1ace0` |
| `crates/trellis-admission-wos/src/lib.rs` | `e3092704dd73fe916f9fa4c873fee46fcaec2b0b08effa74639ba830c23778f7` |
| `crates/trellis-service-client/src/lib.rs` | `4c608bad9c89cfb9125dbc619864cd2cd37193b3486a705d2bb9863142d3d7f3` |
| `crates/trellis-service-client/src/wos_ext.rs` | `4b6673c9a7847aeb7ce7e9cc8e6b1a69927aaa5326fab3a893095925db4e582c` |
| `crates/trellis-server/src/composition.rs` | `61717cd16c8135ee56cc0e13ce799c5270dadfdad5819d10b1e2649f6d9aac7f` |
| `crates/trellis-server/src/openapi.rs` | `c7d5c526af8e212138f6802b24e88bf6460dcb2cc329934231e2a6751c7f781e` |
| `crates/trellis-verify-wos/src/lib.rs` | `b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9` |
| `crates/trellis-verify-wos/src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |
| `crates/trellis-verify-wos/src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| `specs/trellis-http-api.schema.json` | `3dd79d92c4e6613db438867c27468880dbb7189d9188eb1e5ceae4348d5fec4e` |
| `specs/wos-trellis-verification.md` | `c424283b03622140af9c99dbc1fcf105fa9e035b39f430d1045af8c41c96a4c2` |
| `specs/trellis-requirements-matrix.md` | `9f15446d75c4e51b490a82849297863cd009f4c9eacee04793e3e3344c617c08` |
| `fixtures/conformance/native-provenance-routing.json` | `41bce0b250b4971d1697fc88ad521a7b502e09b8fe7aee4a04c1b60c70e77a30` |
| `scripts/check-http-api-schema.py` | `1c3a9cd4226fe2adfc6ad9abc745bb1f24edc55902ef50fb490663bb850b1627` |
| `crates/trellis-conformance/Cargo.toml` | `d80d3c571a57236684badbe2d9b5172c400992d9d293c9cb0b64b7b00c8d7260` |
| `crates/trellis-conformance/src/lib.rs` | `5e47d7ed6784d34d68f5ed30c7c1e630a9fef2a9a1436984d57cbf574e683877` |
| `crates/trellis-conformance/src/native_http_schema.rs` | `9b91c0eb0480b6c2d3bad0c2d30a063e0c25398770e2ac9cebb3a4d3173c424f` |

## Conclusion

VERDICT: APPROVE source preparation only.

Justification:
- Both concrete v1 consumer integration defects are corrected and meaningful offline conformance assertions are present.
- Coverage of reviewed source seams: ADEQUATE for bounded static preflight. Execution, coherent cross-owner closure, full custody/ZIP and final AFTER qualification: INSUFFICIENT and pending.
- Confidence: HIGH for source/pin/lock scope checks; MEDIUM for uncompiled consumer integration. No adoption or D1 qualification is granted.
