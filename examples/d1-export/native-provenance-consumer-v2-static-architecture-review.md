# Native provenance consumer v2: bounded static architecture review

**VERDICT: APPROVE the source shape for continued private qualification.** No blocking architecture correction was found in this bounded consumer delta. This is source-only review: Rust remains uncompiled in the reviewed packet, joint physical dependency qualification and full-window/native/offline evidence remain outstanding. It is not final AFTER acceptance or adoption approval.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Retained full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` applied. Only this certificate written; no Cargo/native commands, drift-check script execution, live calls or source edits.

## 1. Artifact summary

Packet `native-provenance-private-preparation-v2.json` SHA-256 `c2cadd4c74e35891258d979c071a6749c5ad3cbce957d3687380c0cabc696e86`; patch `native-provenance-private-preparation-v2.patch` SHA-256 `70961fa2e8b082897df65e1815453697c8b122c09c10bc1c526df5a9306d5e97`. Candidate `/Users/mikewolfd/Work/formspec-stack/.trellis-native-provenance-v2`, baseline `ea8f547367e4d41d09395001230ccf14705af8c9`. All16 consumer source/spec path hashes independently match the packet.

The delta makes the HTTP generic payload reference the canonical owning schema URI, resolves the drift checker's owning source through admission's actual path dependency, and adds a locally registered owning schema conformance test. Category: proof infrastructure and schema integrity. Beneficiary: consumers/maintainers who need the documented HTTP shape to match admitted native evidence without relying on network retrieval or a wrong sibling checkout.

## 2. Lineage and relationships

| Prior artifact | Relationship | Citation |
| --- | --- | --- |
| Approved paired routing design | Constrains known-kind route, raw preservation, shared owner | `native-provenance-routing-proposal-v2.md`, SHA `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| Core API v3 | Owns schema, strict conversion and bare timestamp policy | root reports `work-spec/full-d1/native-provenance-core-api-before-v3.md`, SHA `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82` |
| Independent BEFORE gate | Accepts exact source-specific decoder design | `native-provenance-before-architecture-review-v2.md:§3,§6–7` |
| WOS verification companion | Separates substrate and domain evidence | `specs/wos-trellis-verification.md:§1,§7` |
| Existing native routing owners | Canonical routes and generic registration remain bounded | candidate `trellis-admission-wos/src/lib.rs:65–89,131–137`; `composition.rs:224–233` |

| Seam | Owner | Depends on | Consumer | Named? |
| --- | --- | --- | --- | --- |
| Native payload schema | Core wos-events | Existing kinds/model | HTTP/schema/offline | Canonical `$id` |
| HTTP conditional reference | Trellis | Owning schema URI | API users/conformance | `SubstrateAppendBody.allOf` |
| Schema drift checker | Trellis | Actual admission manifest path dependency | Maintained check workflow | Existing checker extended |
| Offline schema conformance | Trellis test | Local referencing Registry + actual dev dependency | Test suite | New bounded test |
| Generic domain validation | WOS companion, lent Integrity ownership | Shared NativeProvenanceEvent | Relying-party verdict | Existing RecordValidator extended |

## 3. Invariants and commitments

- **One schema authority — PRESERVED.** HTTP schema line460 references `https://wos-spec.org/schemas/wos-native-provenance-event.schema.json`, exactly matching the owning schema `$id`. The drift checker lines259–267 checks that reference exactly once. Failure would silently validate a different transport shape.
- **Actual dependency lineage — PRESERVED.** Checker lines23–30 resolves `wos-events` from the admission manifest and derives both kind/helper/schema files there. It no longer assumes whichever sibling work-spec happens to sit nearby. Conformance resolves its owning dev dependency similarly (`native_http_schema.rs:10–25`). Failure would prove parity against unused code. Joint physical snapshot must still ensure these selected dependencies are the same frozen owner version.
- **Offline schema resource — PRESERVED in test source.** `native_http_schema.rs:26–39` registers owning schema content by its `$id` using `referencing::Registry`, then builds JSON Schema validation with format assertions. Test source has no network request; `jsonschema` and `referencing` dev dependencies disable default features. This is planned local-resource coverage, not an executed no-network claim.
- **Closed known-kind route — PRESERVED.** Conformance accepts an authored generic fixture and rejects unknown kind, canonical `caseCreated`, missing recordKind and unknown structural fields (`native_http_schema.rs:42–66`). Ingress delegates to the Core helper; canonical branches remain separate. Failure could bypass canonical checks or discard facts.
- **Offline generic custody meaning — PRESERVED.** `trellis-verify-wos/native_provenance.rs:10–35` checks only the shared generic literal and calls strict `from_dcbor_slice`; absent/invalid payload produces blocking domain findings bound to event hash. `validator.rs:23–26` actually invokes it. Error messages do not include original record values. Generic Integrity crates gain no WOS interpretation.
- **No new specialized authority — PRESERVED.** Client remaining-kind branch uses shared helper and literal (`wos_ext.rs:44–58`); canonical branch remains unchanged. Generic event remains custody, not signature/intake/decision/notice admission.

## 4. User value and simplicity

Canonical schema identification fixes an actual interoperability seam: users and local validators can identify the same owner schema while tests supply its exact content offline. Resolving actual dependencies prevents a plausible false parity result from an unrelated checkout. This reuses the maintained checker and one standard schema Registry instead of embedding a copied schema or adding another validator implementation.

The tradeoff is two test-only dependencies and a small local-resource test. No speed or memory improvement is measured. The smaller string-only URI check is retained, but cannot establish that payload validation resolves and enforces the owning resource. The bounded conformance test supplies that missing falsifiable behavior once executed.

## 5. Counterfactuals

Kill criterion: changing the selected owning schema does not affect conformance, or the checker reads a different dependency than admission. Removing the delta leaves a schema reference/physical-checkout ambiguity. Copying the owner schema into Trellis would simplify lookup while creating a second authority. Existing referencing/jsonschema libraries subsume resource resolution/validation; shared helper subsumes native interpretation. Six-month critic: a source-only review or static script claim may be mistaken for full native custody proof. Preserve the uncompiled/unqualified status until exact execution receipts exist.

## 6. Findings

**F1 — KEEP. Severity OBSERVATION; category named-seam.** Canonical `$id` reference and selected dependency lookup correctly bind public schema intent to owning source. Preserve owner URI rather than a relative private filesystem reference.

**F2 — KEEP. Severity OBSERVATION; category user-value.** Locally registered owning resource test checks real schema acceptance/refusal conditions instead of only matching URI text. Do not replace it with a copied schema or per-kind duplicate validation code.

**F3 — DEFER final qualification. Severity OBSERVATION; category scope.** Packet explicitly requires coherent frozen Core dependencies, locked metadata, the same genuine runtime custody window from cursorzero, original JSON/ID/order/receipt assertions, retry/no duplicates, owning decoder negatives and paired AFTER review. These remain required. Private manifest rewrites are qualification-only, not adoption patch authority. Source review found no RESHAPE or REVERSE requirement in this bounded delta.

## 7. Verdict and limits

**APPROVE continued private qualification of this exact source shape.** Intent MATCHES owning schema/dependency lineage; user-value SUPPORTED by removal of schema/check-out ambiguity; commitments HONORED in consumer source; debt PAYS DOWN potential duplicate authority with modest test code/dependencies; sibling subsumption PARTIAL; confidence HIGH for static shape and16-file pin match, no claim of compiled/native behavior.

All six reasoning phases applied. H1 HTTP reference matches owning `$id` CONFIRMED by source. H2 checker follows actual admission dependency CONFIRMED. H3 test performs local Registry resolution CONFIRMED in source only. H4 generic offline check is merely defined but unwired REFUTED by validator call. H5 static preparation proves full D1 REFUTED. No build, native test, real Source history, deployment, independent trust or full D1 result is established.

## Exact consumer source pins

| File | SHA-256 |
| --- | --- |
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

Packet additionally names Core source-v3 index digest `3a410dfebd233e7604dbf30b17ec900e51e131c3313117ea420ee4bf23536268` and lent offline patch digest `bdad6cf32b9fbd11040cd259c8978376872df657e92ac2cf592c1bf2676f8b97`; these are ownership/lineage declarations, not a substitute for the later full physical dependency snapshot and qualification. This review does not approve any foreign lockfile edit or alter the separate qualified auth adoption scope.

Retained static-check receipt independently read: `native-provenance-consumer-v2-static-check.json`, SHA-256 `814c8ae52e93a2e0f1de2be2f9d15b89a1b229f6941293490a8a438739da8105`, binds this packet and records PASS for Python schema-definition/operation checks with no errors. It explicitly excludes Cargo, Rust conformance execution, OpenAPI emission and the native runtime window. This supports static wiring only and does not broaden this verdict.
