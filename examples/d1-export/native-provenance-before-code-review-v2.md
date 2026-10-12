# Native provenance routing — independent BEFORE code review

Review ID: TRELLIS-NATIVE-PROVENANCE-BEFORE-CODE-V2-2026-10-09. Independent nonauthor review by `/root/oidc_code_review`. Method: full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, plus ms-rust review guidance. Scope is the frozen joint design and existing maintained source; prospective APIs have no implementation acceptance. No Cargo, native execution, network, service calls, or source edits performed. Only this certificate was written. Other agents' changes and locks were preserved.

## Findings and decision

**VERDICT: APPROVE the joint BEFORE design at `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8`.** No unresolved design blocker found. Implementation, actual complete-window behavior, offline refusal, adoption and full D1 qualification remain unapproved. Coverage of the design/source seams is adequate; implementation/test execution coverage is presently insufficient by definition. Confidence: HIGH on the traced baseline and direction, MEDIUM on prospective behavior until source and native evidence exist.

F1 — RESOLVED BLOCKER / correctness: the prior blanket no-tags rule for bare custody records contradicted the maintained producer. `work-spec/crates/wos-events/src/custody.rs:134–138,336–337` passes `[(timestamp, tag 0)]` to the encoder, while `trellis/crates/trellis-server/src/append.rs:306` passes an empty tag list for wrapped archive payloads. The prior review missed the producer tag policy; its approval is superseded and must not authorize implementation. The exact successor pair fixes this with one private decoder taking an explicit source policy: permit tag 0 only at the bare root timestamp with a text child, then validate RFC 3339; reject tags anywhere else, nested tags and nontext tag children. Wrapped payloads still reject every tag. Preserve original custody bytes and compare validated complete JSON records across the documented timestamp conversion. Both successor API lists include `from_record_dcbor_slice`; the earlier supplement mismatch is resolved.

F1b — RESOLVED / correctness: shared `from_json` preflight now requires the same signed-i64/finite/non-negative-zero numeric and depth-128 domain as the decoder. This matches maintained converter behavior at `integrity-stack/crates/integrity-cbor/src/lib.rs:350–390`; admitting arbitrary u64 JSON before a stricter offline check would otherwise cause route-dependent acceptance. Implement the same validation for nested application data. Test exact depth boundaries on both entry points, counting the added wrapper consistently.

F2 — OBSERVATION / test coverage: every new helper/schema/route and generic offline check is prospective. Existing canonical-only mock tests do not establish complete native custody. The actual initial full-window RED receipt was not part of this review's inspected inputs; preserve and pin it in the implementation evidence rather than treating the proposal's reported failure as independently executed evidence.

## Patch summary and source context

No implementation diff exists. This certificate supersedes `native-provenance-before-code-review.md`; preserve it as the review history, not a current approval. The proposal adds one service-only WOS adapter event for the 106 known kinds outside the 28 canonical mappings, retaining the canonical array and existing specialized interpretations. It introduces a Core-owned raw-value validator/schema and strict shared decoder; consumers reuse them. Source enumeration confirms 134 Rust enum variants and 28 literal mappings; the registry reports 134. This avoids 106 parallel mappings without a measured performance claim.

Reviewed source HEADs: Trellis `ea8f547367e4d41d09395001230ccf14705af8c9`; work-spec `22296385f4ef179ad330f55d80592194f8b3af6b`; integrity-stack `4dc55bc6a6f3c8901b0fb31e72e68e618c97613d`. Working-tree evidence is bound below rather than assumed clean: untracked review/design artifacts exist; unrelated lock activity was observed and not changed. Instructions read include parent/Trellis CLAUDE and applicable review/Rust guidance. Trellis AGENTS is a CLAUDE symlink.

## Function and caller/callee trace

Paths below are relative to `/Users/mikewolfd/Work/formspec-stack`.

| Function / seam | File:line | Inputs → outputs; verified behavior |
|---|---|---|
| `canonical_event_literal`, reverse lookup | work-spec/crates/wos-events/src/provenance/kind.rs:506,515 | Enum ↔ optional registered literal; source contains 28 mappings. Remaining kinds have no canonical meaning. |
| `ProvenanceRecord::deserialize` | work-spec/crates/wos-events/src/provenance/record.rs:636 | JSON → typed record; defaults optional fields/timestamp, infers omitted kind from canonical event, ignores extra structural fields. It cannot establish lossless strict raw validation. |
| `metadata_for_provenance_record` | work-spec/crates/wos-events/src/custody.rs:44 | Typed record/context → validated case/record/event metadata. Calls event selection and native TypeID checks. |
| `provenance_event_type` | same:263 | Canonical kinds require matching nested event; other kinds currently receive a derived event tail. New generic route must replace only this latter branch. |
| `from_provenance_record`, custody JSON helper | same:131,293 | Typed source → bounded dCBOR; canonical records remove recordKind from custody JSON; `provenance_string_tags` at custody.rs:336 applies tag 0 to root timestamp for authored bytes. Preserve this existing branch and the original source bytes exactly. |
| `record_json_view` | same:166 | CBOR → inspection JSON through bridge; tags/bytes can change representation and duplicate text keys can collapse. It is unsuitable as strict input authority. |
| production initialization | work-spec/crates/wos-runtime/src/runtime/process.rs:336 | Collects actual evaluator/runtime/presentation records, populates fields, stamps timestamps, persists complete log. |
| populate/stamp helpers | work-spec/crates/wos-runtime/src/runtime/provenance.rs:21,36,84 | Existing empty timestamps get current time; absent audit layer populated; definitionVersion only filled when process version is nonempty. Genuine tests must demonstrate required fields; defaults cannot manufacture them. |
| `append_window`, `append_input` | work-spec/crates/wos-runtime/src/runtime/custody_trellis.rs:66,88 | Load complete window → validate → existing client → validate returned receipt → stamp original record. Existing nonempty stamped records skip. |
| input parse/metadata check | same:165,176 | Inspection JSON → typed record; rejects mismatched ID and every kind without canonical mapping before HTTP. Strict bare decoder must precede this path for generic inputs. |
| `validate_trellis_result` | same:215 | Receipt → acceptance/refusal; requires valid hash, verified Event artifact and matching requested event type before stamp. |
| WOS request helper / extension | trellis/crates/trellis-service-client/src/wos_ext.rs:37,97 | Typed record → event selection/serialized payload → maintained append client. Generic branch must use shared helper/raw payload, preserve canonical branch and original triggering event. |
| `WosEventAdmissionPolicy::admit` | trellis/crates/trellis-admission-wos/src/lib.rs:125 | Event/payload → neutral metadata; currently canonical reverse lookup, typed record alignment, event match. Add shared generic helper before existing canonical branch. |
| specs and dispatch | same:62; trellis/crates/trellis-server/src/composition.rs:214,236 | Catalog and actual dispatch are separate; adding specs alone does not route requests. Final joint design explicitly updates both with shared literal. |
| append/build payload | trellis/crates/trellis-server/src/append.rs:99,306 | Admission before append; JSON Value encoded by maintained `json_to_dcbor_bytes(payload, &[])`. Generic event remains service-only; client attestation is refused by existing neutral policy guard. |
| public schema parity | trellis/crates/trellis-server/src/openapi.rs:129 | Existing test compares HTTP schema/OpenAPI enum and admitted literals; new shared generic literal must be admitted to this parity rule without changing canonical list. |
| export verifier | trellis/crates/trellis-verify-wos/src/lib.rs:46; src/validator.rs:22,28 | Raw ZIP → structural verifier plus consumer-owned event/export checks. Generic validation belongs here, alongside specialized checks. |
| domain export material | integrity-stack/crates/integrity-verify/src/trellis/export.rs:95; validator.rs:192 | Archive signed events → DomainEvent with original readable payload bytes or None. Generic event with None must produce a finding, never silently skip. |
| CBOR decode/canonical validation/JSON bridge | integrity-stack/crates/integrity-cbor/src/lib.rs:140,158,297 | Exactly one CBOR value; recursive duplicate-key/nonfinite/negative-zero refusal; JSON bridge otherwise replaces duplicate keys and converts bytes/tags. Validate subset/depth and duplicates before conversion. |
| prospective constructors | final joint proposal shared API | `from_json`, `from_record`, wrapped `from_dcbor_slice`, bare `from_record_dcbor_slice` → validated owning NativeProvenanceEvent or typed error; **unimplemented, not traced as code**. Both byte constructors share one strict decoder. |
| prospective accessors/schema | final joint proposal | `payload`, `record`, `record_kind`, `record_id` expose validated original Value/enum/ID; closed owning schema and cached validator are **unimplemented**. Schema-construction failure must refuse. |

## Data flow and invariants

The original custody bytes originate from persisted runtime records, retain their native identifier, kind, triggering event and data, and stay available until receipt stamping. The generic path first decodes original bare bytes with the shared strict decoder, validates the native record, wraps that original Value once, and passes it through the maintained request/admission/append/export path. The original validated Value must equal emitted payload.record, including optional fields and arbitrary permitted data. A typed deserialize/reserialize detour cannot supply that equality. Wrapper creation adds outer routing only; the generic literal never replaces nested event.

Discriminator membership comes from the owning enum/registry; canonical kinds cannot bypass specialized routes through the generic wrapper. Closed structural schemas reject unknown fields instead of discarding them. Existing API-tier/log schemas describe different shapes, so the proposal correctly creates an owning transport schema. Original signed bytes remain cryptographic authority; canonicalize's sorted result is discarded after validation. Bound depth before recursive canonicalization/bridge conversion. Bytes, nontext map keys, unsupported numeric values, duplicate keys and trailing values refuse. Wrapped payloads reject all tags; bare source permits only root timestamp tag 0 with a text child, which the schema checks as RFC 3339. Never permit this exception in nested data or wrapped archive records. No claim of raw HTTP JSON duplicate detection survives Value parsing.

Receipt identity must match the original record and requested generic event before mutation of runtime state. Replay must not append twice; changed-body replay must refuse. Current auth/grants and the separate bounded-key repair remain prerequisites, not consequences of generic custody. Generic records cannot satisfy specialized signature/intake/legal/notice evidence merely by preserving native data. Generic Integrity crates remain WOS-independent.

## Tests inspected and required execution

**Executed by reviewer: none.** Inspected assertions: custody seeded-event refusal tests at custody.rs:531–558 reject missing/mismatched canonical event; runtime adapter tests at custody_trellis.rs:292,351,392 verify request/receipt stamping, already-stamped skipping, and ID mismatch with no client call/no stamp; admission tests at lib.rs:170,248,265,282 verify aligned metadata and unknown/malformed/mismatched refusal; composition tests at composition.rs:312,364 distinguish actual dispatch from unknown refusal; CBOR tests at lib.rs:739,797,820 cover trailing input, recursive duplicate keys, nonfinite/negative-zero cases; OpenAPI parity assertions at openapi.rs:129 compare schema/admitted enums. These existing tests do not exercise the proposed generic path and no new pass result is inferred.

Required AFTER evidence: all 28 canonical mappings and payloads unchanged; all 106 remaining kinds round-trip valid populated native records; strict negatives for wrapper/fields/kind/ID/timestamp/depth/duplicates/tags/bytes/trailing/absent payload; positive real tagged bare timestamp, negative tag 0 in wrapped payload/other paths, nested timestamp tags/nontext children, original source byte immutability, i64 boundaries, excessive u64, -0 and depth 128/129 across JSON and byte entry points; nested data and snapshot preservation; actual production window beginning OnEntry through maintained client/router with ordered one-to-one record/receipt equality and retry/no-duplicate proof; changed-body conflict; signed ZIP with generic owning check and existing specialized checks; mutation of generic discriminator/shape produces offline refusal. A canonical-only mock, blank-record loop, key-length test or structural ZIP check alone cannot close these gates.

## Exploration notes and limits

H1: the missing-kind failure is an adapter/routing gap, not absent runtime facts. CONFIRMED: native enum has 134 kinds, canonical mapping 28, runtime metadata explicitly rejects unmapped kinds. Exact reported OnEntry run itself was not re-executed.

H2: ordinary typed serde/inspection decoding can preserve every source fact safely. REFUTED: typed serde ignores unknown fields/defaults values; JSON bridge collapses duplicate maps and transforms tags/bytes. Successor joint strict bare decoder resolves this before conversion.

H3: catalog registration alone reaches admission. REFUTED by independent composition dispatch. Successor joint explicitly registers shared literal there as well.

H4: original bare and wrapped source bytes have identical no-tag policies. REFUTED by custody.rs:134–138,336–337 and append.rs:306. Successor explicitly distinguishes these source policies in one private decoder, retains original bytes, and bounds from_json numeric/depth acceptance. The previous certificate missed this fact and is superseded.

H5: existing primitives support strict offline validation without a second serializer or writer. CONFIRMED for primitives; helper implementation and integration remain prospective. No implementation source, new schema, byte vector, actual runtime window, negative offline receipts or deployment composition was reviewed here.

## Exact input pins

SHA-256 binds source/report bytes read; this is not a clean-tree or build claim.

| Input | SHA-256 |
|---|---|
| `trellis/examples/d1-export/native-provenance-routing-proposal-v2.md` | `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md` | `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82` |
| `work-spec/crates/wos-events/src/provenance/kind.rs` | `72f829655d85ecc12b45830304317f945366cf339333dfb70663859d850304c5` |
| `work-spec/crates/wos-events/src/provenance/record.rs` | `d06dec736d6cdb0e9d0760a933fd64dd5dc88c1fe657c2e2fed476629847f9dc` |
| `work-spec/crates/wos-events/src/custody.rs` | `026ec9c8c78da56a388acdd89843ebbc3bd972f5558aafd9d426e7c7749e8c02` |
| `work-spec/crates/wos-runtime/src/runtime/custody_trellis.rs` | `9c98a9f7a917bcad9e2f433ff0e0922f25eb0c2cc2bbea6a0d550c2873ef33a0` |
| `work-spec/crates/wos-runtime/src/runtime/process.rs` | `e4e8a0a431c91d88a2b726b5b587f805b42ca1fe7b5be7079468709a0ee4ee44` |
| `work-spec/crates/wos-runtime/src/runtime/provenance.rs` | `816ee023594613f42a64ab88a94e2c034272fdd88537ae56e97890bd6749c2dc` |
| `work-spec/schemas/record-kind-registry.json` | `1f3de03f7bfd775ed8fb2c4a27194ac313f27014714a987ec02444c4d5204697` |
| `work-spec/schemas/api/provenance.schema.json` | `068a9dd4ea3079ee6b670762cb76474a2c980e621cdbe893cb9e6daaf5500bdc` |
| `work-spec/schemas/wos-provenance-log.schema.json` | `7291e97e1ca2af5e633622c4f92ab552266fc41e10d0e624ae43725bd0d67884` |
| `trellis/crates/trellis-service-client/src/wos_ext.rs` | `091a20df79cc63359b0de7405eaf18637f6d285d8ebfda89d4afcacc37d4e063` |
| `trellis/crates/trellis-service-client/src/lib.rs` | `bc55d2f2080b7d2d1938e8511cd17843c61d92722bc2795afbcc6e75d4f400c2` |
| `trellis/crates/trellis-admission-wos/src/lib.rs` | `209539a13ced4b2c6fb29191d76ebbf5eecf6a6443bc33626914c7a51348ea00` |
| `trellis/crates/trellis-server/src/composition.rs` | `8bd5a4801a0973be0f80e244515e7974c2960c280781e3274c73ff2ceb2120ce` |
| `trellis/crates/trellis-server/src/append.rs` | `615d161bb6de31ef53a99b6cde61fc84aea91462bc4bcaef614dc22728df14be` |
| `trellis/crates/trellis-server/src/openapi.rs` | `477c27c4ce6756c6f5ecddac56fe7f2672c1e95abbcaa78fa43c2dc55ebca30d` |
| `trellis/crates/trellis-verify-wos/src/lib.rs` | `141c2a2c186fdec58d2407493b4845543640cfeff818346c496152adbef272db` |
| `trellis/crates/trellis-verify-wos/src/validator.rs` | `2403d1f82b9acfe92dbdc4790bd05767aea9488f85ee68d6fb401204495ce3f4` |
| `integrity-stack/crates/integrity-cbor/src/lib.rs` | `e7b15d2d259cfad8e0656e6dc19d67903863829d7d56c3240299565c43bd578b` |
| `integrity-stack/crates/integrity-verify/src/trellis/validator.rs` | `9edfaab7343ed3d9e030826a7413662ebb64e8bacdccd91f6b6473dbd0430f6d` |
| `integrity-stack/crates/integrity-verify/src/trellis/export.rs` | `95b42fe6b6c00e3c1bc7da24092d683f80cbfd48f30ce543113c52c73e70d0b6` |
