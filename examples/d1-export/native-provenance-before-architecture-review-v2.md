# Native provenance routing: successor BEFORE architecture review

**VERDICT: APPROVE the exact successor routing design and Core API.** The source-specific decoder policy accepts only the existing bare timestamp tag0, preserves original custody bytes, and keeps wrapped transport payloads untagged. Raw validation precedes inspection conversion; shared JSON preflight aligns admission with offline verification. No implementation or executed qualification is reviewed. The prior RECONSIDER certificate remains unchanged.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs Rust inspection. Only this certificate written; no Cargo, native commands, live operations or source changes. Separate auth GREEN work and its outstanding principal-consistency correction are outside this routing gate.

## 1. Artifact summary

Artifact: `trellis/examples/d1-export/native-provenance-routing-proposal-v2.md`, SHA-256 `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8`, paired with Core `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md`, SHA-256 `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82`. These supersede earlier proposal/API decisions for this gate while retaining prior artifacts and findings. Problem: known native runtime kinds without canonical Trellis mappings cannot traverse the maintained custody producer. The proposed service-only `wos.provenance.recorded` carries exactly `{ "record": <original native JSON record> }`, preserving kind, triggering event and data. Category: proof infrastructure. Beneficiary: a reviewer needing complete signed custody history rather than only selected canonical records.

Static count finds134 enum variants in `wos-events/src/provenance/kind.rs`; the maintained canonical mapping has28 routes. The106 remaining known kinds need transport, not106 new specialized semantics. No helper implementation exists in the inspected original source. The proposal/API names describe planned shared-owner work.

## 2. Lineage and relationship tables

| Prior artifact | Type | Relationship | Citation |
| --- | --- | --- | --- |
| Root GOAL/philosophy | Parent | Complete independent evidence; reuse maintained owners | `GOAL.md:Critical Path5`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility` |
| WOS enum/record | Owning model | Known kinds, canonical mappings and original record facts | `work-spec/crates/wos-events/src/provenance/kind.rs:8–448,450–520`; `record.rs:535–704` |
| Runtime custody | Existing seam | Authored inputs, original record ID and receipt enrichment | `wos-events/src/custody.rs:120–169,264–318`; `wos-runtime/src/runtime/custody_trellis.rs:164–208` |
| Runtime production | Existing lifecycle | Populates/stamps before storing actual records | `wos-runtime/src/runtime/process.rs:336–358`; `runtime/provenance.rs:21–48,86–109` |
| WOS verification companion | Normative seam | Consumer domain meaning beside Core proof | `trellis/specs/wos-trellis-verification.md:§1–2` |
| Core transport/export | Normative substrate | Signed payload/hash/checkpoint and offline byte authority | `trellis/specs/trellis-core.md:§9,§18–19` |

| Component/seam | Owner | Depends on | Consumed by | Named? |
| --- | --- | --- | --- | --- |
| Native record recognition/shape | Core wos-events | Existing enum, schema validator, raw JSON | Producer/admission/offline helper | Proposed shared `NativeProvenanceEvent` |
| Strict CBOR conversion | Core helper / Integrity primitives | decode, bounded subset, duplicate validation, original-value conversion | Bare custody and wrapped offline input | Proposed two constructors / one private decoder |
| Producer route selection | Core runtime | Canonical mapping or validated remaining kind | Existing client | Existing custody seam extended |
| HTTP request construction | Trellis WOS extension | Shared event constant/helper | Generic SubstrateClient | Existing `wos_ext.rs:37–75` |
| Admission/catalog/dispatch | Trellis composition + WOS adapter | Shared owning helper | Generic append/registry | Existing ports; one registered literal added |
| Offline validation | Trellis WOS companion, lent Integrity ownership | Core-derived payload bytes, same helper | Relying-party verdict | Existing `RecordValidator` |
| Specialized signature/intake/clock meaning | Existing WOS/Integrity validators | Canonical events/catalogs | Existing legal/domain checks | Unchanged specialized seams |

## 3. Invariants and commitments

1. **Canonical28 routes/bytes — PRESERVED in decision.** Existing mapping and custody behavior remain authoritative (`kind.rs:450–520`; `custody.rs:264–318`). Generic route rejects any kind with a canonical mapping. Failure could bypass existing specialized validation.
2. **Known-kind closure — NEWLY INTRODUCED.** The enum, rather than a copied106-entry routing table, chooses eligibility. Missing/unknown/vendor/malformed discriminators refuse. Schema parity must be mechanically checked against the maintained registry. Failure silently admits invented record kinds or drifts when enum evolves.
3. **Original facts — PRESERVED as JSON value, not original HTTP formatting.** Full original nested record must round-trip by value; unknown structural fields refuse instead of disappearing through typed deserialization. Existing `record.rs:636–704` defaults fields and infers omitted discriminator, so it cannot alone enforce this boundary. Signed archive bytes remain byte authority; no claim of raw HTTP JSON duplicate detection follows after serde Value parsing.
4. **Strict conversion before lossy inspection — PRESERVED by revised design.** `custody.rs:168–169` uses an inspection bridge; raw duplicate keys/bytes/tags must be checked first. `from_record_dcbor_slice` and wrapped `from_dcbor_slice` now share strict raw checks before original-value JSON conversion. `integrity-cbor/src/lib.rs:140–177,297–315` supplies maintained decoding/duplicate/nonfinite/conversion checks. Failure can erase facts before validation.
5. **Real producer bytes accepted — PRESERVED by source-specific policy.** `CustodyAppendInput::from_provenance_record` passes `provenance_string_tags` (`custody.rs:134–140`), which tags timestamp with0 (`336–338`). Core v3 “Exact CBOR subset” permits this only at the bare root timestamp with a text child subsequently checked as RFC3339. All other tag paths/values and every wrapped tag refuse. One private decoder takes an explicit source policy; original bytes remain unchanged. Maintained `cbor_value_to_json` handles tag0 (`integrity-cbor/src/lib.rs:335–337`) only after the stricter owning checks. Failure to enforce path/source policy would either reject real custody or admit hidden tagged data.
6. **Registration matches dispatch — PRESERVED by revised design.** Adapter specs and composition router are independent (`trellis-admission-wos/lib.rs:62–89`; `composition.rs:210–238`). Final proposal explicitly adds shared generic literal to both while preserving canonical array. Failure yields catalog-advertised but undispatchable events.
7. **Custody is not specialized admission — PRESERVED.** Existing WOS verifier uses specific canonical kinds (`trellis-verify-wos/event_types.rs:27–48`). Generic record validation must not promote nested data/event to signature, intake, determination or notice authority. Failure permits semantic privilege escalation.
8. **Offline completeness check — NEWLY INTRODUCED domain rule.** Generic events require readable payload and owning validation, using `DomainEvent.payload` (`integrity-verify/src/trellis/validator.rs:192–198`) through existing WOS validator (`trellis-verify-wos/validator.rs:21–43`). Missing/unreadable bytes refuse for this declared route; mutable service APIs cannot rescue them (`wos-trellis-verification.md:§1`).

## 4. User-value analysis

The route makes complete native custody possible without claiming every lifecycle fact is a new legal/business event. One shared validator and one registered route remove the need for106 literal registrations and duplicated kind-decoding logic. New helper/schema code and the one path-specific timestamp exception are justified by strict shape and preservation requirements; no line-reduction, speed or resource claim is measured.

Smaller candidates: dropping noncanonical records fails completeness; allowing every unknown kind abandons the closed owner model;106 specialized routes add unsupported semantics and maintenance. Merely serializing `ProvenanceRecord` loses original raw unknown fields before a check. The selected shared raw-value helper is the smallest adequate shape; source-specific timestamp policy now agrees with actual producer encoding. Re-encoding existing custody input would change original persisted bytes and is unnecessary.

Falsifier: genuine OnEntry still cannot append; a known remaining kind disappears or changes data; canonical kinds enter the generic route; the offline validator accepts malformed generic evidence; repeating a custody window produces duplicate appends.

## 5. Counterfactual analysis

Kill criterion: original facts cannot survive route/receipt stamping, or generic wrapper acquires specialized event authority. Opposite decision creates106 per-kind transports or leaves history incomplete. Removal first breaks full native-window custody at the existing canonical-only producer validation (`custody_trellis.rs:184–191`). Shared CBOR primitives partially subsume the helper, but neither enforce the native JSON shape nor owning kind eligibility. Six-month critic: schema registry drifts, decoder policy differs across ingress/offline, or generic custody is cited as actual decision/notice/signature proof. Keep those claims separately qualified.

## 6. Findings

**F1 — KEEP. Severity OBSERVATION; category sibling-conflict.** Successor proposal “Shared owning API and decoder” and Core v3 “Exact CBOR subset” resolve the prior timestamp blocker with the existing bare timestamp-tag exception only. Require tests for valid bare tag0/text/RFC3339, untagged equivalent JSON, tag0 at nested data, nontext timestamp child, tag32, nested tags and wrapped timestamp tags. Preserve original custody bytes and compare complete validated JSON values across the existing conversion. No raw-byte equality claim follows.

**F2 — KEEP. Severity OBSERVATION; category named-seam.** Final revision adds strict bare-record constructor before inspection/typed conversion and explicit composition dispatch separate from catalog registration. These resolve initial review findings. Require one private decoder and no duplicated consumer kind lists.

**F3 — KEEP. Severity OBSERVATION; category ownership.** Core owns helper/schema/runtime selection; Trellis owns admission/client/composition/schema and integrates the pinned lent WOS verifier patch. Generic Integrity primitives retain no WOS semantics. WOS shared helper has authority to reject unknown record fields; arbitrary permitted application data remains original.

**F4 — DEFER. Severity OBSERVATION; category scope.** No implementation, observed generic GREEN, actual fresh custody, deployment or full D1 acceptance follows. Preserve initial full-window RED and separate idempotency-key evidence. Execute original ordered unstamped records through actual router/client, retain append receipts, stamp the matching original IDs, retry unchanged and refuse changed-body replay. Then verify exact pinned ZIP plus negative generic payload/discriminator cases. Separate auth and evidence-provider gates persist.

## 7. Verdict

**APPROVE the exact paired successor design.** Intent MATCHES complete custody without invented semantics. User value SUPPORTED by current canonical-only producer/client/admission boundaries. Commitments HONORED in proposed ownership and canonical-route preservation including the resolved real-input decoder policy. Conceptual debt PAYS DOWN per-kind routing duplication through shared machinery; sibling subsumption PARTIAL. Confidence HIGH for static boundary coherence; implementation/executed behavior unqualified. No unresolved RESHAPE or REVERSE finding remains for this exact design.

All six reasoning phases completed. H1 existing enum supports only28 kinds REFUTED:134 exist but28 canonical mappings. H2 existing typed deserializer preserves/validates original structural facts REFUTED. H3 shared raw validation can serve ingress/offline CONFIRMED in design; H4 existing bare custody is untagged REFUTED by timestamp-tag rule; successor explicit bare-only exception resolves the mismatch. H5 catalog registration alone enables dispatch REFUTED, corrected final proposal. H6 generic custody grants specialized authority REFUTED by explicit route restrictions and unchanged specialized validators. Next action is owner-scoped implementation followed by meaningful native RED→GREEN and paired AFTER qualification under an explicitly assigned native window.

## Exact inspected source pins

| File | SHA-256 |
| --- | --- |
| `work-spec/crates/wos-events/src/provenance/kind.rs` | `72f829655d85ecc12b45830304317f945366cf339333dfb70663859d850304c5` |
| `work-spec/crates/wos-events/src/provenance/record.rs` | `d06dec736d6cdb0e9d0760a933fd64dd5dc88c1fe657c2e2fed476629847f9dc` |
| `work-spec/crates/wos-events/src/custody.rs` | `026ec9c8c78da56a388acdd89843ebbc3bd972f5558aafd9d426e7c7749e8c02` |
| `work-spec/crates/wos-runtime/src/runtime/custody_trellis.rs` | `9c98a9f7a917bcad9e2f433ff0e0922f25eb0c2cc2bbea6a0d550c2873ef33a0` |
| `work-spec/crates/wos-runtime/src/runtime/process.rs` | `e4e8a0a431c91d88a2b726b5b587f805b42ca1fe7b5be7079468709a0ee4ee44` |
| `trellis/crates/trellis-service-client/src/wos_ext.rs` | `091a20df79cc63359b0de7405eaf18637f6d285d8ebfda89d4afcacc37d4e063` |
| `trellis/crates/trellis-admission-wos/src/lib.rs` | `209539a13ced4b2c6fb29191d76ebbf5eecf6a6443bc33626914c7a51348ea00` |
| `trellis/crates/trellis-server/src/composition.rs` | `8bd5a4801a0973be0f80e244515e7974c2960c280781e3274c73ff2ceb2120ce` |
| `trellis/crates/trellis-verify-wos/src/validator.rs` | `2403d1f82b9acfe92dbdc4790bd05767aea9488f85ee68d6fb401204495ce3f4` |
| `integrity-stack/crates/integrity-cbor/src/lib.rs` | `e7b15d2d259cfad8e0656e6dc19d67903863829d7d56c3240299565c43bd578b` |

Revisions: Trellis `ea8f547367e4d41d09395001230ccf14705af8c9`; work-spec `22296385f4ef179ad330f55d80592194f8b3af6b`; integrity-stack `4dc55bc6a6f3c8901b0fb31e72e68e618c97613d`; stack-common `6aaba49911d80303ee883cfdcb329dce4999432c`. These are static snapshots, not proof of service state or ratification. Core successor supplement reviewed in full at `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md`, SHA-256 `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82`. Its schema section correctly distinguishes FactsTierRecord, which forbids recordKind, from the new transport schema. Its value-domain preflight covers nested application data with signed64-bit integers, finite floats, no negative zero and maximum depth128. Constructors reject unsupported values before emission; no accepted producer value may depend on a permissive inspection conversion to become verifiable.

## Concrete design counterexamples and required checks

| Input/counterexample | Required result | Why |
| --- | --- | --- |
| Genuine stamped OnEntry bare record with root timestamp tag0/text | Accept if complete schema/ID/kind validates | Matches existing source encoding |
| Same record converted to untagged wrapped JSON payload | Accept by same schema/value domain | Existing Trellis JSON-to-CBOR transport |
| Tag0 under `data.timestamp` or tag32 at bare root timestamp | Refuse | Exact source-path exception only |
| Tag0 at wrapped `record.timestamp` | Refuse | Wrapped transport emits no tags |
| Duplicate root timestamp or nested recordKind CBOR keys | Refuse before JSON conversion | Inspection conversion otherwise collapses keys |
| Missing recordKind inferred by typed record parser | Refuse | Explicit original kind is required |
| Canonical SignatureAffirmation carried in generic wrapper | Refuse | Cannot bypass specialized canonical authority |
| Remaining known kind with triggering event resembling a canonical event | Preserve context; grant no specialized semantics | Original `event` is not outer route authority |
| Unknown structural field versus arbitrary permitted data key | Refuse structural field; preserve permitted data | Avoid silent fact loss without inventing application schema |
| Nested integer beyond signed64, negative zero or depth beyond128 | Refuse at JSON and CBOR entry points | Admission/offline value-domain agreement |
| Generic signed event with absent/unreadable payload | Offline refusal | Custody meaning cannot be inferred without original record |
| Repeated original record window / changed-body retry | Same receipts, no extra append / conflict | Stable identity and exact content |

These are falsifiable design requirements, not test results. The whole-window proof must include original native record identifiers/order, both canonical and generic payload equivalence, returned receipt stamping, archive readback and owning offline verdict. The preexisting bounded-key prerequisite remains independently unqualified until executed; this certificate grants no native window and does not conceal that dependency.
