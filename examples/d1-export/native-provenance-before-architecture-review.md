# Native provenance routing: independent BEFORE architecture review

**VERDICT: RECONSIDER the bare-record timestamp encoding; KEEP the single generic known-kind route.** The revised proposal fixes raw-value validation order and explicit admission dispatch. One concrete encoding mismatch remains: existing custody inputs encode timestamp tag0, while the new bare-record decoder forbids all tags. Settle that generic-only producer encoding before implementation approval. No implementation or executed qualification is reviewed.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs Rust inspection. Only this certificate written; no Cargo, native commands, live operations or source changes. Separate auth GREEN work and its outstanding principal-consistency correction are outside this routing gate.

## 1. Artifact summary

Artifact: `trellis/examples/d1-export/native-provenance-routing-proposal.md`, reviewed revision SHA-256 `364cfd71582c5897a528dc4cb36e3627b76458833ae32ad49f7e49bce796a905`; supersedes initial `aba3d72cc742660669777b2f9211020513e41a82659c6ab284a57a1730d21bcc`. Problem: known native runtime kinds without canonical Trellis mappings cannot traverse the maintained custody producer. The proposed service-only `wos.provenance.recorded` carries exactly `{ "record": <original native JSON record> }`, preserving kind, triggering event and data. Category: proof infrastructure. Beneficiary: a reviewer needing complete signed custody history rather than only selected canonical records.

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
5. **Real producer bytes accepted — BROKEN by unresolved tag policy.** `CustodyAppendInput::from_provenance_record` always passes `provenance_string_tags` (`custody.rs:134–140`), which tags timestamp with0 (`336–338`). Proposed no-tags bare decoder rejects that ordinary record. Preserve canonical bytes while defining generic-only no-tag input, or explicitly revise bare decoder policy. Failure blocks every normally stamped generic custody input before HTTP.
6. **Registration matches dispatch — PRESERVED by revised design.** Adapter specs and composition router are independent (`trellis-admission-wos/lib.rs:62–89`; `composition.rs:210–238`). Final proposal explicitly adds shared generic literal to both while preserving canonical array. Failure yields catalog-advertised but undispatchable events.
7. **Custody is not specialized admission — PRESERVED.** Existing WOS verifier uses specific canonical kinds (`trellis-verify-wos/event_types.rs:27–48`). Generic record validation must not promote nested data/event to signature, intake, determination or notice authority. Failure permits semantic privilege escalation.
8. **Offline completeness check — NEWLY INTRODUCED domain rule.** Generic events require readable payload and owning validation, using `DomainEvent.payload` (`integrity-verify/src/trellis/validator.rs:192–198`) through existing WOS validator (`trellis-verify-wos/validator.rs:21–43`). Missing/unreadable bytes refuse for this declared route; mutable service APIs cannot rescue them (`wos-trellis-verification.md:§1`).

## 4. User-value analysis

The route makes complete native custody possible without claiming every lifecycle fact is a new legal/business event. One shared validator and one registered route remove the need for106 literal registrations and duplicated kind-decoding logic. New helper/schema code is justified by strict shape and preservation requirements; no line-reduction, speed or resource claim is measured.

Smaller candidates: dropping noncanonical records fails completeness; allowing every unknown kind abandons the closed owner model;106 specialized routes add unsupported semantics and maintenance. Merely serializing `ProvenanceRecord` loses original raw unknown fields before a check. The selected shared raw-value helper is the smallest adequate shape, once its actual producer encoding agrees.

Falsifier: genuine OnEntry still cannot append; a known remaining kind disappears or changes data; canonical kinds enter the generic route; the offline validator accepts malformed generic evidence; repeating a custody window produces duplicate appends.

## 5. Counterfactual analysis

Kill criterion: original facts cannot survive route/receipt stamping, or generic wrapper acquires specialized event authority. Opposite decision creates106 per-kind transports or leaves history incomplete. Removal first breaks full native-window custody at the existing canonical-only producer validation (`custody_trellis.rs:184–191`). Shared CBOR primitives partially subsume the helper, but neither enforce the native JSON shape nor owning kind eligibility. Six-month critic: schema registry drifts, decoder policy differs across ingress/offline, or generic custody is cited as actual decision/notice/signature proof. Keep those claims separately qualified.

## 6. Findings

**F1 — RESHAPE. Severity BLOCKER; category sibling-conflict.** Location: proposal “Shared owning API and decoder”; source `custody.rs:134–140,336–338`. A normal original custody timestamp is CBOR-tagged; same strict no-tags decoder rejects it. Smallest correction: only remaining-kind generic custody production uses empty string-tag rules, preserving canonical-route encoding. Alternative explicit bare timestamp-tag acceptance needs a revised decoder design and review. Add genuine stamped-record round-trip coverage, not blank constructor evidence.

**F2 — KEEP. Severity OBSERVATION; category named-seam.** Final revision adds strict bare-record constructor before inspection/typed conversion and explicit composition dispatch separate from catalog registration. These resolve initial review findings. Require one private decoder and no duplicated consumer kind lists.

**F3 — KEEP. Severity OBSERVATION; category ownership.** Core owns helper/schema/runtime selection; Trellis owns admission/client/composition/schema and integrates the pinned lent WOS verifier patch. Generic Integrity primitives retain no WOS semantics. WOS shared helper has authority to reject unknown record fields; arbitrary permitted application data remains original.

**F4 — DEFER. Severity OBSERVATION; category scope.** No implementation, observed generic GREEN, actual fresh custody, deployment or full D1 acceptance follows. Preserve initial full-window RED and separate idempotency-key evidence. Execute original ordered unstamped records through actual router/client, retain append receipts, stamp the matching original IDs, retry unchanged and refuse changed-body replay. Then verify exact pinned ZIP plus negative generic payload/discriminator cases. Separate auth and evidence-provider gates persist.

## 7. Verdict

**RECONSIDER only the generic bare-record encoding in F1.** Intent MATCHES complete custody without invented semantics. User value SUPPORTED by current canonical-only producer/client/admission boundaries. Commitments HONORED in proposed ownership and canonical-route preservation except the real-input decoder mismatch. Conceptual debt PAYS DOWN per-kind routing duplication through shared machinery; sibling subsumption PARTIAL. Confidence HIGH for static mismatch and boundary trace; implementation/executed behavior unqualified.

All six reasoning phases completed. H1 existing enum supports only28 kinds REFUTED:134 exist but28 canonical mappings. H2 existing typed deserializer preserves/validates original structural facts REFUTED. H3 shared raw validation can serve ingress/offline CONFIRMED in design; H4 existing bare custody is untagged REFUTED by timestamp-tag rule. H5 catalog registration alone enables dispatch REFUTED, corrected final proposal. H6 generic custody grants specialized authority REFUTED by explicit route restrictions and unchanged specialized validators. Next action is exact revised producer/decoder policy and supplemental API review, then paired implementation AFTER qualification.

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

Revisions: Trellis `ea8f547367e4d41d09395001230ccf14705af8c9`; work-spec `22296385f4ef179ad330f55d80592194f8b3af6b`; integrity-stack `4dc55bc6a6f3c8901b0fb31e72e68e618c97613d`; stack-common `6aaba49911d80303ee883cfdcb329dce4999432c`. These are static snapshots, not proof of service state or ratification. Core supplement reviewed at `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v1.md`, SHA-256 `e7bb10dc3a5db51e23233cfddf76ea13b446769043ebef8225502057fc6d25b6`. Its “Schema and raw validation” correctly distinguishes the post-append FactsTierRecord schema, which forbids recordKind, from the proposed native transport. Its “Exact CBOR subset” is appropriate for wrapped Trellis JSON payload but its producer section preserves original custody bytes, so F1 also applies to this supplement. Await the jointly agreed exact bare-only timestamp-tag policy and updated API before final approval.
