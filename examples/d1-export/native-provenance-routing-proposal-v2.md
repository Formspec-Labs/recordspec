# Complete native provenance custody routing

Status: frozen joint BEFORE design; no implementation or native qualification.

A real custody window includes runtime records whose known `ProvenanceKind` has no canonical Trellis event literal. The first `OnEntry` record fails request construction before HTTP. The current vocabulary maps 28 of 134 known kinds; dropping the remaining records would make the custody history incomplete.

## Decision and exact wire shape

Preserve every existing canonical mapping and its payload bytes. Route a remaining known typed kind through the single service-only event `wos.provenance.recorded`. The outer append request selects that event. Its JSON payload is exactly `{ "record": <complete original native record JSON> }`. The original nested `recordKind`, `event`, identifier, timestamp, actor, data, and other fields remain unchanged. The generic event literal never replaces the original triggering event.

Use the existing `ProvenanceKind` enum to recognize kinds. The generic route requires an explicit recognized `recordKind` whose `canonical_event_literal()` is `None`; canonical kinds must retain their existing route. Missing, unknown, vendor-extension, or malformed kind values refuse. No copied list of 106 variants and no new per-kind event table.

The Core-owned `wos-events` helper owns the exact validated shape and preserves the original JSON value. Admission and offline verification consume that helper. The existing permissive `ProvenanceRecord` deserializer alone is insufficient: it can infer an omitted discriminator, default fields, and ignore unknown fields. Validation must refuse unknown structural record fields without stripping facts. Application `data` remains original arbitrary JSON within the maintained JSON/CBOR subset where its existing type permits it. A new maintained schema describes this native custody transport shape; API-tier and post-append log schemas have different shapes and must not be applied by assumption.

## Shared owning API and decoder

Core `wos-events` exports `WOS_NATIVE_PROVENANCE_EVENT_LITERAL` and `NativeProvenanceEvent::{from_json(&Value), from_record(&ProvenanceRecord), from_dcbor_slice(&[u8]), from_record_dcbor_slice(&[u8]), payload(), record(), record_kind(), record_id()}`. Constructors return a validated raw-value-owning result or a typed `NativeProvenanceError`; accessors expose the original validated JSON payload/record, known enum kind and original identifier. Consumer code must not duplicate kind lists or decode policy.

Core owns `schemas/wos-native-provenance-event.schema.json`: closed wrapper, closed native record structural fields, explicit known remaining-kind discriminator, required original `id`, `timestamp`, `auditLayer`, `definitionVersion`, RFC 3339 timestamp validation and native identifier validation. The actual runtime production populate/stamp path supplies these fields (`runtime/process.rs` around 336–358); a genuine window test must prove this rather than rely on blank constructors. Preserve compatible existing field/snapshot constraints and arbitrary permitted application `data`. The schema's remaining-kind enum derives from the maintained record-kind registry and receives a parity check; producer/admission/offline consumers use the single helper. The cached maintained `jsonschema` validator owns shape checking.

For a generic custody input, call `from_record_dcbor_slice` on the ORIGINAL bare custody-record bytes before any `record_json_view()` or typed `ProvenanceRecord` conversion. The existing inspection bridge can collapse duplicate map keys and convert bytes/tags, so its output cannot establish strict source validity. The bare-record and wrapped-payload constructors share one private strict CBOR decoder with an explicit source-shape policy described below; the bare constructor wraps the validated original JSON record and then calls `from_json`. Compare the whole original validated JSON value against emitted `payload.record` before stamping. The existing canonical routes remain unchanged.

The shared private decoder uses maintained `decode_cbor_value` for exactly one value, bounded traversal (text map keys, no byte strings, depth at most 128), and maintained `canonicalize_cbor_value` validation to refuse duplicate canonical keys, non-finite numbers and negative zero. Its explicit source policy differs only for the original native timestamp: `from_record_dcbor_slice` permits CBOR tag 0 ONLY at the bare record's root `timestamp` field, with a text child subsequently checked as RFC 3339. It rejects that tag everywhere else and rejects every other tag. The wrapped `from_dcbor_slice` permits no tags because Trellis produces those event payloads through `json_to_dcbor_bytes(payload, &[])`.

Convert the ORIGINAL validated decoded value with maintained `cbor_value_to_json`, then call `from_json`. The known timestamp tag becomes its JSON string during this documented conversion; original persisted custody bytes remain unchanged. Do not claim byte equality between the tagged original custody record and the untagged transport representation. Compare their validated complete JSON records. Signed archive bytes remain the cryptographic authority; the helper never rewrites them. `from_json` applies the same depth, signed 64-bit integer, finite-number and negative-zero checks before admission, including nested application data, so accepted JSON cannot become unverifiable through the maintained JSON/CBOR converter. The helper does not claim raw HTTP JSON duplicate detection after serde has parsed a `Value`.

Core's detailed supplement is `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-core-api-before-v3.md`; its source-specific timestamp policy and shared JSON preflight are part of this design.


## Owners and implementation seams

- Core: shared `wos-events` constant, validated native-record helper and schema; producer custody event selection and original record metadata validation. Preserve the original record bytes and stamp the receipt against the original record identifier. Keep the separate bounded idempotency-key fix separate.
- Trellis: the existing WOS client extension selects the shared generic route only for remaining known kinds. The WOS admission adapter registers one `wos.provenance` family member, validates through the shared helper, and emits existing neutral event metadata. Register the shared generic literal in `composition::default_admission_policy` dispatch as well as `wos_event_type_specs` catalog metadata; dispatch currently independently lists `WOS_CANONICAL_EVENT_LITERALS`. Keep the canonical array unchanged. Update the HTTP event enum, WOS verification companion, requirement mapping, and a bounded conformance vector together.
- Integrity: private lent ownership of `trellis-verify-wos` native-provenance validation and narrow tests. Interpret original payload bytes through the shared helper; keep WOS-specific interpretation out of generic Integrity crates. Deliver a pinned patch for Trellis integration.

All work occurs in separate private candidates. The original service, keys, histories, and source trees remain unchanged until owner review and authorized adoption.

## What this establishes

Input: original runtime custody records and exact tenant/case routing context. The existing producer selects the canonical route or the shared known-kind fallback. Trellis authenticates and authorizes the request, validates the owning shape, and appends the original record payload. Output: the existing canonical Trellis event hash, checkpoint and bundle references, followed by a receipt stamp on the original runtime record.

The generic event establishes custody of that original record. It does not promote a native kind into a signature, intake handoff, legal determination, notice, or other specialized event. Existing specialized offline checks continue to use their existing canonical mappings. Unknown kinds refuse instead of receiving invented semantics.

## Verification gates

1. Preserve the observed initial full-window failure. A narrowed canonical-kind key test is evidence for key length only.
2. Run paired independent full CODE and architecture BEFORE reviews on the exact shared proposal and helper API before implementation.
3. Assert every existing canonical kind retains its exact route and payload. Assert every remaining known enum kind is accepted by the shared generic validator and round-trips the original record without field loss.
4. Refuse duplicate CBOR map keys (including `recordKind`), unsupported tags/bytes/non-text keys (including tag 0 outside the original bare timestamp, and any tag in the wrapped payload), excessive depth, unreadable or absent offline payload, missing/unknown discriminator, canonical-kind generic bypass, malformed wrapper, additional structural fields, empty original identifier, and malformed known fields. Preserve permitted nested application data exactly.
5. Run a genuine runtime custody window beginning with `OnEntry` through the actual Trellis router/client. Verify every original unstamped record appears once, in order, with its original identifier/kind/data; stamp each returned receipt; repeat and verify no duplicate append. Changed-body replay must refuse.
6. Verify the pinned native ZIP with existing canonical/signature checks plus the owning generic-record check. Mutate the generic payload shape or discriminator and require offline refusal. Show original member bytes and exact receipt/bundle identity.
7. Run paired independent AFTER reviews against frozen sources, patch and actual execution receipts before adoption. Full D1 qualification still requires the real accepted Source filing, WOS history/issued notice, complete immutable evidence members, current grants, and independent offline trust inputs.

## Simplicity and limits

One shared known-kind validator and one registered service event replace the need for 106 new event mappings. Reusing the owning enum prevents a second kind registry from drifting. No speed or memory improvement is claimed. The owning helper/schema and decoder are specified above. Exact error variant names may follow existing Core conventions; a substantive validation change requires review. This proposal is not deployment authority.
