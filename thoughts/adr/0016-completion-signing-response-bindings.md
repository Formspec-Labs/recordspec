---
title: Completion certificates with per-signing-event response bindings
status: accepted
date: 2026-10-10
scope: [trellis, integrity]
supersedes: []
---

# ADR 0016 — Completion signing-response bindings

## Decision

Register `trellis.certificate-of-completion.v2` for a certificate that binds every formal signing event to its exact signed response digest. Preserve the registered v1 interpretation and its existing fixtures. Core §6.7 registration is append-only; a lack of certificates in one database does not permit changing v1 meaning.

A complete case can include an accepted initial response and later actually signed case-task responses. Their digests can differ. One aggregate response digest cannot identify what every signer signed. V2 places the required digest beside each existing signer row, in the same order as `signing_events`. It retains one complete-case certificate and the complete case archive.

## Wire shape

`CertificateOfCompletionPayloadV2` retains ADR 0007's fields and byte types: `certificate_id`, `case_ref`, `workflow_ref`, `completed_at`, `signing_events`, `presentation_artifact`, `chain_summary`, `attestations`, and `extensions`. The event's `event_type` and payload extension key are both `trellis.certificate-of-completion.v2`. The only changed nested shape is:

```cddl
ChainSummaryV2 = {
  signer_count: uint,
  signer_display: [+ SignerDisplayEntryV2],
  workflow_status: "completed" / "countersigned" / "notarized" /
                   "partially-completed" / tstr,
  impact_level: "low" / "moderate" / "high" / tstr / null,
  covered_claims: [* tstr],
}
SignerDisplayEntryV2 = {
  principal_ref: tstr,
  display_name: tstr,
  display_role: tstr / null,
  signed_at: [uint, uint], ; Core timestamp; nanos < 1000000000
  response_ref: bstr .size 32,
}
```

V2 has no aggregate `chain_summary.response_ref`. Every `signer_display[i].response_ref` is required and non-null. Its digest meaning comes from the selected consumer's response-proof resolver. For the Formspec/WOS producer it is the unchanged SHA-256 `Response.signedPayload.digest` resolved from the genuine `SignatureAffirmation`; it is not the case-root hash, full-response hash, or presentation hash.

`len(signer_display) == signer_count == len(signing_events)`. Signing-event hashes MUST be unique. Distinct events MAY bind the same response digest. V2 decode MUST reject an aggregate response field, a missing or null row digest, and any ambiguous combination of v1 and v2 certificate extensions.

Presentation attachment binding, raw-byte/content/presentation hashes, exact timestamps, operator-attestation preimage, and certificate-ID stability remain unchanged. The same certificate ID cannot name different canonical payloads across either version. The operator's external trusted-key binding MUST permit the exact v2 event purpose. No new cryptographic primitive is introduced.

## Verification

Explicit version dispatch selects the registered shape. For every index `i`, a v2 verifier MUST resolve `signing_events[i]` to one chain-present event with readable signing evidence. The selected consumer resolver MUST return exactly one response proof and an identifiable principal for that event. The verifier MUST compare the resolved digest to `signer_display[i].response_ref`, principal to `principal_ref`, and exact event timestamp to `signed_at`. Missing/unreadable/unrecognized proof fails `signing_event_unresolved`; malformed digest retains `malformed_response_digest`; a wrong digest fails `response_ref_mismatch`; wrong principal or count fails `certificate_chain_summary_mismatch`; wrong timestamp retains `signing_event_timestamp_mismatch`. One correct row cannot compensate for a wrong or missing row.

The server's product composition supplies its maintained signing-proof resolver to independent substrate verification. A generic no-op resolver cannot qualify a v2 response binding. Operator authority is separately reported as unchecked, verified, or failed according to independently selected external trust, in the Core outcome field `attestation_authority`. Archive possession does not establish current disclosure permission or protected-original readability.

The optional v1 `065` catalog retains its registered v1 scope. V2 authoring does not emit it. Full v2 verification resolves the signed events and attachment binding directly.

V2's supported `covered_claims` tags are `signer_count` (exact event count and row alignment), `principal_ref` (every row's principal matches its signing event), `signed_at` (every row's exact timestamp matches its signing event), and `response_ref` (every row's digest matches its resolved response proof). Unknown tags fail `certificate_covered_claim_unknown`. Empty tags still require all mandatory v2 checks; recognized tags cannot weaken verification. Status and impact extension registries remain empty, so only the enumerated literals and nullable impact are admitted until a normative registry amendment. Unknown strings fail `certificate_enum_extension_unknown`. Existing v1 reader behavior remains separate and unchanged.

## Owning completion inputs

WOS and its selected product binder derive the complete required formal signing set from actual accepted initial evidence and actually signed case-task acts required by the governed workflow. They MUST require exact set equality, rejecting omissions, extras, and duplicates. Task status, notices, checks, and machine callbacks do not create human signing evidence. All such records remain part of the complete case history.

Source supplies unchanged signed response text, evidence, and permitted original bytes. Trellis verifies byte bindings; it cannot infer business completeness, source acceptance, current case permission, signer labels, or operator authority from caller assertions. Current permission and an unchanged complete snapshot are checked around awaited composition/publication.

## Verification evidence required

The focused gate covers two different response digests, repeated digests across distinct events, omission/extra/duplicate refusal, missing/null digest decode, swapped or partly wrong bindings, absent proof, operator purpose mismatch, exact retained HTML extraction, and unchanged v1 vectors. A controlled fixture is byte/protocol evidence, not actual D1 acceptance. Actual full-case acceptance requires the owning Source/WOS inputs, complete permitted original inventory, and current authority.
