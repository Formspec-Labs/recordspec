---
title: Document signing through existing Trellis bindings
status: accepted
date: 2026-10-20
scope: [trellis, wos, formspec]
supersedes: []
---

# ADR 0017 — Document signing through existing bindings

## Decision

Document signing uses the existing user-content attestation and presentation
hash constructions. This clarification adds no event kind, CDDL field, domain
tag, signature format or verifier rule. [Trellis Core](../../specs/trellis-core.md)
§§6.7, 9.8, 19 step 6d and 28 remain authoritative.

WOS `signingActId` remains in the admitted `SignatureAffirmation` host event.
An existing `UserContentAttestationPayload` binds that event through its signed
`attested_event_hash` and `attested_event_position`. After verifying the
same-scope event binding, a consumer that can read and recognize the host payload
can resolve the act ID, document reference and other WOS evidence from it.
An event hash alone cannot supply unreadable or unrecognized payload fields.

The shared gesture ID is not the Trellis `attestation_id`. Distinct per-document
attestations retain distinct attestation identities: the existing verifier
rejects different canonical payloads sharing an `attestation_id`. Putting an
act ID in an extension also does not add it to the inner user signature's
preimage. The host-event binding supplies the authenticated association.

## Presentation bytes

WOS `presentationHash` uses the existing
`trellis-presentation-artifact-v1` domain from Core §9.8. The maintained
`integrity_cbor::domain_separated_sha256` helper hashes the exact selected
input bytes with Trellis's length-prefixed domain framing. Formspec's
signed-response canonicalization, ceremony wording hash and raw source-document
digest retain their separate meanings.

The selected [P-12 adapter](../../../work-spec/specs/profiles/signature-ports.md)
owns which input bytes are committed. Its default commits exact source bytes;
declared alternatives can bind rendered material. The default does not prove
browser or pixel equivalence. Reusing the domain does not make a
signer's document presentation and a completion certificate's rendered artifact
the same artifact. Each retains its own bytes, digest and reference. The
certificate verifier's artifact check does not independently establish which
document presentation the person saw.

## Composition

[ADR 0085](../../../thoughts/adr/0085-wos-formspec-signature-consumption-binding.md)
and [WOS Signature Profile §2.8](../../../work-spec/specs/profiles/signature.md)
keep Formspec authored evidence distinct from governed WOS provenance.
Formspec primitive verification, WOS admission and any profile-required Trellis
user-content attestation each retain their own checks. An operator seal or valid
chain does not prove that an unchecked source signature passed, nor does it
create missing assent or stronger identity evidence.

[ADR 0010](0010-user-content-attestation-primitive.md) records the original
attestation decision; current Core §28 and the maintained parser govern the
timestamp and preimage bytes. This ADR does not reproduce the earlier
integer-only timestamp sketch. [ADR 0016](0016-completion-signing-response-bindings.md)
continues to bind each completion signing event to its exact source-response
digest.

## Verification and limits

Existing requirement rows TR-CORE-152 through TR-CORE-157 in the
[requirements matrix](../../specs/trellis-requirements-matrix.md) cover
attestation shape, event binding, identity, signature, key state and collisions.
Presentation and completion checks remain under Core §19 step 6c. Their existing
positive and altered-input fixtures retain their original scope. TR-CORE-157
currently records prose coverage; this clarification does not promote it to
executed collision-test coverage.

This decision establishes how existing bytes carry the association; it does not
qualify a routed-signing deployment. In particular, the current WOS signed-acts
catalog compares document fields under a shared act ID. The same-gesture,
different-document case still needs an owning implementation control and any
necessary correction under `fs-jjwc` / `fs-6pb7`. Neither a one-document fixture
nor this clarification proves that multiple-document product path.
