# Derivation — `export/006-signature-affirmations-inline`

This fixture realizes the Trellis side of the WOS-T4 signature export contract.

It starts from `append/019-wos-signature-affirmation`, packages that canonical
event as the only event in the export, and derives
`062-signature-affirmations.cbor` from the readable WOS-authored
`SignatureAffirmation` payload already carried inside the signed event.
It also derives `066-signed-acts.cbor`, a verifier-facing projection over the
same signed record with nested signer, bound-subject, consent, admission, and
source-reference sections.
The export also includes `067-policy-closure.cbor`, the effective
admission-policy evidence snapshot for this signing profile. That closure
records intent/method registries, posture floors, authority shape, defaults,
deny rules, tombstones, and validity windows, but it explicitly leaves trust
roots, adapter allowlists, and server operational configuration to the verifier
or runtime environment.

Both catalogs are chain-derived rather than independently authored. Each row names
the admitting `canonical_event_hash` and repeats the WOS evidence fields needed
for verifier/reporting surfaces to summarize the signing act without redefining
canonical authority. The policy closure is evidence, not executable verifier
configuration. The human-facing certificate remains a derived artifact; the
signed Trellis export remains the authority.
