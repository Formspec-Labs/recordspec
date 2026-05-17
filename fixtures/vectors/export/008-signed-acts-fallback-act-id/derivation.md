# Derivation — `export/008-signed-acts-fallback-act-id`

This fixture realizes the additive SignedAct projection rule for source rows
that do not carry a shared signing act id.

It packages a single readable WOS `SignatureAffirmation` payload copied from
`append/019-wos-signature-affirmation` with `data.signingActId` removed. The
manifest binds `066-signed-acts.cbor` under
`signed-act-projection-wos-formspec-v2`. The projected row derives `act_id`
as `signed-act-projection-act-id-v1:<sha256>` over the canonical CBOR bytes of
the sorted `source_refs` array.

The signed source event remains authoritative. The fallback id is only
correlation data for deterministic projection and verifier reporting.
