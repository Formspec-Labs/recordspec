# Derivation — `export/009-signed-acts-manifest-only`

This fixture realizes the substrate-only branch of the WOS/Formspec signed-acts
contract: the export carries the canonical WOS `SignatureAffirmation` event but
binds only the `068-signed-acts-manifest.cbor` member through
`trellis.export.signed-acts.manifest.v1`. The render-time
`066-signed-acts.cbor` projection and its `trellis.export.signed-acts.v1`
extension are intentionally absent.

The 068 manifest member is a canonical-CBOR array of
`[bstr(canonical_event_hash), tstr(event_type)]` pairs, sorted ascending by
`(hash, event_type)`, derived deterministically from the sealed
`wos.kernel.signature_affirmation` and `wos.kernel.signature_admission_failed`
events in scope (Task A1 / `signed-acts-manifest-v1`). The export-manifest
extension binds `manifest_digest = SHA-256(068 member bytes)` so any drift in
the manifest member is detectable without re-deriving from sealed events.

This shape is permitted: the 066 projection is an optional reporting surface
and exporters MAY omit it. The signed source event chain plus the 068 manifest
remain authoritative.
