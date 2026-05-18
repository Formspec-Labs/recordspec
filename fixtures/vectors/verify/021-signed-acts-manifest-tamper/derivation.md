# Derivation — `verify/021-signed-acts-manifest-tamper`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
the final byte of `068-signed-acts-manifest.cbor`, and leaves the signed
`000-manifest.cbor` unchanged. The substrate-anchored signed-acts manifest is
the load-bearing proof of which signed-act source events landed, bound to the
manifest extension `trellis.export.signed-acts.manifest.v1.manifest_digest`.

The WOS validator must localize the failure to
`signed_acts_manifest_extension_digest_mismatch` (substrate-shape failure;
blocking) and the relying-party verdict MUST become invalid. Render drift on
the 066 projection alone never blocks; substrate drift on the 068 manifest
always does.
