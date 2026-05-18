# Derivation — `verify/022-066-render-drift-tampered-only`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`acts[0].bound.document_id` in `066-signed-acts.cbor`, recomputes the
`catalog_digest` under `trellis.export.signed-acts.v1`, and re-signs
`000-manifest.cbor`. The ZIP remains structurally valid, every manifest digest
matches archive contents, and `068-signed-acts-manifest.cbor` is left
untouched — so it still byte-equals the deterministic
`signed-acts-manifest-v1` derivation over the sealed events.

The verifier reports advisory `signed_acts_render_drift` (066 projection bytes
disagree with the canonical derivation) but the relying-party verdict stays
valid because the load-bearing substrate-anchored 068 manifest is intact.
Distinct from `verify/019-export-006-signed-acts-render-drift`, which mutates a
signer field; this fixture mutates a bound-subject field. Together they pin the
"render drift on any 066 surface is advisory only" invariant.
