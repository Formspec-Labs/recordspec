# Derivation — `verify/019-export-006-signed-acts-render-drift`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`066-signed-acts.cbor`, recomputes the `catalog_digest` under
`trellis.export.signed-acts.v1`, and re-signs `000-manifest.cbor`. The ZIP
remains structurally valid, every manifest digest matches archive contents,
and the substrate-anchored `068-signed-acts-manifest.cbor` member is untouched
and still equals the deterministic `signed-acts-manifest-v1` derivation over
the sealed events.

The 066 catalog is a downstream render-time projection whose bytes can
legitimately drift across renderers; its byte mismatch with the canonical
derivation is reported as advisory `signed_acts_render_drift`. The 068 manifest
is the substrate-anchored proof of which signed-act source events landed, so
render drift alone never blocks the relying-party verdict.
