# `export/014-interop-sidecar-c2pa-manifest` derivation

Wave 25 positive — c2pa-manifest@v1 dispatched verifier.

Built by `_generator/gen_interop_sidecar_c2pa_037_to_040.py` from
`export/001-two-event-chain`: the manifest is re-emitted with
`interop_sidecars: [<one c2pa-manifest@v1 entry>]`, the sidecar file
`interop-sidecars/c2pa-manifest/cert-wave25-001.c2pa` is added, and the
manifest is re-signed under `_keys/issuer-001.cose_key`.

The sidecar bytes are a synthetic five-field Trellis assertion
dCBOR map (mirrors `trellis-interop-c2pa::emit_c2pa_manifest_for_certificate`).
For path-(b) digest-only verification, the wrapping format is
irrelevant — the verifier only recomputes
`SHA-256(trellis-content-v1, file-bytes)` and compares to
`manifest.interop_sidecars[0].content_digest`.

The runners rebuild the ZIP byte-for-byte from `input-ledger-state.cbor`
+ per-member files (Core §18.1 deterministic ZIP) and then verify it
against `[expected.report]`.

`zip_sha256 = a22270c5de5c7ffe278df969dda423f56675f0c5b175e5572752210ce448289d`
