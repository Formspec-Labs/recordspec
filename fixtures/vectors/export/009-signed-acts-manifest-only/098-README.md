# Trellis Export (Fixture) — export/009-signed-acts-manifest-only

WOS-T4 signature export fixture that binds only the substrate-anchored `068-signed-acts-manifest.cbor` member through `trellis.export.signed-acts.manifest.v1`. The render-time `066-signed-acts.cbor` catalog and its `trellis.export.signed-acts.v1` extension are intentionally absent: the 068 manifest is the load-bearing proof of which signed-act source events landed, while the 066 projection is an optional reporting surface that may legitimately be omitted.
