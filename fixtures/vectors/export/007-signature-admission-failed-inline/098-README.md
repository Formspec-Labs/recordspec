# Trellis Export (Fixture) — export/007-signature-admission-failed-inline

WOS-T4 signature export fixture with a readable WOS `SignatureAdmissionFailed` payload. `066-signed-acts.cbor` is the verifier-facing signing projection and must include the rejected act; `068-signed-acts-manifest.cbor` carries the substrate-anchored sealed `(canonical_event_hash, event_type)` list for the admission-failed event; `067-policy-closure.cbor` carries admission-policy evidence.
