# Derivation — `tamper/056-policy-closure-digest-mismatch`

This fixture starts from `export/006-signature-affirmations-inline`, mutates
`067-policy-closure.cbor`, and leaves the signed `000-manifest.cbor` unchanged.
The verifier must localize the failure to the effective policy-closure evidence
digest bound by `trellis.export.policy-closure.v1.closure_digest`.
