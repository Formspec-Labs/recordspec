# Derivation — `tamper/052-cert-response-ref-malformed-digest`

Starts from `export/010-certificate-of-completion-inline`. Event 1's `data.signedPayloadDigest` is rewritten to a 64-character non-hex marker (`ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ`) while `signedPayloadDigestAlgorithm = "sha-256"` is preserved, so the WOS resolver still recognizes the payload as a sha-256-claimed signing event but cannot parse the digest as hex.

Phase-N posture (Trellis review F2): the resolver returns `Err(ResolverError::MalformedResponseDigest)` (Rust) / raises `MalformedResponseDigestError` (Python) instead of silent-skipping. `finalize_certificates_of_completion` translates this into a fail-closed `malformed_response_digest` failure localized to the certificate event's `canonical_event_hash`.

The certificate event itself carries a well-formed `chain_summary.response_ref` (byte-equal to the positive fixture); only the SignatureAffirmation record's digest text is malformed. This isolates the malformed-digest path from the mismatched-digest path covered by `tamper/024-cert-response-ref-mismatch`.

Generator: `_generator/gen_export_010_certificate_of_completion.py`.
