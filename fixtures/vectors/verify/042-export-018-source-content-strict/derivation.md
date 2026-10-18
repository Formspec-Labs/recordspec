# Derivation — `verify/042-export-018-source-content-strict`

Byte-identical to `export/018-assembled-source-content-closeout/expected-export.zip`, verified without selecting the publication phase. The strict phase requires independently admitted opening and Source verification of protected content, and a generic verifier can do neither.

The expected outcome comes from the maintained Rust verifier. The generating test `a_source_content_closeout_export_passes_publication_and_fails_strict_verification` asserts it on these bytes before retaining them. The substrate verifies, and the first WOS failure is `protected_response_unavailable`. It is located at the intake event, the `intake_event_hash` of the `063` catalog row and the native event hash of its protected locator.
