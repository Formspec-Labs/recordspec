# Derivation — `export/019-assembled-native-external-attachment`

The maintained Rust test `native_service_append_exports_verified_ciphertext_and_recipient_opens_original` (trellis-service-core) generated these retained bytes with `TRELLIS_ASSEMBLED_EXPORT_VECTOR_DIR` set to a new private output directory. It protects the `append/047` original afresh for the fixture reader, so the data-encryption key and ephemeral wrap are new. `append/047` already pins that fixture's ephemeral key, and Core §9.4 forbids reusing it. The test admits the accepted attachment through the service's prepared-attachment composition, appends it under scope `case_123`, and exports the head checkpoint with `export::assemble`, the same assembly the bundle routes serve.

Core §9.4.1 fixes the expected outcome, and the test asserts it with the maintained Rust verifiers before retaining the bytes:

- The event's `trellis.payload-protection-profile.v1` marker selects the profile; the binding, `PayloadExternal` reference and nonempty suite-1 key bag are well formed, and the `060-payloads` body hashes to the signed `content_hash`. Structure and integrity verify.
- Structural parsing grants no recipient authority, and a generic verifier holds no recipient private key, so it MUST NOT claim the original readable: `readability_verified = false`.
- `trellis-verify-wos` returns the same substrate report with no domain finding.

The test then opens the retained body with the fixture reader's private key (`../../_keys/append047-reader.seed`) and recovers the original. That key is a public test artifact. Event timestamps and encryption entropy belong to the generating run, so regeneration yields different bytes. Replay from these committed bytes is deterministic.
