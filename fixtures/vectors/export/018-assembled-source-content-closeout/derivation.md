# Derivation — `export/018-assembled-source-content-closeout`

The maintained Rust test `a_source_content_closeout_export_passes_publication_and_fails_strict_verification` (trellis-service-core) generated these retained bytes with `TRELLIS_ASSEMBLED_EXPORT_VECTOR_DIR` set to a new private output directory. The test fixture appends a WOS intake event through the append coordinator. A neutral Source-content batch for that intake is stored under the contributor's object key. The test then posts the closeout to `POST /v1/scopes/case_123/events` with a `sourceContent` claim naming the batch. The reference server reads the object with its own credential, checks the claim hash, admits the batch, keeps its scope-keyed copy and appends the closeout. The test fetches the export pinned at the closeout's checkpoint through `GET /v1/scopes/case_123/bundles/{checkpointDigest}`, which runs `export::assemble`.

Before retaining the bytes, the test checks each outcome with the maintained Rust verifiers:

- The bare substrate verifier (`integrity_verify::trellis::verify_export_zip`) passes with no failures. The `substrate-export-verifier` gate pins that for Python.
- `trellis-verify-wos` `verify_source_content_publication` admits the export. This vector pins that outcome.
- `trellis-verify-wos` `verify_export_zip` (strict) keeps substrate structure, integrity and readability but fails `protected_response_unavailable` at the intake event. `verify/042` pins that outcome on these bytes.

Both events carry inline payloads, so substrate readability holds in either phase. Only the protected Response separates the phases.

The batch protects a neutral Response with real HPKE suite-1 encryption to a fixture recipient, so the `060-payloads` member is genuine ciphertext. Its signing, publication and policy hashes are fixed placeholders. The bytes are publication-plumbing evidence only: they confer no Source signing authority, recipient permission or independent-reader readiness. Event timestamps, the minted intake identifier and the encryption entropy belong to the generating run, so regeneration yields different bytes. Replay from these committed bytes is deterministic.
