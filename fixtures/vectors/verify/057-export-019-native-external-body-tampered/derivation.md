# Derivation — `verify/057-export-019-native-external-body-tampered`

Starts from `export/019-assembled-native-external-attachment/expected-export.zip` and flips the last bit of the single `060-payloads` body. No other member changes and nothing is re-signed.

Core §19 step 4.g: for `PayloadExternal` with `060-payloads/<content_hash>.bin` present, SHA-256 of the file bytes under §9.3 MUST equal `content_hash`. Core §9.4.1: `CONTENT_DOMAIN` hashes exactly the ciphertext-plus-tag body, and outer `content_hash`, reference `content_hash` and binding `payload_content_hash` MUST agree. The flipped body breaks that equality for the one event, which Core §19.1 reports as `content_hash_mismatch` located at the event. Readability stays false: the profile never claims the original readable (Core §9.4.1).

The expected outcome is fixed by the spec text above and confirmed against the maintained Rust verifier (`trellis-conformance`). Bytes were produced by `_generator/gen_verify_resigned_export_negatives.py`, an authoring aid; this document, not the generator, is the reproduction authority.
