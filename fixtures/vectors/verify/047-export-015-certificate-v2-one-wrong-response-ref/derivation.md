# Derivation — `verify/047-export-015-certificate-v2-one-wrong-response-ref`

Starts from `export/015-certificate-v2-distinct-responses/expected-export.zip` and mutates the payload of its last event as described below. The event's `author_event_hash` (Core §9.5) is recomputed and the event re-signed with the public fixture key `issuer-001`. Every member that binds the event is rebuilt: the events array, the Merkle root and the re-signed head checkpoint (Core §11.2–§11.3), the inclusion and consistency proofs (Core §11.4), any `061` row's `binding_event_hash`, the seal-fence fields including `export_attempt_id` (Core §18.3e), the README head lines, the archive root name, and the re-signed manifest with its digests. The verifier therefore reaches the obligation under test rather than a stale digest.

Core §19 step 6c (v2): a wrong digest fails `response_ref_mismatch`, and "a matching row cannot compensate for another row's failure." Row 0 still matches its signing event; row 1's digest is 32 bytes of `ee`.

The expected outcome is fixed by the spec text above and confirmed against the maintained Rust verifier (`trellis-conformance`). Bytes were produced by `_generator/gen_verify_resigned_export_negatives.py`, an authoring aid; this document, not the generator, is the reproduction authority.
