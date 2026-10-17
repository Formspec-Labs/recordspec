# Derivation — `verify/055-export-019-native-external-missing-binding`

Starts from `export/019-assembled-native-external-attachment/expected-export.zip` and mutates the payload of its last event as described below. The event's `author_event_hash` (Core §9.5) is recomputed and the event re-signed with the public fixture key `issuer-001`. Every member that binds the event is rebuilt: the events array, the Merkle root and the re-signed head checkpoint (Core §11.2–§11.3), the inclusion and consistency proofs (Core §11.4), any `061` row's `binding_event_hash`, the seal-fence fields including `export_attempt_id` (Core §18.3e), the README head lines, the archive root name, and the re-signed manifest with its digests. The verifier therefore reaches the obligation under test rather than a stale digest.

Core §9.4.1: the marker's host event MUST carry `trellis.evidence-attachment-binding.v1`, and "Core §19 extension processing MUST reject ... missing attachment bindings". The `061` catalog row still names the rebuilt event.

The certificate or profile rule rejects the event's payload, and an event that does not decode rejects the export: structure, integrity and readability are all false. The spec does not fix which check reports the rejection first. Both the seal-fence high-water decode (Core §18.3e) and event decoding (Core §19 step 4.c) read this last event, so the failure kind is not pinned.

The expected outcome is fixed by the spec text above and confirmed against the maintained Rust verifier (`trellis-conformance`). Bytes were produced by `_generator/gen_verify_resigned_export_negatives.py`, an authoring aid; this document, not the generator, is the reproduction authority.
