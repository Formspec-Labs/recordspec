# Derivation - `append/014-reinstatement`

ADR 0066 mode 5 reinstatement event on the same chain.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `wos-case:adr0066-fixture-primary`
- `sequence` = `3`
- `prev_hash` = `abeb3b6ff06035f506d93d0406b60989009548a34d86ba51b3c1adaa7a3246d2`
- `event_type` = `wos.governance.reinstated`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.

## Pinned hashes

- `content_hash` = `236204a8317cdc989c3f3476fac75a1052e420e5d28c60565e5dfac70557c7c8`
- `author_event_hash` = `6171a7d6605b0eb519866e37f53c77fef619e342f519b21a1bee249171130505`
- `canonical_event_hash` = `7a748ed167a3ad4be847574a2cf8141df5ca1b146c353e24667413369973e82f`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
