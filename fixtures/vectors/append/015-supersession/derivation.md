# Derivation - `append/015-supersession`

ADR 0066 mode 3 new-chain supersession event with registered Trellis linkage extension.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `wos-case:adr0066-fixture-superseding`
- `sequence` = `0`
- `prev_hash` = `null`
- `event_type` = `wos.kernel.supersession_started`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.

## Supersession extension

`EventPayload.extensions["trellis.supersedes-chain-id.v1"]` carries
`SupersedesChainIdPayload`:

- `chain_id` = `wos-case:adr0066-fixture-primary`
- `checkpoint_hash` = `fce9e813193b1a0bb1f5568da9190ad38bd6926e17b74f39b62f922842cdda85`

This pins Core section 6.7 / section 28 and TR-CORE-169 at the fixture layer.

## Pinned hashes

- `content_hash` = `aa455f2e406dec21c14b9abb749d67e1a3c138044ad0588178f435de98d3adcd`
- `author_event_hash` = `5dc4d037dbf86c7f834e6551df17512aed00490afdfe7a8a6ee0183aaa6d5a46`
- `canonical_event_hash` = `56e4c34d5945c51d4d3c9a12b9e3808574efad05116f7f3280d7ca73771406cd`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
