# Derivation - `append/012-amendment`

ADR 0066 mode 2 determination-changing amendment event on the same chain.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `wos-case:adr0066-fixture-primary`
- `sequence` = `1`
- `prev_hash` = `9608f5d61f65095cd41847b18188c686d6a4a9d1a3842bbf4043b38b987367fc`
- `event_type` = `wos.governance.determination_amended`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.

## Pinned hashes

- `content_hash` = `eccc272c01c87859adda67279e3606ec5b6606a85cdcf3abc95e7932a15fb210`
- `author_event_hash` = `c6f69ef7f3da83cad85e68f10f61b3ba98af4521e01edfd2cd7c5b309e41b39c`
- `canonical_event_hash` = `c711989ec090246beb736a9d9a00ea33621fb7878fc42abd9f2b5289583a30aa`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
