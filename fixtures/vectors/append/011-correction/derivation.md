# Derivation - `append/011-correction`

ADR 0066 mode 1 correction-authorizing act on the existing chain.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `wos-case:adr0066-fixture-primary`
- `sequence` = `0`
- `prev_hash` = `null`
- `event_type` = `wos.governance.correction_authorized`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.

## Pinned hashes

- `content_hash` = `2f722c9e20c48c39c88f58c309d0b28973caa00e3524e451818d499ec216df55`
- `author_event_hash` = `1ce043a6b33b6a3491973cb1615cb39312dd151d8f560dd5a35cdaaf67522bea`
- `canonical_event_hash` = `9608f5d61f65095cd41847b18188c686d6a4a9d1a3842bbf4043b38b987367fc`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
