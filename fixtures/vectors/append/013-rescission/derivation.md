# Derivation - `append/013-rescission`

ADR 0066 mode 4 determination-rescinded event on the same chain.

## Inputs

- Issuer key: `_keys/issuer-001.cose_key` (Ed25519 / suite-id 1).
- `ledger_scope` = `wos-case:adr0066-fixture-primary`
- `sequence` = `2`
- `prev_hash` = `c711989ec090246beb736a9d9a00ea33621fb7878fc42abd9f2b5289583a30aa`
- `event_type` = `wos.governance.determination_rescinded`
- WOS/Formspec-owned payload bytes: `input-adr0066-record.cbor`.

The payload record is dCBOR-encoded as the inline ciphertext marker. Trellis
does not interpret the WOS governance fields in this positive append vector;
the envelope binds them through `content_hash`, `author_event_hash`, the COSE
signature, and `canonical_event_hash`.

## Pinned hashes

- `content_hash` = `8ee38134e98d56a9aa1f264f17d345cbea555988b168dd4d2192c921bc7c8364`
- `author_event_hash` = `835d5b7b50c4ee4e40a37b9b125809137d92701315424afb069fbe039085ac7f`
- `canonical_event_hash` = `abeb3b6ff06035f506d93d0406b60989009548a34d86ba51b3c1adaa7a3246d2`

Generator: `fixtures/vectors/_generator/gen_append_011_to_015.py`.
