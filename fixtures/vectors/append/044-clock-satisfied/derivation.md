# Derivation - `append/044-clock-satisfied`

ADR 0067 clockResolved record satisfying the opened response clock.

The WOS-owned provenance record is dCBOR-encoded as `input-clock-record.cbor`.
Trellis treats that record as inline payload bytes and binds it through
`content_hash`, `author_event_hash`, the COSE signature, and
`canonical_event_hash`.

## Inputs

- `ledger_scope` = `wos-case:adr0067-fixture`
- `sequence` = `1`
- `prev_hash` = `f7778887da517ff96c07ef010be9cc39963dbe7d15f53357e3818f45588a66ba`
- `event_type` = `wos.governance.clock_resolved`
- `event` = `wos.governance.clock_resolved`

## Pinned hashes

- `content_hash` = `583122626d3a3d84aaa5f962bd873d20d9190bd95df7b0a6de8cc4f15f29fbc2`
- `author_event_hash` = `25572f40648c5eabd3228158a9f05ecd71da0c9bf0b44eecfd2234a7e1a32cc9`
- `canonical_event_hash` = `7aff4a05ca33a52ff7ee1af3424da87861a4dd45d323d01402ad3cda4b3ea53e`

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
