# Derivation - `append/043-clock-started`

ADR 0067 clockStarted record opening a statutory response clock.

The WOS-owned provenance record is dCBOR-encoded as `input-clock-record.cbor`.
Trellis treats that record as inline payload bytes and binds it through
`content_hash`, `author_event_hash`, the COSE signature, and
`canonical_event_hash`.

## Inputs

- `ledger_scope` = `wos-case:adr0067-fixture`
- `sequence` = `0`
- `prev_hash` = `null`
- `event_type` = `wos.governance.clock_started`
- `event` = `wos.governance.clock_started`

## Pinned hashes

- `content_hash` = `8ddd8917246a7892298cc27e6835d4f887a78fc579f31c1746291768d6fe425f`
- `author_event_hash` = `251a8e5dcff54687a9ec13733284978b6e0b7f63e795b988e77e90ca3fb86188`
- `canonical_event_hash` = `f7778887da517ff96c07ef010be9cc39963dbe7d15f53357e3818f45588a66ba`

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
