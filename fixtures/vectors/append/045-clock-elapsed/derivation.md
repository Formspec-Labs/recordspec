# Derivation - `append/045-clock-elapsed`

ADR 0067 clockResolved record marking an independent notice clock elapsed.

The WOS-owned provenance record is dCBOR-encoded as `input-clock-record.cbor`.
Trellis treats that record as inline payload bytes and binds it through
`content_hash`, `author_event_hash`, the COSE signature, and
`canonical_event_hash`.

## Inputs

- `ledger_scope` = `wos-case:adr0067-fixture`
- `sequence` = `2`
- `prev_hash` = `7aff4a05ca33a52ff7ee1af3424da87861a4dd45d323d01402ad3cda4b3ea53e`
- `event_type` = `wos.governance.clock_resolved`
- `event` = `wos.governance.clock_resolved`

## Pinned hashes

- `content_hash` = `4108464aaba3629931577f93e8d0aff9241b357eff54c9673cb16de12e88388f`
- `author_event_hash` = `1018f5f23e106ad547cd58cb47d0ebd4f5c512e8558668faeff6f6a437d25c1b`
- `canonical_event_hash` = `e02fb880cc2c1da186cb83cacc83af505f8c66137bd2239f3d2913e108dc937d`

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
