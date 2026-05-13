# Derivation - `append/046-clock-paused-resumed`

ADR 0067 residual clockStarted segment after a pause/resume boundary.

The WOS-owned provenance record is dCBOR-encoded as `input-clock-record.cbor`.
Trellis treats that record as inline payload bytes and binds it through
`content_hash`, `author_event_hash`, the COSE signature, and
`canonical_event_hash`.

## Inputs

- `ledger_scope` = `wos-case:adr0067-fixture`
- `sequence` = `3`
- `prev_hash` = `e02fb880cc2c1da186cb83cacc83af505f8c66137bd2239f3d2913e108dc937d`
- `event_type` = `wos.governance.clock_started`
- `event` = `wos.governance.clock_started`

## Pinned hashes

- `content_hash` = `4750319e94d1223422feb756ce16747f0ac7da3b69caaba186747bbc27f0227a`
- `author_event_hash` = `948f21151c8d15923efb9143654c260ba298e33741fe48e36046e1de037edd90`
- `canonical_event_hash` = `05177be29f44a6b0df7e44eeac1749960d43af32b15b48c7ddcdefb538dec0ce`

Generator: `fixtures/vectors/_generator/gen_adr0067_clocks.py`.
