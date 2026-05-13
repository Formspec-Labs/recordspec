# Derivation - `tamper/050-rescission-terminality`

This vector exercises ADR 0066 D-3 rescission terminality. The first three
events are copied byte-for-byte from `append/011-correction`,
`append/012-amendment`, and `append/013-rescission`. The fourth event is a new
`wos.governance.determination_amended` event with:

- `sequence` = `3`
- `prev_hash` = `abeb3b6ff06035f506d93d0406b60989009548a34d86ba51b3c1adaa7a3246d2`
- `event_type` = `wos.governance.determination_amended`

The fourth event recomputes `content_hash`, `author_event_hash`, and
`canonical_event_hash`, then signs the resulting payload under
`issuer-001`. Hash linkage, content hash, and signature verification all pass.

The failure is semantic and chain-local: the chain already observed
`wos.governance.determination_rescinded`, and no
`wos.governance.reinstated` event appears before the later determination
amendment. Core section 19 step 4.h / TR-CORE-171 requires the verifier to
record `rescission_terminality_violation`.

Pinned failing event id: `fc5e98eaebd68b1d290d30ea2dfbed8e27de640d95bd016807e245ad76cc4101`.

Generator: `fixtures/vectors/_generator/gen_tamper_050.py`.
