# append/010 — WOS `custodyHook` state transition

This vector admits one WOS-authored provenance record through the Trellis
canonical append surface. It exercises the Core §23 split:

- WOS owns the authored fact bytes.
- Trellis owns the envelope, canonical append, hash chain, and signature.
- The idempotency input comes from the WOS-owned ADR-0061 tuple
  `(caseId, recordId)`.

## Pinned WOS inputs

The authored WOS record is the dCBOR-native record in
`input-wos-record.dcbor`. It represents a Kernel Facts-tier
`stateTransition` record:

- `caseId = "linc_case_01j5d5p0c8e9g2h3j4k5m6n7p8"`
- `recordId = "linc_prov_01j5d5p1d9f0h3j4k5m6n7p8q9"`
- `event = "wos.kernel.state_transition"`
- `fromState = "intake"`
- `toState = "review"`
- `inputs[0] = "submitted"`
- `timestamp = "2026-04-21T14:30:00Z"`

The Trellis event header uses `event_type = "wos.kernel.state_transition"`.
This satisfies Core §23.4's `wos.*` namespace rule and remains
outcome-neutral: the event type names the WOS record family, not whether a
benefit, permit, claim, or other adjudication was granted or denied.

## Idempotency construction

The WOS-owned source tuple is encoded in
`input-wos-idempotency-tuple.cbor`:

```json
{
  "caseId": "linc_case_01j5d5p0c8e9g2h3j4k5m6n7p8",
  "recordId": "linc_prov_01j5d5p1d9f0h3j4k5m6n7p8q9"
}
```

Per Core §23.5, the fixture derives the Trellis `idempotency_key` as a
32-byte SHA-256 digest over the dCBOR-encoded map, framed with the §9.1
domain-separation discipline under the accepted ADR tag
`trellis-wos-idempotency-v1`. The map is exactly
`{"caseId": caseId, "recordId": recordId}`; both values are untagged CBOR text
strings and the dCBOR encoder orders the keys lexicographically.

## Envelope construction

`ledger_scope` is the UTF-8 byte string
`"wos-case:linc_case_01j5d5p0c8e9g2h3j4k5m6n7p8"`, so the event is scoped to
one WOS case per Core §23.3.

`sequence = 0`, so `prev_hash = null` per Core §10.2.

`payload_ref` is `PayloadInline` whose `ciphertext` bytes are the WOS dCBOR
payload. This is a structural fixture: like append/001, it carries the payload
bytes opaquely to exercise append surfaces without asserting HPKE behavior.

`content_hash` is the Core §9.3 `trellis-content-v1` hash over those payload
bytes. The `author_event_hash`, canonical event payload, COSE_Sign1 envelope,
and `AppendHead` are then constructed by the same Core §§6, 7, 9, and 10 rules
as the other append vectors.

## Non-goals

This vector does not test posture-transition sequencing. Core §23.2 and the
Operational Companion require WOS governance decisions that alter Trellis
posture to produce two facts: the WOS governance record first, then the
Trellis posture-transition event. Existing append/006-008 vectors cover
posture-transition envelope mechanics; this vector covers the WOS-authored
record admission immediately before that kind of follow-on transition.
