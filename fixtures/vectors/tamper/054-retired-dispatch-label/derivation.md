# Derivation - `tamper/054-retired-dispatch-label`

This vector pins the ADR 0109 tombstone for protected-header label `-65539`.
It starts from `append/001-minimal-inline-payload/expected-event.cbor` and adds
one protected-header map entry:

| Field | Value |
|---|---|
| `alg` | `-8` |
| `kid` | issuer-001 kid |
| `suite_id` | `1` |
| `artifact_type` | `"event"` |
| retired dispatch label `-65539` | `1` |

The COSE signature bytes are left unchanged. A verifier therefore must reject
at protected-header parsing with `RetiredDispatchLabelPresent` / generic
`malformed_cose` report kind before it can reach Ed25519 verification.

The protected-header bytes are:

```text
a501270450af9dff525391faa75c8e8da4808b17433a00010000013a00010001656576656e743a0001000201
```

Invariant reproduction checklist:

- `input-tampered-event.cbor` is 710 bytes.
- `sha256(input-tampered-event.cbor)` is `acaf994620b8dc0adbe2cb0ba03beba39c973cfe26d5cd12d1182a8dcfda72a1`.
- `sha256(input-tampered-ledger.cbor)` is `2fc9802041b4086ba3fef01d4689625f0c6b73ec97e6768da1cf677197e54bd6`.
- Rust, TypeScript, and Python decoders surface the same tombstone rejection reason from the same committed bytes.
