# Derivation - `tamper/053-unknown-artifact-type`

This vector pins the ADR 0109 closed enum for Trellis substrate
`artifact_type` values. It starts from
`append/001-minimal-inline-payload/expected-event.cbor` and rewrites only the
protected header value at COSE label `-65538`:

| Field | Baseline | Tampered |
|---|---|---|
| `alg` | `-8` | unchanged |
| `kid` | issuer-001 kid | unchanged |
| `suite_id` | `1` | unchanged |
| `artifact_type` | `"event"` | `"x-adr0109-unknown"` |

The COSE signature bytes are left unchanged. A verifier therefore must reject
at protected-header classification with `ArtifactTypeUnknown` / generic
`malformed_cose` report kind before it can reach Ed25519 verification.

The protected-header bytes are:

```text
a401270450af9dff525391faa75c8e8da4808b17433a00010000013a0001000171782d616472303130392d756e6b6e6f776e
```

Invariant reproduction checklist:

- `input-tampered-event.cbor` is 716 bytes.
- `sha256(input-tampered-event.cbor)` is `47fe399f262bd01838b1439050b3f43d8a289f2777d102618a2df9a1a6058fd9`.
- `sha256(input-tampered-ledger.cbor)` is `cf60716e842fbe4cc073dd86efc032883cbcdfdd4fee05fc5f7d47c3154bb492`.
- Rust, TypeScript, and Python decoders surface the same closed-set rejection reason from the same committed bytes.
