# Derivation - `projection/006-cadence-positive-time`

**What this vector exercises.** This fixture broadens O-3 cadence coverage beyond the original height-only pair. The deterministic chain authors one event per minute, so a declared `time-driven` cadence with `interval = 120` seconds requires checkpoints at tree sizes 2, 4, and 6.

**Runner contract.** The conformance runner reads the declared `[cadence]` table, observes the checkpoint payload `tree_size` values, and compares them with `required_tree_sizes`. This fixture does not require a wall-clock scheduler; it proves that non-height cadence declarations are preserved in the report surface and can be checked against the fixture-declared required points.

**Expected report.** `expected-cadence-report.cbor` is dCBOR over:

```text
{
  cadence_kind:        "time-driven",
  interval:            120,
  expected_tree_sizes: [2, 4, 6],
  observed_tree_sizes: [2, 4, 6],
  missing_tree_sizes:  [],
  cadence_satisfied:   true,
  failure_code:        null
}
```
