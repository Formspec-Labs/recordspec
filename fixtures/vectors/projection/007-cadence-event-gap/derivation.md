# Derivation - `projection/007-cadence-event-gap`

**What this vector exercises.** This fixture broadens O-3 cadence coverage beyond the original height-only pair. The chain declares an `event-driven` cadence with `interval = 2`; in this fixture every event is qualifying, so checkpoints are required at tree sizes 2, 4, and 6.

**Runner contract.** The conformance runner reads the declared `[cadence]` table, observes checkpoint payload `tree_size` values, and compares them with `required_tree_sizes`. This fixture deliberately omits tree size 4 and therefore must surface `failure_code = "missing-required-checkpoint"`.

**Expected report.** `expected-cadence-report.cbor` is dCBOR over:

```text
{
  cadence_kind:        "event-driven",
  interval:            2,
  expected_tree_sizes: [2, 4, 6],
  observed_tree_sizes: [2, 6],
  missing_tree_sizes:  [4],
  cadence_satisfied:   false,
  failure_code:        "missing-required-checkpoint"
}
```
