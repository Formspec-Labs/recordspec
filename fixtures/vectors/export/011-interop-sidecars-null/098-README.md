# Trellis Export (Fixture) — export/001-two-event-chain

- scope (manifest.scope): `test-response-ledger`
- tree_size (manifest.tree_size): `2`
- tree_head_hash (checkpoint[1].tree_head_hash): `280d335433963c2acb9d71c23546f10417c17d792d10338a7c0ce50d5f5088ba`
- head_checkpoint_digest: `ca746f01dae06a7924e0148e3c7318071e454a11f135202452154eb50b3f1607`
- registry_digest: `651b13673bfa5c30f422512a2e8282479df6c903ff2d6b1cd56f0dca74d4a78a`

## Posture Declaration (manifest.posture_declaration)
```json
{
  "delegated_compute": false,
  "external_anchor_name": null,
  "external_anchor_required": false,
  "metadata_leakage_summary": "Fixture export: envelope reveals event_type, authored_at (1s granularity), retention_tier, classification, ledger_scope, and COSE kid.",
  "provider_readable": true,
  "reader_held": false,
  "recovery_without_user": true
}
```

## Omitted payload checks
```json
[]
```

## Verify
Run `./090-verify.sh` from this directory (or run your verifier directly).
