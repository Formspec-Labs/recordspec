# Trellis export for case_123

- scope (manifest.scope): `case_123`
- tree_size (manifest.tree_size): `1`
- tree_head_hash (checkpoint[0].tree_head_hash): `653ca6c709067929a1ced8805e54e39d6a9ad797188b692840098133a3db4e93`
- head_checkpoint_digest: `ae6e497435908a5cdcd8e5505494c6238527154f025917815e74710e868a5e36`
- registry_digest: `1b2dd29c1fab2bb8b22a293638075eb955c7505844bc6ecfa1044950e24a5608`

## Posture Declaration (manifest.posture_declaration)
```json
{
  "delegated_compute": false,
  "external_anchor_name": null,
  "external_anchor_required": false,
  "metadata_leakage_summary": "compute:native-attachment:retained-custody (readerHeld)",
  "provider_readable": false,
  "reader_held": true,
  "recovery_without_user": false
}
```

## Omitted payload checks
```json
[]
```

## Verify
Run `./090-verify.sh` from this directory (or run your verifier directly).
