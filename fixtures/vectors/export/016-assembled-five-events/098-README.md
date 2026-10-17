# Trellis export for case_assembled

- scope (manifest.scope): `case_assembled`
- tree_size (manifest.tree_size): `5`
- tree_head_hash (checkpoint[4].tree_head_hash): `f4fc7c24ecd17cd4423267eed051ba14f48828bff099f3b58329e05e0733d454`
- head_checkpoint_digest: `aaecf9ef599bb19d56ee50c7f34899f6211d4d22f8537ffda4d630a4c4820f98`
- registry_digest: `1b2dd29c1fab2bb8b22a293638075eb955c7505844bc6ecfa1044950e24a5608`

## Posture Declaration (manifest.posture_declaration)
```json
{
  "delegated_compute": false,
  "external_anchor_name": null,
  "external_anchor_required": false,
  "metadata_leakage_summary": "publicMetadata",
  "provider_readable": true,
  "reader_held": false,
  "recovery_without_user": false
}
```

## Omitted payload checks
```json
[]
```

## Verify
Run `./090-verify.sh` from this directory (or run your verifier directly).
