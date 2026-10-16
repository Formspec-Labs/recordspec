# Trellis export for case_completion

- scope (manifest.scope): `case_completion`
- tree_size (manifest.tree_size): `3`
- tree_head_hash (checkpoint[2].tree_head_hash): `aff3a2ef5cef677771e3e15c89a4842576736aae96edd0886e378c2ac9a28323`
- head_checkpoint_digest: `dcd7c0fbc32d8ee23230ebcdeef202554f3ec8b6e66f202f732e907456908a4d`
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
