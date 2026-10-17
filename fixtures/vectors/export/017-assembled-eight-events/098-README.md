# Trellis export for case_assembled

- scope (manifest.scope): `case_assembled`
- tree_size (manifest.tree_size): `8`
- tree_head_hash (checkpoint[7].tree_head_hash): `be37806fe6bf8f35f410db3a04f27088b02742b476a95ec0331377c37f14b9c0`
- head_checkpoint_digest: `0e63a09a8d532a7ac8724772e38d443ee0d28741a0a0b1059c1353d312b6e616`
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
