# Trellis export for case_completion

- scope (manifest.scope): `case_completion`
- tree_size (manifest.tree_size): `3`
- tree_head_hash (checkpoint[2].tree_head_hash): `ab32c3a1336c604b0f17ac6f4dc8da2ba8409891abcb3df9cf2329ea398d1fc7`
- head_checkpoint_digest: `980ec8b5edeacb48ee15ef6dbe239422fa3aedc7d3ab27fe5410cfdb2a1a0641`
- registry_digest: `53f447c0c75b353bf4632e42bc23719f499e77a13ddca86bcc3f7c0d5f0ae6d0`

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
