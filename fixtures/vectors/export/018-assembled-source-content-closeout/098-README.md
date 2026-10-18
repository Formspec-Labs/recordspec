# Trellis export for case_123

- scope (manifest.scope): `case_123`
- tree_size (manifest.tree_size): `2`
- tree_head_hash (checkpoint[1].tree_head_hash): `8dfa8b25ad02642ab2028c0a582328dda8b771673ca2b99cfa2705abd02e7056`
- head_checkpoint_digest: `a730d0808afb208471606d68e6a5f4f9d637b23ce3c349e12dfb3c701a15cecb`
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
