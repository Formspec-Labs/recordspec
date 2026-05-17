# Derivation — `verify/020-export-006-signed-acts-unsupported-rule`

This fixture starts from `export/006-signature-affirmations-inline`, changes the
`trellis.export.signed-acts.v1.derivation_rule` manifest-extension value to
`signed-act-projection-wos-formspec-unsupported`, and re-signs `000-manifest.cbor`.
The ZIP remains structurally valid and all member digests match archive
contents, but the WOS validator has no registered derivation implementation
for that rule ID and must reject it as `signed_acts_catalog_invalid` without
falling back to the v1 derivation.
