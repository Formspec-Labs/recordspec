# Derivation — `verify/044-export-015-operator-authority-wrong-key`

`input-export.zip` is byte-identical to `export/015-certificate-v2-distinct-responses/expected-export.zip` (see `verify/043`). The selected registry binds `urn:test:operator` with the right class, purpose and window, but to `../../_keys/issuer-002.cose_key`'s public key, a real key that did not sign the attestation.

Core §19 step 6c, step 3: authority is `"failed"` unless every row verifies under the selected registry, and a failed check fails `attestation_insufficient`, which flips `integrity_verified`. The failure is located at the certificate event's canonical hash.
