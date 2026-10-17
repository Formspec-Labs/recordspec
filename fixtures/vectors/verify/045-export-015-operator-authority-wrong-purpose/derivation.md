# Derivation — `verify/045-export-015-operator-authority-wrong-purpose`

`input-export.zip` is byte-identical to `export/015-certificate-v2-distinct-responses/expected-export.zip` (see `verify/043`). The selected registry binds `urn:test:operator` to the signing key with the right class and window, but only for purpose `trellis.certificate-of-completion.v1`.

ADR 0016 requires an exact externally trusted operator purpose (TR-CORE-183): a v1 binding does not cover a v2 certificate, even though the signature itself verifies. Core §19 step 6c, step 3 then reports `"failed"` and fails `attestation_insufficient` at the certificate event, as in `verify/044`.
