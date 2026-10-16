# Derivation — `verify/028-source-content-publication-protected-intake`

Starts from `export/007-intake-handoffs-public-create`: the `063` row drops
`response_bytes` and carries a `protected_response` locator whose native event
hash, Response ref and Response hash equal the intake anchor and handoff. The
ciphertext and key material are fake; the publication phase checks only the
closed locator and its native binding, never decryption or Source signatures.
The catalog digest and the signed manifest are recomputed.
