# Derivation — `verify/043-export-015-operator-authority-verified`

`input-export.zip` is byte-identical to `export/015-certificate-v2-distinct-responses/expected-export.zip`. Its v2 certificate carries one operator attestation: authority `urn:test:operator`, class `new`, signed with the public development key `../../_keys/issuer-001.cose_key` over the certificate's attestation preimage.

`input-certificate-authorities.json` is the external trust registry the verifier selects, in the shape `certificate_authorities_from_json` reads. Its one row binds `urn:test:operator` to `issuer-001`'s public key for class `new` and purpose `trellis.certificate-of-completion.v2`. The inclusive window `[0, 0]` to `[4102444800, 0]` holds the certificate's `completed_at`.

Core §19 step 6c, step 3: `attestation_authority` is `"verified"` when every attestation row verifies under the selected registry. Here the one row does, so integrity is unaffected and the outcome reports `verified`, where the same bytes with no registry report `unchecked`. The fixture key is public; this establishes no real operator authority.
