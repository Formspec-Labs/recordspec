# Completion and Source-content startup

The normal server first loads its required incoming OIDC profile and current resource grants. Completion and Source content are optional and use two additional private files:

- `TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE`: explicitly selected completion operator keys. Without it the seal route is unavailable. It requires the Source-content file, because the operator key attests whatever selection the caller sends: only that file's `publisher` may seal, checked before anything is reserved or signed (403 otherwise).
- `TRELLIS_SOURCE_CONTENT_CONFIG_FILE`: the WOS Source publisher, provider pins, object store and native closeout policy. Without it a Source-content claim is refused and no append is classified as a final closeout, so a closeout record appends as an ordinary event. With it, a final closeout that carries no Source-content claim is refused (`auth.rs`, the `(None, Some(composition))` arm).

Both absent leaves both unselected. A file setting that is present but empty, or whose file is missing, fails startup. Both files are validated before ledger keys or database setup. Trellis holds no outgoing client, credential or origin for the owning service: the seal body carries the product's selection and the Source claim names an object Trellis reads from its own store.

The operator file is a closed JSON array of one to eight objects. Each object requires `authority` (unique nonempty string), `authorityClass` (`prior` or `new`), `publicKey` (32-byte integer array), `validFrom` and `validUntil` (Unix seconds and nanoseconds pairs), and `coseKeyFile` (explicit private COSE key path). The existing signer checks the public/private key pair and finite increasing interval. Selection matches authority, class, and public key exactly. It never implicitly reuses the ledger event key.

The Source-content file is a closed JSON object:

```json
{
  "pins": {"providerSelectionHash": [..32 bytes..], "nativePolicyHash": [..32..], "recipientPolicyHash": [..32..]},
  "publisher": "principal-of-the-wos-machine",
  "objectStore": {"bucket": "wos-source", "endpoint": "https://s3.example", "region": "us-east-1", "prefix": "source"},
  "nativeHostSelectionFile": "native-selection.json",
  "nativeHostSelectionSha256": "sha256:..."
}
```

`publisher` must equal the principal the authorizer admits for the WOS machine's Append. It is the one publisher: any other principal carrying a claim, and any other principal sealing a completion, is refused. `pins` must equal the claim's provider, native-policy and recipient-policy hashes. `objectStore` locates the prepared-batch objects; the read credential is the launcher's process credential, as for WOS's archive read store, and Trellis only ever reads: it opens the bucket once the bucket records the deployment's cell (`stack-cell`) without writing, so a read-only credential suffices there. WOS records it once it opens its Source bucket as a `ScopedBucket` (ADR 0168 unit W); until then a read-only credential cannot open an unrecorded bucket, and a read-write one has Trellis record the cell in WOS's bucket. The object key is `<scope key>/wos-source-content/sha256_<hex>` under `prefix`: `trellis_server_ports::source_content_object_name` derives the name from the preparation key, and the admitted scope's `ScopedObjects` puts it under that scope's key (ADR 0168 §1.4).

Secret and COSE paths resolve relative to their containing configuration file; absolute paths are also accepted. Every file must be a private regular file owned by the current user, have no group/other permissions, and stay within one MiB. Final symlinks and nonregular files are refused. Diagnostics contain no credentials.

The owning service remains responsible for current person permissions, legal case association, complete evidence census, and the selection it sends. Successful configuration loading does not qualify those behaviors.
