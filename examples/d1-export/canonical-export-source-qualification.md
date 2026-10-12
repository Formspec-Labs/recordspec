# Canonical export source qualification

The maintained packages now expose the acquisition and generic native-provenance capabilities previously present only in qualified integration candidates. This completes source integration; it does not qualify a completed application case or adopt a new running server.

The client preserves original attachment bytes through `AcceptedAttachmentAppendBody::from_original_bytes` and acquires the exact checkpoint ZIP through `TrellisServiceClient::bundle_bounded`. `S3CompatibleArtifactStore::get_bounded` enforces bucket/prefix selection and delegates byte/deadline collection to the maintained Common reader. Existing unbounded methods and service authentication remain unchanged. Limits apply to retained output, not all transport buffers or expanded ZIP contents.

The WOS helper uses `wos.provenance.recorded` only for recognized record kinds without canonical mappings. Ingress and independent verification reuse `wos-events::NativeProvenanceEvent`; canonical kinds cannot bypass their existing routes. Default registration, HTTP schema/OpenAPI, and offline conformance agree. Generic custody does not establish specialized business meaning or disclosure permission.

## Verification

- API regression: canonical consumer tests failed with `E0599` for missing bounded acquisition methods.
- Behavioral regression: 29 client tests passed and one failed because the old helper emitted `original-entry-trigger` instead of `wos.provenance.recorded`.
- After integration: all 30 client tests and 17 ports tests passed.
- Owning native-provenance filters: 2 admission, 1 offline schema, 1 dispatch, and 6 verifier tests passed.
- `scripts/check-http-api-schema.py` passed with 31 admitted literals. This check invokes its maintained Cargo OpenAPI emitter and contract tests.
- Independent semi-formal code and architecture reviews approved the final canonical diff. Their review scope preserved OIDC, completion, protected attachments, external certificate-authority verification, and strict payload refusal.

The bounded Cargo runs used toolchain `1.94.0`, offline resolution, locked green runs, one build job, the existing shared target, three coordination locks, a 3 GiB free-space floor, and owned process groups. Test logs and execution receipts remain at `/private/tmp/trellis-canonical-finish-20261011-v1/`; this document retains the result without copying an experiment tree.

Common dependency: `9a0712714a31918de5b2846ea6b398d7c4fc07c4`. Integrity dependency: `e5be2622bffc68aaf47c021c471b5f30f979d0f8`. Baseline Trellis: `72ada0ca2c271bdefc3f6d0a30f6a67e45e16ede`.

The existing service, application data, original accepted records, keys, and storage were not changed. Runtime adoption and actual whole-case export/offline verification remain separate owning-service work.
