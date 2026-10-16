# trellis-py

Standalone Python implementation of Trellis Phase-1 **append**, **verify**, and **export** (deterministic ZIP), plus a local vector conformance runner. Used for G-5 ratification: behavior is fixed by `../specs/trellis-core.md` and the committed corpus under `../fixtures/vectors/`.

## Working directory (monorepo vs submodule)

Paths below are written for two common checkouts:

| Checkout | `trellis-py` directory |
|----------|-------------------------|
| Trellis repo root (`.../trellis/`) | `trellis-py/` |
| Stack monorepo root (`.../formspec-stack/`) | `trellis/trellis-py/` |

Vector discovery defaults to `../fixtures/vectors` **relative to this package**, so conformance must be run with cwd inside `trellis-py`, or pass `--vectors` explicitly (CI uses `pip install -e "./trellis/trellis-py"` from the monorepo root).

## Install

```bash
# From Trellis repo root:
cd trellis-py && pip install -e .

# From stack monorepo root (matches CI):
pip install -e "./trellis/trellis-py"
```

## APIs

- `trellis_py.append_event(signing_key_cose: bytes, authored_event: bytes) -> AppendArtifacts`
- `trellis_py.export_to_zip_bytes(entries: list[ExportEntry]) -> bytes`
- `trellis_py.verify_export_zip(export_zip: bytes) -> VerificationReport`
- `trellis_py.verify_tampered_ledger(registry: bytes, ledger: bytes, ...) -> VerificationReport`
- `trellis_py.verify_wos.verify_export_zip(export_zip, authorities=None) -> WosVerificationReport` — strict WOS-domain verification; `authorities` is an externally trusted `CertificateAuthorityRegistry` (`{authority URI: TrustedCertificateAuthority}`) for operator attestations, otherwise authority is reported `unchecked`.
- `trellis_py.verify_wos.verify_source_content_publication(export_zip, authorities=None) -> SourceContentPublicationReport` — ADR 0163 publication phase (`publication_admitted`, `substrate`, `findings`, `blocking_reasons`). Admits protected Response and Source task catalog rows without requiring their content; it is never final Source readiness.

## Conformance

```bash
# Default vectors root: ../fixtures/vectors relative to this package — cwd must be trellis-py.
cd trellis-py   # from Trellis root; or: cd trellis/trellis-py from stack monorepo root
python -m trellis_py.conformance

# From monorepo root without cd (after `pip install -e "./trellis/trellis-py"`):
python3 -m trellis_py.conformance --vectors trellis/fixtures/vectors

# Same, editable tree only (no pip install):
PYTHONPATH=trellis/trellis-py/src python3 -m trellis_py.conformance --vectors trellis/fixtures/vectors

# explicit path + JSON report
python -m trellis_py.conformance --vectors /path/to/fixtures/vectors --write-report BYTE-MATCH-REPORT.json
```

**Pytest (G-5):** from `trellis/` repo root, `cd trellis-py && python3 -m pytest -q`. From stack monorepo root, `cd trellis/trellis-py && python3 -m pytest -q`, or `PYTHONPATH=trellis/trellis-py/src python3 -m pytest trellis/trellis-py -q` if you keep cwd at the root.

Exit code `0` means every vector under `append/`, `export/`, `verify/`, `tamper/`, `projection/`, and `shred/` passed.

## Source-content publication (ADR 0163)

`verify_source_content_publication` is the counterpart of Rust
`trellis_verify_wos::verify_source_content_publication`; catalog readers live in
`trellis_py.source_content`. Both runtimes check the closed protected Response
locator, the closed `sourceSignedCompletedTask` rows and their protected proof
packages, the exact native `taskCreated` / `taskCompleted` join, and the
original-context join. Neither opens protected content or verifies Source
signatures, and the batch checks and Source-opening verifiers are Rust-only.

Native provenance records are validated as Rust validates them
(`trellis_py.native_provenance`): the owning JSON Schema ships as package data
(`schemas/`, pinned byte-for-byte to
`work-spec/schemas/wos-native-provenance-event.schema.json` by a test), with the
`date-time` and record-TypeID formats enforced, the signed-64-bit/finite-float/
depth-128 subset, and the TypeID grammar. A missing schema refuses every record.

Python also refuses CBOR reference tags (string-reference 25/256, value-sharing 28/29) before decoding, as Rust leaves them as tags and refuses them.

Python refuses some RFC 3339 timestamps Rust accepts (lowercase `t`/`z`, `23:59:60`, year `0000`); that is the stricter side and intentional.

Python rejects duplicate map keys anywhere in the 062/063 catalogs; Rust does so
only in closed maps and takes the first match in 063 (fs-465t), so Python is the
stricter side there.

## Dependencies

`cbor2`, `cryptography` (Ed25519), `jsonschema` + `rfc3339-validator` (native provenance schema). No Rust runtime is required at import time.

## Out of scope (intentional)

The Python G-5 oracle implements **path-(b)** of the ADR 0008 interop-
sidecar dispatched verifier — digest-binds only, no `source_ref`
resolution, no C2PA manifest decode (Wave 25). That is the same
discipline `trellis-verify` follows in Rust; both implementations
treat the manifest store as opaque bytes whose SHA-256 (under
`trellis-content-v1`) is the only verifiable surface.

The **C2PA-tooling-path consumer** (read manifest from PDF/JPEG,
decode the `org.formspec.trellis.certificate-of-completion.v1`
assertion, run the five-field cross-check against the canonical
chain) is **not ported to Python**. That path lives in Rust under
`trellis-interop-c2pa` and is consumer-tier per ADR 0008 §"`c2pa-manifest`"
(an adopter picks a C2PA SDK and integrates the assertion bytes into
their PDF rendering pipeline). Porting it to Python would force every
G-5 oracle deployment to ship a C2PA SDK; the path-(b) discipline
sidesteps that by checking only the bytes the export ZIP catalogues.
