# Trellis Test Vectors

## Directory layout

```
fixtures/vectors/
├── append/NNN-slug/         # one directory per vector
├── verify/NNN-slug/
├── export/NNN-slug/
├── tamper/NNN-slug/
├── _keys/                   # pinned COSE_Key bytes + README
├── _inputs/                 # pinned payloads / prior heads + README
└── _generator/              # Python authoring aid (non-normative, §7)
```

Ordering within each op-dir is lexicographic via prefix (`001-`, `002-`, …). Underscored directories signal non-vector scaffolding and are excluded from conformance-runner walks.

## Vector contract

Operation-first tagged union. Each vector declares its `op` in its manifest and carries op-specific inputs and expected outputs. The runner dispatches on `op` rather than on directory placement — a vector is self-describing and relocatable.

- **append** — `(prior_head?, signing_key, authored_event) → (canonical_event, signed_event, next_head)`. Runner byte-compares outputs against committed sibling files.
- **verify** — `(ledger_artifact) → VerificationReport`. Runner compares report fields (`structure_verified`, `integrity_verified`, `readability_verified`) against inline expected.
  `[expected.report]` is the **WOS-resolved relying-party verdict** (Trellis substrate plus WOS domain findings, with WOS-owned references such as completion signing events resolved), not the bare Trellis verdict. A Trellis-only verifier reports `export/015` as `integrity_verified = false` (`signing_event_unresolved`) and must compose the WOS layer before comparing. The same holds for `export` and `tamper` reports.
- **export** — `(ledger_state) → zip_bytes`. Runner byte-compares ZIP bytes against committed expected, validates the manifest `zip_sha256` pin against the committed ZIP, and verifies the ZIP, comparing the report to the required inline `[expected.report]` (a byte-exact ZIP that does not verify to its labelled outcome fails the build).
- **tamper** — `(tampered_artifact) → VerificationReport` where at least one `*_verified` flag is false. Runner compares failure kind + failing event id.

Manifest input/expected fields mirror whatever Core says each API's signature is. This spec does not re-normatize the API — it reflects Core.

## Source-content publication vectors

`verify` and `export` vectors may select a non-default verifier with `inputs.verifier`. The only value is `"source-content-publication"` (ADR 0163): both runtimes verify the ZIP with `verify_source_content_publication` (Rust `trellis_verify_wos`, Python `trellis_py.verify_wos`) instead of the strict verifier and compare the report to `[expected.report]` as usual. Absent means strict.

`verify/028..039` are derived from `export/007` by `_generator/gen_intake_export_007.py` (protected locators, native provenance refusals, a mixed-family Source task row with native task records and a joined protected original; ciphertext, keys and Source proofs are fake). Each admitted bundle has a strict-phase twin with the same bytes.

**Reserved slot — real-route vector (fs-cy14).** The Source-content export captured through the real export route (the `claude/export-job` seal route, ADR 0163/0164) lands as `verify/040-source-content-publication-real-route/` with `inputs.verifier = "source-content-publication"`, `export_zip` the bytes the route produced (capture them, never regenerate), and the labelled outcome in `[expected.report]`. Add its strict twin as `041-…` with the strict outcome. Both runners pick it up with no code change; if the bytes diverge between runtimes, fix the lagging runtime, not the label.

## Conformance runner contract

Vectors are pure data. There is no shared runner protocol. Each implementation writes its own runner in its own language; implementations couple only through the committed vector bytes.

Runner responsibilities:

- Walk `fixtures/vectors/{append,verify,export,tamper}/*/`, ignoring `_`-prefixed siblings.
- Parse `manifest.toml`, dispatch on `op`.
- Load inputs; invoke the local `append` / `verify` / `export` API.
- For `append` / `export`: byte-compare output against expected sibling files.
- For `verify` / `tamper` / `export`: compare report fields against inline `[expected.report]` (for `export`, the report is of `expected-export.zip`).

A shared stdin/stdout protocol was considered and rejected. It would dilute the stranger test by introducing a second normative artifact beyond Core — "did I implement the protocol right?" competing with "did I implement Core right?" Data-only preserves the ratification bar.

## See also

- `_generator/README.md` — authoring discipline and generator constraints; consult this when adding a new generator script.
- `../../../thoughts/specs/2026-04-18-trellis-g3-fixture-system-design.md` — full normative design: manifest schema, derivation-evidence convention, coverage enforcement, and rationale for all decisions made here.
