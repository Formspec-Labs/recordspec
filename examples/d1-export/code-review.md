# D1 export candidate: independent static code-review certificate

Review ID `trellis-d1-export-code-2026-10-08-01`; reviewer `/root/oidc_code_review`, nonauthor. Skill `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` read in full and applied. Applicable root/Trellis instructions were read in this reviewer's session; direct report-only ownership and no Cargo/build/live-call instructions govern. Only this certificate was written; unrelated `Cargo.lock` preserved.

## Findings first

**F1 — BLOCKER / correctness / `examples/d1-export/writer-qualification.md:7`. Resolved during review.** The linked Integrity candidate pin `85eb389f53f387d34301a5d8234bf53031f7ebbaf879c4e4386bcf6113534491` differed from the linked file's observed SHA-256 `b66d35465a90823c67fdcceaf7a92acdd0dcd30e18a69e03228c39613fc082d4` during review. This is concurrent candidate drift, not a duplicate-format problem. Refresh that pin and the input-pin map after the Integrity owner freezes its candidate. Author removed the mutable cross-owner digest and now explicitly routes exact version/pins to Integrity's certificate before execution. Reviewer read the correction and verified this candidate's final pins. No review of the Integrity wire body's semantics is claimed here.

**F2 — WARNING / test-coverage / `examples/d1-export/probes/native-fixture-results.json` (`pythonAttempts`). Resolved during review.** Initial Python records omitted exact input binding, invocation and source provenance. Author added fixture path/hash, argv/script/cwd, source HEAD and hashes for all `trellis_py/*.py` files without rerunning unchanged checks. Reviewer verified all source digests against disk and complete source-map coverage. Original failed import and successful output remain preserved. These are author-recorded process results; this reviewer did not independently execute verifiers.

**F3 — OBSERVATION / security / `crates/trellis-server/src/http.rs:258`.** Native retrieval authorizes whole scope and ignores extracted tenant context (`261,273–278`); head exports all scope events (`144–155`). Thus header propagation is not field-level disclosure or tenant-grant proof. Candidate correctly states this limitation (`writer-qualification.md:13,195`) and defers runtime qualification. Retain it when root executes requests; do not promote a successful ZIP download into X4 field-visibility evidence.

**F4 — OBSERVATION / test-coverage / `writer-qualification.md:17–29`.** Native writer has no inputs/emission for the listed payload/attachment/affirmation/handoff/completion/open-clock members. Existing fixture archives contain some of those members, but verifying those archives does not test current writer emission. Candidate accurately records the gap and preserves the source-event requirement and generic failing emission gate (`197`). This is a D1 qualification limitation, not a requirement that every conformant export contain every optional catalog.

## 1. Patch summary and review binding

Scope: authored `retrieval.http`, `writer-qualification.md`, `probes/native-fixture-results.json`, `review-input-pins.json`. No implementation changed. Intent: native HTTP requests plus honest writer/member and complete Need coverage, with synthetic fixture evidence; no D1-completion claim or second `BundleCreateRequest` body. Trellis source HEAD `3d1380ba00749b8c6b6ac0d3672216fc24bcd19f`; Integrity source HEAD observed `d2dd4827cd294aaecc470e6a49dd8954a48880cf`. Trellis tracked diff only contains unrelated Cargo.lock; examples are untracked authored candidates.

Reviewed input SHA-256:

| Input | Digest |
| --- | --- |
| `retrieval.http` | `a1cb65249c9c4b2d37e5ed94bd483ba1bf93e7f00fd986155ba99bea2f809153` |
| `writer-qualification.md` | `04c48c8f3f98534d0260961f7bcd8d86983807642bbe362822dd58240545c38d` |
| `probes/native-fixture-results.json` | `15614c6cf78dfaa151221b6f8a58db2ec219083c9365af5db10d31368c9c6973` |
| `review-input-pins.json` | `b7ac159c6260c2b425ef433594ffad2f2e573a7c8b2135b213c9c432fcdcca11` |

Source evidence pins: writer `crates/trellis-export-writer/src/lib.rs` `955cac11ad0dc1966b4484aed25a096eab58386229345871ad7f522d560db60b`; server `lib.rs` `5a3c68dfbebe4fe06782b759cb868f23b94f86124b4a37209c5d4e4694ddd0f1`; server `http.rs` `7d8efedb29e93f4a1eb37a8c987a0c39401655f9dbd487e37f41e74d7e8752f6`; export profile `31c42a9eea217e1cec972bd23c20317ecfb37253e23ab15cb78a7515a835dcd4`.

Full Need import at sibling `formspec-studio/demo-authoring/sources/d1-full/v0.3.0/complete-d1-needs-import-v0.3.0.json` hashes to the declared `2b349b10fda5618543d0aa6dcd79ee1632e87c593c5f43edc89a2cdc3a7b88b8`. Static comparison verified every indexed ID, title and `statement.done`: 39 entries, no missing/extra/changed entries. This verifies exact transcription, not requirement fulfillment.

## 2. Function trace

All source paths are relative to Trellis unless a sibling is named. No functions are modified by the patch; these are behavior-critical callers/callees supporting document claims.

| Function / schema | File:line | Inputs | Output | Verified behavior |
| --- | --- | --- | --- | --- |
| `getHeadBundle`, `getBundleByCheckpointDigest`, `getSigningKeyRegistry` | `specs/trellis-http-api.schema.json:74,95,121` | scope/context and digest for pin | ZIP / CBOR or problem | GET paths/content types match request candidate |
| `router` | `crates/trellis-server/src/http.rs:27` | state | router | registers those routes at 44–51 |
| `head_bundle` | `http.rs:138` | scope, tenant headers, bearer | ZIP/error | authorizes, locks, reads all scope events, calls publish with head update |
| `pinned_bundle` | `http.rs:177` | scope, digest, headers | ZIP/error | normalize; existing pin lookup; missing pin publishes head then returns head only if digest matches, otherwise 404 |
| `read_authorized` | `http.rs:258` | headers and scope | unit/error | authenticates; Read scope authorization; no tenant/field grant comparison |
| `normalize_checkpoint_digest` | `http.rs:361` | bare/prefixed hexadecimal | lowercase sha256 pin/error | validates 64 hex digits; documented lowercase-prefixed request is accepted |
| `signing_key_registry` | `http.rs:224` | scope, headers | CBOR/error | Read authorization then current server signing registry; no external trust assertion |
| `bundle_response` | `http.rs:282` | record/store | ZIP/error | reads stored artifact; not-found if absent |
| `publish_bundle` | `crates/trellis-server/src/lib.rs:190` | state, scope, closed events, compute | bundle record/error | empty set404; event-derived timestamps/high-water; profile composition; writer; verifies; immutable store/index |
| `build_export_profile_members` | `crates/trellis-server/src/export_profile.rs:129` | scope, events, policy artifacts | optional 066/067/068 | no signed acts returns empty; closure only when eligible; catalogs derived before writer |
| `write_export` | `crates/trellis-export-writer/src/lib.rs:354` | `ExportWriterInput` at247 | signed deterministic ZIP/error | validates/prepares; proof/checkpoint/registry generation; manifest signature; emits base members and optional031/066/067/068 |
| `verify_export_zip` | `trellis-py/src/trellis_py/verify_wos.py:229` | ZIP bytes | substrate/domain report | invokes core with domain resolver; returns early on invalid structure; then validates domain export/events |
| report `verdict` / `_verdict_from_parts` | same file:115,127 | substrate + findings | layered verdict | structure/integrity gate; only failure-severity findings block domain/projection verdict |

## 3. Data flow and invariants

Request placeholders hold privately supplied credential and requested tenant/workspace/environment/cell; literal ledger path fixes the pending-review baseline (`retrieval.http:1–14`). Context headers match shared `HeaderConfig::wos` (`../stack-common/crates/stack-common-http/src/tenant.rs:34–41`). Placeholder values are not credentials or grants. Request outputs must remain private; candidate saves no returned case bytes or tokens. These requests are documentation, not executed HTTP evidence.

Checkpoint identity is created by native writer from the last checkpoint (`writer lib.rs:377–380`), included in signed manifest (`1264–1265`), formatted by server (`server lib.rs:261`), and used by pinned route lookup. Archive SHA-256 and checkpoint digest are separate identities; neither is an invented case-completion proof. Head can mutate publication state; pinned miss can also publish (`http.rs:194–206`). Candidate warns GET may publish (`retrieval.http:4`). Reproducibility depends on preserved indexed artifact, not treating head as immutable.

Writer input owns scope/events/registries/signing material, optional catalogs and seal fence (`writer lib.rs:247–289`). Server derives inputs from closed event snapshot and selects optional members (`server lib.rs:200–260`). Writer binds/signs and returns ZIP bytes; server verifies before immutable publication (`272–287`). No unsealed catalog can supply new signing authority. Optional policy evidence is distinct from verifier trust roots (`writer lib.rs:283–288`; core spec:1208).

The writer table is supported by all emitted entries (`writer lib.rs:431–493`) and input fields. Spec permits optional attachments/affirmations/handoffs/signed acts/policy/open clocks (`specs/trellis-core.md:1398–1407`) and optional completion catalog (`355`). No D1 backend or top-level retention field is introduced. Complete case history, privacy, notices, clock closure, signing and sample retention remain desired consumer evidence in the index, not produced members.

Probe data binds author-recorded outputs to tracked synthetic fixtures and existing binary. Reviewer independently checked current fixture hashes, ZIP member lists, tracked status, binary hash `72c0ff37365061b6e8669a67e08e23e1090080e804fcdac9492c556f0c73e46d`, and corrected Python source maps. Binary digest does not prove source provenance; author explicitly says it is not a current-source rebuild. All probe validation by reviewer was metadata/byte inspection, no verifier execution.

## 4. Test behavior and edge cases

**Reviewer executed no tests, Cargo/build or live calls.** Read-only JSON/hash/ZIP-list checks establish artifact binding only. Author receipt records five Rust verifier exits0; Python import attempt exits1 and retry exits0 for fixture010 with resolved certificate/signing/attachment links and policy-closure advisory. Author results are bounded to these inputs. No changed code means no patch-induced test behavior change; predictions below follow inspected assertions, not execution.

| Relevant test inspected | Location | Assertion/trace and limits |
| --- | --- | --- |
| `pinned_bundle_returns_existing_checkpoint_with_normalized_digest_forms` | server `lib.rs:1540` | append→head→prefixed/bare/uppercase pin; statuses200 and all ZIP bytes equal (`1613–1615`); local state, not reader grants |
| `pinned_bundle_returns_not_found_for_unknown_checkpoint_after_head_publish` | server `lib.rs:1619` | append then ff digest; asserts404 at1640; missing historical pin not guaranteed by head rebuild |
| `signature_affirmation_append_publishes_profile_members_verified_by_wos_verifier` | server `lib.rs:1644` | append→head; requires066/067; substrate pass and no WOS findings/valid result (`1666–1686`); confirms existing server composition, not D1 complete history |
| `publish_bundle_is_byte_identical_across_independent_states` | server `lib.rs:1972` | same admitted sequence/signing key sent to independent states; loaded archive bytes equal at2043; no proof of current running binary |
| `write_export_binds_signed_acts_catalog_when_provided` | writer `lib.rs:2067` | member hash equals input; signed-manifest catalog_digest/ref/derivation assertions; byte carriage, not domain semantics |
| `write_export_emits_068_member_when_signed_acts_manifest_provided` | writer `lib.rs:2130` | raw empty CBOR catalog carried and digest bound; comments explicitly say verifier does not run (`2133–2134`) |
| `write_export_binds_policy_closure_when_provided` | writer `lib.rs:2243` | member and manifest digest/ref/version assertions; no trust-root acceptance |
| `test_certificate_response_ref_mismatch_fixture_fails_substrate_verification` | Python `tests/test_verify_wos.py:454` | malformed reference fixture: structure true, integrity false, response_ref_mismatch in event and completion outcome |
| `test_certificate_malformed_response_digest_fixture_fails_substrate_verification` | Python same:474 | malformed digest: structure true, integrity false, named failure in event and completion outcome |

Concrete scenarios: advancing head after late/reopen events requires new head while retaining earlier pin (medium reproducibility risk; native pin test covers stable pin, no late/reopen D1 fixture here). Missing historical artifact cannot be recreated from later head alone (medium; missing pin404 covered). Same whole-scope grant with restricted fields can still expose full archive (high; not covered by these probes). Fixture containing061/062/063/065 does not imply writer can emit those members (high qualification risk; accurately distinguished). Advisory policy closure absence may coexist with valid cryptographic result (medium; recorded in both010 outputs, and verdict implementation distinguishes failure severity). No tests in this slice establish complete Need fulfillment, actual D1 signer identity, trusted-key pin consumption, native photo/response bytes, field filtering or offline complete history.

## 5. Exploration and dispositions

H1 (medium), motivated by request comments: native path/context/content types match handlers. Read schema, router/read helpers and normalization; confirmed, with head/pin publication side effects. H2 (medium), motivated by member table: writer gaps are real despite fixtures carrying richer members. Read full input/emission path and server profile caller; confirmed with066/067/068 existing support. H3 (medium), motivated by full-index claim: exact import text is preserved. Read pinned import, compare IDs/title/Done; confirmed all39. H4 (medium), motivated by recorded verifier success: evidence is fixture-only and requires exact process/input/source binding. Byte and JSON inspection confirms Rust binding; Python correction resolved initial omission. H5 (low), motivated by cross-owner link pin: mutable candidate may drift; observed F1 and routed correction to author.

Unresolved/outside scope: Integrity wire candidate semantics/full verifier recipe, cryptographic dependency internals, entire Python verifier dependency graph, source provenance of existing Rust executable, Presenter UI implementation, baseline case's actual records, configured reader grants, durable storage and live retrieval. Source evidence does not establish runtime safety. No need to duplicate Integrity-owned wire request or build a new export route to review these documents.

## 6. Conclusion

VERDICT: APPROVE — scoped documentation/request/receipt commit only.

The native requests and bounded writer/probe claims otherwise achieve the authored candidate intent. Full Need transcription is adequate; runtime/full-D1 qualification coverage is INSUFFICIENT and explicitly deferred. Confidence HIGH for source/request/artifact checks, MEDIUM for probe execution provenance because recorded runs were not independently repeated. F1/F2 corrections were re-read and all final input pins verified. No unresolved commit blocker remains in this slice. This certificate never grants runtime or D1-completion acceptance.
