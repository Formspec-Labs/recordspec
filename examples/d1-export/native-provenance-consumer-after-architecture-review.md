# Native provenance consumer: final AFTER architecture review

**VERDICT: APPROVE the exact qualified consumer routing change within the private qualification scope.** Source and execution evidence support the shared-owner routing, HTTP admission, schema registration and offline domain-check integration. No blocking architecture correction remains in this consumer change. The actual runtime-window ZIP has not been qualified through the complete owning offline verifier. That remains an export acceptance gate; this certificate does not establish full D1, deployment, production authority or adoption.

Reviewer: `/root/oidc_arch_review`, independent non-author, October 9, 2026. Full `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied; retained `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` informs source inspection. This reviewer ran only read-only source/digest comparisons, wrote only this certificate, and ran no Cargo, native binaries, live services or adoption operations. Execution statements below describe retained owner receipts, checked against source and logs.

## 1. Artifact summary

Qualified snapshot: `/private/tmp/core-native-provenance-inputs-v1-20261009/trellis`. Exact packet `native-provenance-qualified-consumer-inputs.json` SHA-256 `8982b06ef40dbdd2d5e33ce5f1840566224f2d8ea139d326a6f5224bd7066079`. Portable consumer patch SHA-256 `da9505aad0693a18e0bc8e77e7f0862e1ed67a9fd98049d568ac030192702957`; bounded test delta SHA-256 `d7bbb7dbc3122c94632776096871488b61a45b69a6c0b3ca53ab24dba8a75328`. All 16 packet source/spec hashes match the qualified snapshot independently.

Patch baseline: Trellis `ea8f547367e4d41d09395001230ccf14705af8c9`. Current separately adopted authentication work is `3d59b235a0b3d12c1596529dc9fb1385284f17df`; this packet is not proof of integration with that commit. Preserve its authorization/replay guarantees in eventual integration rather than applying baseline files wholesale.

Problem: 106 known native provenance kinds outside the existing 28 canonical routes could not traverse complete custody. Decision: add one service-only `wos.provenance.recorded` route containing the complete original supported JSON record, interpreted by the maintained Core `NativeProvenanceEvent` helper. Category: proof infrastructure supporting independent case-history inspection. Core owns native kind recognition, strict conversion, schema and producer selection; Trellis owns client/admission/composition/HTTP surface; WOS companion validation supplies domain checks alongside generic Integrity proof.

Qualification receipt: root `thoughts/plans/benefits-scenarios/execution/reports/work-spec/full-d1/native-provenance-qualification-receipt-v1.json`, SHA-256 `bd388601cd21c705ba26cb56646eab533372a432a27c8cb21a52dcbfc23fa2cb`, identical to snapshot `execution/qualification-receipt.json`. It records 401 passing named tests after retained failed attempts, no production changes during execution and clean process-group release. This review verifies all seven retained stage-log hashes, exact packet/patch hashes and all 7,712 final source-guard hashes; it does not rerun the tests or independently observe historical process termination.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Root production goal | Requires independent evidence surviving the live server | `GOAL.md:Product Claim, Critical Path`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Paired successor proposal | Constrains generic eligibility, original data and ownership | `native-provenance-routing-proposal-v2.md`, SHA `083f72794b9b020c99fdcc2c0a311bc3dc3e25cf3640c1353828f8b216bd8aa8` |
| Core API v3 | Declares bare timestamp exception and strict JSON/CBOR subset | root reports `work-spec/full-d1/native-provenance-core-api-before-v3.md`, SHA `b34ce813af78538e2c9621bc678684d8aa29604da41a84f932e815ce808fbc82` |
| Independent successor BEFORE | Approves corrected source-specific design; preserves prior RECONSIDER | `native-provenance-before-architecture-review-v2.md:§3,§6–7`, SHA `20749da8a1ed8367d07301eff354207eb883a174defce91d3b813c8b64bd1bfb` |
| Consumer static gate | Establishes source shape before compilation | `native-provenance-consumer-v2-static-architecture-review.md`, SHA `a07cb761a2a53b0636cf6662a75ba8cb8c4fc69adde3d496e90a42f0a73e7614` |
| Normative substrate and domain seams | Signed payload proof separate from specialized WOS evidence | snapshot `trellis/specs/trellis-core.md:§9,§18–19`; `specs/wos-trellis-verification.md:§1,§7/WOS-TV-028` |

| Component / named seam | Owner | Depends on | Consumed by |
| --- | --- | --- | --- |
| `NativeProvenanceEvent` / owning schema | Core wos-events | Native enum/record and strict raw decoder | Producer, client, admission, offline |
| Custody window and receipt stamp | Core runtime | Original persisted records and shared helper | Existing Trellis client |
| `wos_ext` / `SubstrateAppendRequest` | Trellis client | Core helper and existing generic request | Maintained HTTP ingress |
| Admission/catalog/dispatch | Trellis WOS adapter/composition | Shared literal/helper | Generic append and registry |
| Canonical schema URI / local Registry | Core schema, Trellis HTTP/conformance | Actual selected owning dependency | API users and schema checks |
| WOS `RecordValidator` | WOS companion / Integrity review ownership | Core-derived payload bytes and same helper | Offline relying-party verdict |
| Authentication and publication evidence | Separate host/provider owners | Current authority, grants, genuine owned evidence | Actual deployment / full D1 |

These are named existing seams extended with one route, not a second SDK, export creator or consumer-specific interpretation in generic Integrity code.

## 3. Invariants and commitments

1. **Closed owner model and canonical routes — PRESERVED.** Client generic branch delegates to the shared helper (`crates/trellis-service-client/src/wos_ext.rs:44–58`); admission registers then validates the same literal (`trellis-admission-wos/src/lib.rs:65–89,131–137`). Composition explicitly dispatches it separately from the canonical array (`trellis-server/src/composition.rs:224–233`). Unknown kinds and canonically mapped kinds cannot enter generic custody. Failure would allow specialized validation bypass or silent audit loss. Executed adapter suites and source inspection support this boundary; the runtime window exercises several kinds, not every enum variant in one workflow.

2. **Original facts before conversion — PRESERVED with explicit representation limit.** Runtime window test `work-spec/crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:107–215` validates the original bare custody bytes through `from_record_dcbor_slice`, exports through the actual router/client, decodes each signed event, and compares full original JSON, order and IDs. Bare root timestamp tag0 is allowed only by Core's source-specific policy; wrapped payloads remain untagged. JSON equality does not assert byte equality between tagged original storage and HTTP transport. Failure would erase source fields before validation or mutate persisted bytes.

3. **Receipt enrichment and replay — PRESERVED in tested window.** Same window compares every stamped record with its original plus only `canonicalEventHash`, replays the exact request with equal receipt fields, rejects changed-body reuse with 409, retries stamped inputs with no new outcomes, and compares unchanged head ZIP bytes. These are genuine maintained-runtime records in a controlled fixture, not externally accepted program-case evidence.

4. **One schema authority / actual dependency — PRESERVED.** HTTP schema line460 references the canonical owning `$id`. Checker lines23–30 resolves actual admission's wos-events dependency; conformance `native_http_schema.rs:10–39` resolves its selected dependency and registers that schema locally. Executed conformance accepts the valid fixture and rejects invalid generic shapes; OpenAPI parity tests pass. Copying schema into Trellis would create a competing authority.

5. **Offline domain validation actually wired — PRESERVED.** `trellis-verify-wos/src/native_provenance.rs:10–35` checks exact generic payload bytes using the shared decoder and yields blocking missing/invalid findings; `validator.rs:23–26` invokes it. Static errors do not expose original record data. The 63-test owning verifier suite passes separately. This does not establish full verifier success on the actual runtime-window ZIP.

6. **Trust and specialized meaning — PRESERVED / RELIED-UPON.** `specs/wos-trellis-verification.md:§1,§7` keeps generic custody distinct from signature, filing, legal decision, notice and clock authority. Core signed byte/checkpoint proof and externally supplied trust remain prerequisites under `trellis-core.md:§9,§18–19`. A generic record proves transported facts, not their legal sufficiency. Full D1 must retain accepted Source history, genuine WOS authority/evidence and complete offline trust checks.

7. **Frozen qualification / dependency direction — PRESERVED.** Before/final guard delta has exactly three declared test/fixture repairs: Core runtime test source; Trellis typed-client expected JSON; tenant-prefixed fixture ID. No guarded production file changes during execution. Compared with preserved v2 there is also a qualification-only Cargo manifest path normalization to coherent snapshot siblings; this is not a third behavior repair or production dependency change. Lock reconciliation is private execution evidence, not automatic authority to stage lock edits or overwrite separate auth work.

## 4. User-value and simplicity analysis

A reviewer can inspect complete native custody without 106 new specialized public event definitions. One shared kind/shape check serves producer, admission and offline validation, paying down duplicated interpretation and reducing drift risk. The HTTP schema now names the same owner resource that conformance actually resolves. Existing append, signer, writer and bundle formats remain the proof path.

The added costs are a bounded generic registration, consumer wiring and test-only schema dependencies. No measured speed or memory benefit is claimed. Generating 106 routes adds unsupported meaning; accepting arbitrary records abandons the closed model; a canonical-only history loses facts. Shared routing is the smallest adequate shape among those alternatives. The value is refuted if complete native history still drops records, mutates data, bypasses canonical validators or cannot be independently checked after server shutdown.

The corrected client test now compares `serde_json::to_value(&record)` computed before request construction. Empty optional collections omitted by the maintained typed serializer therefore do not create a false failure. That test checks the typed API; the raw original-preservation assertion remains independently covered by the runtime window. The fixture now uses the maintained `default_` tenant prefix. Neither correction weakens production rejection behavior.

## 5. Counterfactual analysis

Kill criterion: a known native fact disappears, generic transport accepts canonical/unknown kinds, raw decoding admits ambiguous input, or malformed generic evidence passes the owning offline check. Opposite decision leaves incomplete custody or multiplies kind-specific routes. Removing this change first breaks the maintained runtime's full-window append at remaining kinds. Core helper/schema subsume consumer interpretation; generic Integrity primitives subsume byte proof but cannot supply WOS kind meaning.

Six-month critic: 401 passing tests could be mislabeled as full D1 or as verification of the exact runtime ZIP. Preserve the distinction: runtime-export equality/replay evidence, independently executed verifier-suite evidence, and actual exported-ZIP full-verifier acceptance are separate observations. The last is still required.

## 6. Findings

**F1 — KEEP; OBSERVATION; named-seam/ownership.** Shared Core helper, canonical schema URI, explicit composition dispatch and wired WOS offline validation match the approved design. Preserve the single owner and one literal; no duplicate consumer decoder or new export request is justified. Evidence: §2–3 source traces and qualified adapter/schema/OpenAPI results.

**F2 — KEEP; OBSERVATION; intent-vs-shape.** Both consumer test repairs correct expectations to maintained tenant-ID and typed-serialization behavior. Full raw JSON preservation remains tested separately in the runtime window. Evidence: bounded test-delta patch and source guard comparison. No RESHAPE or REVERSE requirement remains for this exact consumer change.

**F3 — DEFER; OBSERVATION; scope.** Before an actual native export acceptance claim, feed the exact runtime-window ZIP and pinned verification context to owning `verify_export_zip`, retain its verdict, and mutate a generic payload to demonstrate offline failure. The current 63-test verifier suite cannot substitute for that test. This is the remaining export gate, not a block to accepting the bounded routing architecture.

**F4 — DEFER; OBSERVATION; commitment/integration.** Adoption must preserve separately qualified auth commit `3d59b235a0b3d12c1596529dc9fb1385284f17df` and review the actual combined tree/dependency edges. This review authorizes no live operation, source adoption, foreign lock edit, full D1 or production-current-authority claim. Evidence: final packet adoptionStatus and original patch baseline.

## 7. Verdict and exact execution boundary

**APPROVE the exact qualified consumer routing decision.** Intent MATCHES complete native custody with bounded meaning. User value SUPPORTED by actual maintained window export/equality/replay plus owning suite results. Commitments HONORED within reviewed scope. Conceptual debt PAYS DOWN duplicated native interpretation; sibling subsumption PARTIAL through existing Core/Integrity owners. Confidence HIGH for pinned source and bounded qualification; actual ZIP full offline acceptance remains unqualified.

All six reasoning phases completed. H1 shared routing preserves original facts CONFIRMED for the executed native window; it is not an exhaustive workflow claim. H2 production changed to make tests green REFUTED by exact 7,712-file final guard and three declared test/fixture deltas. H3 client test expectation proves raw original-byte equality REFUTED; it proves typed JSON behavior. H4 schema parity is source-only REFINED by executed local resource and OpenAPI tests. H5 actual native ZIP passed complete offline verification REFUTED by test body and receipt scope. No phase is skipped.

The final successful stages total 317 Core events/runtime + 81 admission/client/verifier + 1 focused HTTP-schema + 2 OpenAPI = 401 named tests. Three failed attempts remain retained; the result is not a first-run-pass claim. Commands used `--offline --locked -j1`; focused schema/OpenAPI stages leave unrelated tests filtered. Receipt records 600-second stage timeout, 32-MiB log bound, 2-GiB disk floor, reused target and cleared process groups. This is no fresh-cache, full-workspace, production service or performance qualification.

Source guard before SHA `b9c8211bfc400a5df4e3b7f38e3fec0bab2955bc690fec5072f3727457200918`; final SHA `7fb286f3a537f6b399c1ca82c2cd81e69100c8d8381448ddacd19dd61efb54c3`. Lock reconciliation SHA `25b96e5ecd984885d4d852aecc80191728e23353b1cf64c7918461285147c5a4`; private Trellis resolved lock `e4a1f711ac99f089cf796b82f29f1b6c218d2982f5b28acace7460cb85f5517e`. It adds jsonschema/referencing 0.46.1 and micromap 0.3.0 alongside existing 0.45.1 and records dependency edges; no automatic lock adoption follows.

### Qualified consumer source pins

Paths below are relative to `/private/tmp/core-native-provenance-inputs-v1-20261009/trellis`.

| File | SHA-256 |
| --- | --- |
| `crates/trellis-admission-wos/src/lib.rs` | `e3092704dd73fe916f9fa4c873fee46fcaec2b0b08effa74639ba830c23778f7` |
| `crates/trellis-service-client/src/lib.rs` | `4c608bad9c89cfb9125dbc619864cd2cd37193b3486a705d2bb9863142d3d7f3` |
| `crates/trellis-service-client/src/wos_ext.rs` | `7e57ce296cdae460a221f554a45c69df6b80f16ead764c060090b0f3a9a03bb6` |
| `crates/trellis-server/src/composition.rs` | `61717cd16c8135ee56cc0e13ce799c5270dadfdad5819d10b1e2649f6d9aac7f` |
| `crates/trellis-server/src/openapi.rs` | `c7d5c526af8e212138f6802b24e88bf6460dcb2cc329934231e2a6751c7f781e` |
| `crates/trellis-verify-wos/src/lib.rs` | `b0cc2fa240d5bd51d2a1b9965930c132900cd499b899a3cd8f1cc3c31ee737e9` |
| `crates/trellis-verify-wos/src/validator.rs` | `e62ae040c4ab84711179ac31eabe253898b33d5b00bd5542d235e623a1ed31d0` |
| `crates/trellis-verify-wos/src/native_provenance.rs` | `82553ea2c5d311204a0828375530b0223b813dfcea93047cda6a1e82dcce3d67` |
| `specs/trellis-http-api.schema.json` | `3dd79d92c4e6613db438867c27468880dbb7189d9188eb1e5ceae4348d5fec4e` |
| `specs/wos-trellis-verification.md` | `c424283b03622140af9c99dbc1fcf105fa9e035b39f430d1045af8c41c96a4c2` |
| `specs/trellis-requirements-matrix.md` | `9f15446d75c4e51b490a82849297863cd009f4c9eacee04793e3e3344c617c08` |
| `fixtures/conformance/native-provenance-routing.json` | `c25be87e3598edeb03fa7363a65c24ffa0b8da589eb47542fb193d01e2e0de88` |
| `scripts/check-http-api-schema.py` | `1c3a9cd4226fe2adfc6ad9abc745bb1f24edc55902ef50fb490663bb850b1627` |
| `crates/trellis-conformance/Cargo.toml` | `e3313426135c4cb4e6184cd864c43db18b71d250c33467d8a90d2448b6203476` |
| `crates/trellis-conformance/src/lib.rs` | `5e47d7ed6784d34d68f5ed30c7c1e630a9fef2a9a1436984d57cbf574e683877` |
| `crates/trellis-conformance/src/native_http_schema.rs` | `9b91c0eb0480b6c2d3bad0c2d30a063e0c25398770e2ac9cebb3a4d3173c424f` |

### Retained stage evidence

All log hashes independently match their receipt; paths are snapshot `execution/<stage>.log`.

| Stage | Outcome | Log SHA-256 |
| --- | --- | --- |
| `core-lib-1` | failed; exit 101 | `b4e4a2e5e033601c806238e9ced5f716e7189580d74a9f8358a2c20fb6c184ed` |
| `core-lib-2` | passed; exit 0 | `0094256b52932a9b80adfcf5d9b6d0b98550e28d1af5837b5e2c86567251d6d6` |
| `trellis-adapter-1` | failed; exit 101 | `4390885f00d1c07e130537e0fbadef5e417b5ab374795ee9787d254c397e89ad` |
| `trellis-adapter-2` | failed; exit 101 | `5a56b45146c6883d17752c66330ba350c974f744ceab4af4e8cbc624863bc3e3` |
| `trellis-adapter-3` | passed; exit 0 | `4aa2bdd7881c40b1079652465849c3cce748a7a7178d05e12255fd5fdff2979d` |
| `trellis-schema-1` | passed; exit 0 | `75a0e8babfe3a02f2d738dd3398787d99b619b9ec1e21ea39e8a7031773f2cd7` |
| `trellis-openapi-1` | passed; exit 0 | `e0b287018aaa7c20c10b368053fa1412739d9e805101b6a75dc0620c882f9ca7` |
