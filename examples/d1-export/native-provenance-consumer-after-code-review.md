# Native provenance consumer — independent AFTER code review

Review ID: TRELLIS-NATIVE-PROVENANCE-CONSUMER-AFTER-2026-10-09. Independent nonauthor: `/root/oidc_code_review`. Full method: `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`; applicable ms-rust review guidance and parent/Trellis instructions retained from the preceding reviews. This certificate supersedes the execution-pending disposition of the v2 static certificate only for the exact consumer source and retained evidence below. Only this certificate was written. Reviewer executed no Cargo, builds, tests, native programs, network or live calls; reviewer performed read-only source, diff, hash and receipt inspection.

## Findings

No blocking finding remains in the qualified consumer delta or its reported test results. **APPROVE the exact consumer source-equivalence/test-delta gate.** This does not approve adoption, deployment, actual D1 evidence, the separate authentication integration, or a full offline-verifier result for the ZIP produced by the native Core window.

F1 — RESOLVED / correctness / qualified `fixtures/conformance/native-provenance-routing.json:6`. The original unqualified `prov_…` identifier failed owning admission validation. The final controlled fixture uses native `default_prov_…` shape. Retained trellis-adapter-1.log:251–265 shows the real admission failure; adapter-3 passes the same preservation test. No production validation was relaxed.

F2 — RESOLVED / test-coverage / qualified `crates/trellis-service-client/src/wos_ext.rs:142–156`. The typed-record helper's expected JSON now comes from the maintained serializer before ownership moves. `wos-events/src/provenance/record.rs:596–618` omits empty inputs/outputs/transitionTags. Retained adapter-2.log:36–41 demonstrates precisely that expected/actual difference. This is a correct test of typed-input preservation; it is not proof of preservation of arbitrary pre-deserialization JSON. The raw-input Core window separately asserts complete JSON equality.

F3 — OBSERVATION / test-coverage / Core `runtime/custody_trellis_router_tests.rs:162–184` versus consumer `native_provenance.rs:10` and `validator.rs:22`. The real router window exports and inspects a ZIP, while the owning verifier tests run separately. The window never calls `verify_export_zip` on that ZIP. Remaining combined export gate: verify the actual full-window ZIP with the owning offline verifier, then require generic payload mutations to fail through that same complete verifier path. Current packet and receipt state this limitation accurately. It does not block this expressly bounded consumer delta approval; it blocks a claim of full exported-bundle verification qualification.

F4 — OBSERVATION / integration / qualified packet adoptionStatus. The portable patch is against ea8f547, whereas separate auth commit `3d59b235a0b3d12c1596529dc9fb1385284f17df` now exists in the maintained checkout. Any eventual adoption must preserve that auth change and qualify the combined closure. This review makes no merge/adoption assertion. Qualification-only dependency path substitutions are not portable source changes.

## Patch summary and exact scope

Qualified Trellis snapshot: `/private/tmp/core-native-provenance-inputs-v1-20261009/trellis`. Preserved comparison candidate: `/Users/mikewolfd/Work/formspec-stack/.trellis-native-provenance-v2`, based on `ea8f547367e4d41d09395001230ccf14705af8c9`. The preceding full static certificate reviewed the sixteen consumer files, including generic client routing, service-only admission, actual composition dispatch and catalog, HTTP/OpenAPI schema, offline check, conformance fixture, checker and normative mapping. The only consumer execution-time changes are the two test/fixture corrections above. All production bytes remain equal to the reviewed v2 preparation.

The conformance manifest also differs between physical candidates because qualification redirects integrity-verify and wos-events to the coherent sibling snapshot. These are explicit setup path changes, not a third execution-time source repair. The portable patch retains maintained relative dependency paths. The exact packet pins the physical manifest that actually compiled. No new writer, duplicate owning schema, consumer-derived record history or business classification was added.

## Function trace

Consumer paths below are relative to the qualified Trellis root; Core paths are relative to its sibling work-spec root. All unchanged functions retain the source inspected in the full v2 review; this review rechecked their hashes and changed tests/result path.

| Function / seam | File:line | Inputs → outputs and verified behavior |
|---|---|---|
| wos_provenance_append_request | crates/trellis-service-client/src/wos_ext.rs:37 | Typed record → canonical route unchanged when mapped; otherwise owning from_record validates and wraps serialized native record under shared generic literal. |
| append_wos_provenance | same:97 | Calls request helper then maintained SubstrateClient.append_event; transports existing append request. |
| native_provenance_client_preserves_original_record | same:137 | Fixture → typed record → expected maintained serialization before move → request; asserts generic event, whole typed JSON equality and original event string. |
| canonical client regression test | same:160 | Every one of28 canonical literals → unchanged literal and exact typed payload. |
| event OpenAPI schema | crates/trellis-service-client/src/lib.rs:93 | Canonical literals plus separate generic constant and Formspec literals → enum. |
| wos_event_type_specs / admit | crates/trellis-admission-wos/src/lib.rs:65,130 | Generic spec + JSON through owning from_json; invalid data refuses, accepted data obtains neutral serviceOnly metadata. Canonical path unchanged. |
| default_admission_policy / catalog | crates/trellis-server/src/composition.rs:214,242 | Registers generic in actual dispatch and catalog independently. Generic route is not merely advertised. |
| OpenAPI parity tests | crates/trellis-server/src/openapi.rs:129,170 | HTTP/OpenAPI event enums compared; owning generic recognized separately from preserved canonical mapping. |
| validate_native_provenance | crates/trellis-verify-wos/src/native_provenance.rs:10 | Generic DomainEvent payload bytes → wrapped strict decoder; absent/invalid bytes → blocking domain Failure with event hash; other events skip this check. |
| WosRecordValidator.validate_events | crates/trellis-verify-wos/src/validator.rs:22 | Composes native check with existing clock/rescission validation. lib.rs:21 registers module. |
| checker parse / check_defs | scripts/check-http-api-schema.py:143,242 | Discovers actual owner constant and canonical macro; checks enum parity and one owning absolute schema reference. |
| offline HTTP schema test | crates/trellis-conformance/src/native_http_schema.rs:8 | Reads actual dependency's owner schema; registers resource, builds validator with formats; valid body accepts and four invalid classes refuse. lib.rs:10 registers test. |
| NativeProvenanceEvent methods | Core crates/wos-events/src/native_provenance.rs:44 onward | Owning from_record/from_json/from_dcbor_slice/from_record_dcbor_slice enforce shared strict subset; consumer does not duplicate decoder or schema. Whole helper acceptance remains separately owned. |
| TrellisCustodyAppender / full-window test | Core crates/wos-runtime/src/runtime/custody_trellis_router_tests.rs:107–204 | Actual runtime records → custody inputs → actual localhost router/client → exported ZIP; verifies complete ordered original JSON and receipt-only mutation, then exact replay/conflict/stamped retry. |
| existing runtime trait test repair | Core crates/wos-runtime/src/runtime.rs:2826–2840 | Expected route follows canonical mapping or shared generic; expected canonical payload removes recordKind only for canonical branch. Test-only adjustment matches new owning route semantics. |

## Data flow and invariants

The preserved28canonical kinds keep their existing route and payload. Only known remaining typed kinds select `wos.provenance.recorded`; unknown/canonical-bypass data refuses in the owning helper. Native JSON stays under one `record` key. Admission validates without rewriting original payload. Core validates original bare custody bytes before its inspection/typed bridge; its bare policy permits only the real root timestamp tag0 Text, while wrapped archive data rejects tags. Recursive duplicate rejection precedes JSON conversion. Signed-i64, finite numbers, negative zero and depth128 remain owning helper limits, covered by its separate tests.

The test's `original` value is created from the typed record before `record` moves into the helper. It never escapes the test except as an equality assertion. This acknowledges the serializer's omission rules rather than changing production records. The fixture changes only id shape; event, data, nested values and empty-list fields remain present for admission/raw-JSON tests.

The actual Core full-window test loads every runtime record and its custody input, checks equal lengths, publishes through the maintained appender/router, reads the events ZIP member and decodes each signed event. It checks sequence, event type, complete generic input JSON and full original typed source JSON in order (`:167–184`). Stored records may differ only by canonicalEventHash stamp (`:188–192`). Exact retry returns original references; changed body produces409; stamped retry emits nothing and bundle bytes stay equal (`:194–204`). This establishes those controlled-window properties, not signature validity under an independent verifier or production host authentication. The test harness uses controlled service composition.

## Test behavior and actual evidence

Reviewer execution: **none**. Retained commands were run by the owning qualification agent under `--offline --locked -j1`. I inspected their logs, exact hash matches, failure causes and assertions. Final named passing count is401:32 events +285 runtime +11 admission +7 client +63 verifier +1 focused HTTP schema +2 focused OpenAPI. This count is selected suites, not the full Trellis server/conformance suite; schema reports10 filtered and OpenAPI88 filtered. Earlier failed attempts remain retained and are not counted as successful qualification.

- Client native preservation (`wos_ext.rs:137`) now passes and still asserts whole expected typed record, generic route and unchanged event. Canonical preservation (`:160`) covers all28 existing literals.
- Admission positive (`admission/lib.rs:344`) asserts neutral family/schema/serviceOnly, exact original wrapper equality and one generic spec. Refusal (`:380`) exercises unknown kind, canonical bypass and missing recordKind. Fixture id correction satisfies existing native identifier rule; no refusal assertion was removed.
- Offline tests (`verify/native_provenance.rs:98–284`) cover original OnEntry/NoticeSent values, unavailable payload blocking verdict, malformed structure, canonical bypass behavior, duplicate nested keys, trailing data, bytes, nontext maps, wrapped tag and depth refusal, and mixed-event failure attribution. These run in the actual63-test verifier suite, separately from the Core exported ZIP.
- HTTP conformance (`conformance/native_http_schema.rs:8–60`) actually compiles the owning registered resource with format validation. Valid native body accepts; unknown/canonical kind, absent kind and extra structural field refuse. This directly exercises the former relative-reference defect.
- Core full-window (`runtime/custody_trellis_router_tests.rs:107`) is listed PASS in core-lib-2.log. It uses runtime-generated OnEntry, TimerCreated, TaskCreated, TaskPresented and StateTransition records; it does not invent D1 business history. Full original window membership/order/stamps/replays are asserted as traced above.
- Actual dispatch regression test in composition.rs:497 was statically inspected but is outside the focused OpenAPI run. The Core real-router full-window test supplies runtime evidence that the generic branch is actually dispatched. No full server test-suite pass is claimed.

Concrete edge risks: typed serde cannot preserve unknown pre-deserialization fields; raw custody validation/equality is a separate producer guarantee. A canonical kind submitted through generic route refuses. Missing native payload yields domain invalidity even when cryptographic checks pass. Registry resolution must accompany the external HTTP schema for offline consumers. The checker assumes the current explicit path dependency and fails visibly if that layout changes. None of these limits is hidden by the fixture repairs.

## Provenance, source guard and cleanup

The initial and final source guards each contain7712 paths. I independently compared both maps: exactly the two consumer test/fixture files plus Core runtime.rs changed, matching all three declared repairs. Every final file hash matches current snapshot bytes; no unexpected addition/removal/drift appears. The Core repair is within an existing test, and the client repair lies under cfg(test). ProductionCodeChangedDuringExecution=false is consistent with this inspected delta.

All seven retained stage log hashes match the qualification receipt; all seven retained executable hashes match the receipt's binaries. These checks read bytes only, without executing them. Stage receipts record command, cwd, target, exit status, process group and groupClear=true, including failed attempts. Cleanup is retained owner evidence, not a new independent process-liveness observation by this reviewer. The runtime fixture server has scoped teardown; no deployment or persistent baseline18088 action occurred in this review.

The lock-reconciliation receipt hash matches `25b96e5ecd984885d4d852aecc80191728e23353b1cf64c7918461285147c5a4`. Core lock changes dependency edges only; Trellis setup adds jsonschema0.46.1/referencing0.46.1/micromap0.3 alongside existing versions, with no package removals. Qualification used the reconciled physical closure; this certificate does not authorize copying its lock wholesale over unrelated maintained work. Authentication's own lock and commit remain separately reviewed.

## Exploration record

H1: qualification may have silently changed production behavior. REFUTED for the source-guard interval:7712-path equality check shows exactly three declared test/fixture repairs; all16 consumer pins match. Manifest path translations are separately visible setup context.

H2: changing expected client JSON could conceal dropped raw fields. REFINED: typed helper expectation correctly follows maintained serde omission; raw-byte preservation requires the distinct Core path. Full-window source assertions compare original values, while independent full-ZIP verification remains pending.

H3:401PASS could imply a full exported ZIP verification. REFUTED by actual call trace: Core exports/decodes the ZIP and the offline suite tests validator separately. Packet's explicit narrower claim is accurate.

H4: failures might have been discarded or counts inflated. REFUTED: failed core-lib-1 and adapter-1/2 logs remain pinned; final401 count sums only successful suites, with filtered counts visible.

## Exact input and result pins

All hashes below were checked against current bytes. Consumer source hashes bind the qualified physical snapshot; the portable patch binds eventual reviewable source preparation against ea8f547.

| Input | SHA-256 |
|---|---|
| qualified consumer packet | `8982b06ef40dbdd2d5e33ce5f1840566224f2d8ea139d326a6f5224bd7066079` |
| portable consumer patch | `da9505aad0693a18e0bc8e77e7f0862e1ed67a9fd98049d568ac030192702957` |
| two-file test delta patch | `d7bbb7dbc3122c94632776096871488b61a45b69a6c0b3ca53ab24dba8a75328` |
| qualification receipt | `bd388601cd21c705ba26cb56646eab533372a432a27c8cb21a52dcbfc23fa2cb` |
| initial source guard | `b9c8211bfc400a5df4e3b7f38e3fec0bab2955bc690fec5072f3727457200918` |
| final source guard | `7fb286f3a537f6b399c1ca82c2cd81e69100c8d8381448ddacd19dd61efb54c3` |
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

| Retained stage log | SHA-256 |
|---|---|
| `core-lib-1.log` | `b4e4a2e5e033601c806238e9ced5f716e7189580d74a9f8358a2c20fb6c184ed` |
| `core-lib-2.log` | `0094256b52932a9b80adfcf5d9b6d0b98550e28d1af5837b5e2c86567251d6d6` |
| `trellis-adapter-1.log` | `4390885f00d1c07e130537e0fbadef5e417b5ab374795ee9787d254c397e89ad` |
| `trellis-adapter-2.log` | `5a56b45146c6883d17752c66330ba350c974f744ceab4af4e8cbc624863bc3e3` |
| `trellis-adapter-3.log` | `4aa2bdd7881c40b1079652465849c3cce748a7a7178d05e12255fd5fdff2979d` |
| `trellis-schema-1.log` | `75a0e8babfe3a02f2d738dd3398787d99b619b9ec1e21ea39e8a7031773f2cd7` |
| `trellis-openapi-1.log` | `e0b287018aaa7c20c10b368053fa1412739d9e805101b6a75dc0620c882f9ca7` |

## Conclusion

VERDICT: APPROVE — exact qualified consumer source-equivalence and test-delta gate only.

Justification:
- Both real consumer test failures were corrected without production relaxation; exact source and retained native result evidence agree.
- Coverage of the requested consumer delta: ADEQUATE. Combined actual full-window ZIP plus owning offline verification/mutation gate, combined auth integration, adoption and full D1: INSUFFICIENT / outside this approval.
- Confidence: HIGH for reviewed source equivalence, assertion meaning and retained evidence identity. Qualification evidence was inspected, not reproduced. No source adoption or live authorization follows from this certificate.
