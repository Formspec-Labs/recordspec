# Trellis OIDC startup: bounded v4 AFTER architecture delta review

**VERDICT: APPROVE the v4 delta for continued qualification.** Production source is identical to approved v3. The sole test-source correction makes parallel temporary-directory names unique; the lockfile resolves maintained OIDC features without replacing or removing existing package versions. Retained evidence now supports intended CLI RED2→GREEN3 and OIDC startup12PASS after the preserved fixture-collision failure. Authentication14, posture2, client suite and build remain pending in this certificate; actual provider/DB/service operations remain unqualified.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` and `/Users/mikewolfd/.agents/skills/ms-rust/SKILL.md` applied. This bounded successor inherits the seven-section architecture/source analysis of `trellis-oidc-startup-after-architecture-review-v3.md`, SHA `3eb9b02fac908ee7f217813b976a25dbf2f64038354bd4d95259583c8a6a9d0d`. Only this certificate written; read-only digest/source/log analysis; no reviewer Cargo/compiler/metadata/provider/DB/live calls.

## 1. Artifact summary

Packet `trellis-oidc-startup-qualified-v4.json` SHA `8021af372812eccb144566d36595123f90b42e6e7cfd96692050336cf654f09f`; patch SHA `685b85159cbd22fc6af9d86d15b4bde9b055ae827a8c51846bb89c6e0b85c288`. Private source `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`, base `eda346c166a71c7b8df55afd8549247456229277`. All12 final packet hashes match independently. Relative to v3, only `oidc_startup_tests.rs` and newly pinned Cargo.lock differ. Category: qualification infrastructure and dependency closure; no new product policy.

## 2. Lineage and relationships

| Artifact | Relation | Evidence |
| --- | --- | --- |
| BEFORE v2 and static AFTER v3 | Unchanged production architecture | `trellis-oidc-startup-before-architecture-review-v2.md:§3`; inherited v3 certificate |
| Maintained shared auth | Owns optional OIDC protocol dependencies | `stack-common-auth/Cargo.toml:features.oidc`; `oidc_startup.rs:71–99` |
| Parallel fixture failure | Explains bounded test correction | `execution/oidc-green-1.log:116–141` |
| Final selected qualification | Supports corrected fixture and CLI behavior | `execution/{oidc-green-2,cli-green}.json/.log` |

| Seam | Owner | Dependents | Status |
| --- | --- | --- | --- |
| Current identity/grants/actor authorization | Existing shared auth + Trellis host | Actual CLI/router | Production unchanged |
| Fixture directory lifecycle | Trellis tests | Twelve startup tests | Atomic sequence added |
| Dependency closure | Cargo lock / maintained manifests | Existing native qualification |23 versions added, no replacement |
| Current service provider | WOS composition + maintained provider | Shared Trellis client | Production unchanged; suite pending |

## 3. Invariants and commitments

- **Production scope — PRESERVED.** All previously pinned production/doc/manifest files remain byte-identical to v3. Existing strict current-authority composition, one-deployment grants, pre-replay checks, pointer delegation and outbound per-call provider design retain the inherited source traces and limits.
- **Independent test fixtures — RESTORED.** Exact comparison against the immutable v3 added-file patch shows only static `NEXT_FIXTURE: AtomicUsize` plus fetch_add(Relaxed) appended to PID/timestamp directory names (`oidc_startup_tests.rs:95,104–113`). Relaxed ordering is sufficient for distinct counter values; no inter-test data ordering is required. No assertions are weakened, grant behavior changed or test serialized to hide a production race.
- **Dependency stability — PRESERVED at version level.** Independent TOML comparison of retained `green-original.Cargo.lock` and current lock confirms23 additional package versions, zero removed/replaced versions. Existing dependency lists do change: most changes disambiguate duplicate names; normalized additions include shared OIDC dependencies, client→auth, server→rustix and upstream feature edges for chrono/crypto/serde/url. Therefore “no existing version changes” must not be phrased as “no existing dependency changes.” No resolver/compiler claim is inferred solely from this comparison.
- **Separate baseline edge — RELIED-UPON.** The reused qualified638 closure includes stack-common-typeid→rand_core0.6.4. Lock analysis explicitly separates that baseline edge; it is not justified as an OIDC feature requirement. This review does not authorize unrelated shared lock adoption.
- **Evidence honesty — PRESERVED.** The first startup attempt had10PASS/2FAIL from directory creation collisions, not asserted authorization failures; it remains retained. Actual parent CLI RED fails two intended behavior assertions because it reports missing signing key before missing OIDC profile. Corrected CLI GREEN exercises all three tests, including each legacy setting branch. No fresh provider/DB/readback claim follows fixture protocol execution.

## 4. User value and simplicity

A unique fixture sequence fixes observed parallel filesystem collisions without altering product behavior, adding synchronization to production or weakening tests. The lock addition enables the maintained OIDC feature path rather than a duplicate implementation. No speed or memory improvement is measured. Per-request authority design and bounded manual existing-case grant remain unchanged; automatic case→grant registration stays out of scope.

## 5. Counterfactuals

Kill criterion: a production file changes, an assertion disappears, new dependency versions replace existing ones without explanation, or later full qualification fails. Removing the sequence restores an observed collision; serializing tests would mask shared fixture identity rather than correct it. Existing AtomicUsize subsumes uniqueness within the process without a new dependency. Six-month critic: partial native PASS may be relabeled final qualification. Keep pending stages explicit and bind the final receipt separately.

## 6. Findings

**F1 — KEEP; OBSERVATION; scope.** Fixture-only sequence is the smallest correct correction; exact production equality supports retaining prior architecture approval.

**F2 — KEEP; OBSERVATION; conformance.** CLI intended RED2→GREEN3 and corrected OIDC12PASS are supported by retained argv/results and checked logs. Keep initial collision evidence; do not call it first-run PASS.

**F3 — DEFER; OBSERVATION; qualification.** Authentication14, posture2, complete client suite and actual executable build need final receipts. Current-provider/database startup and actual deployment grants remain separately authorized cohort work. Source-derived service+human delegation is not legal signing or independent agency trust.

No RESHAPE or REVERSE architectural correction arises from this v4 delta.

## 7. Verdict and exact evidence

**APPROVE bounded v4 continuation.** Intent MATCHES fixture isolation/maintained closure; user value SUPPORTED as reliable qualification; commitments HONORED; debt NEUTRAL in product and PAYS DOWN test nondeterminism; sibling subsumption PARTIAL; confidence HIGH for exact delta and retained partial outcomes. Final acceptance waits final native receipt and outstanding checks. All six phases applied; no phase skipped. H1 production changed REFUTED by pins. H2 failing fixture demanded policy relaxation REFUTED by exact atomic-only delta. H3 all qualification is complete REFUTED by current packet status. H4 versions were replaced REFUTED by independent lock parsing; dependency edges did change.

Retained logs/receipts live in `/private/tmp/trellis-native-provenance-qualified-v1-20261009/execution`. Owner receipts show offline locked -j1 commands, reused target, exit101 for intended RED and initial collision, exit0 for corrected startup and CLI; recorded process groups clear. Historical cleanup is receipt evidence, not reviewer-run process observation.

| Artifact | SHA-256 |
| --- | --- |
| `execution/cli-red-2.json` | `a2477c08bb813355703ac0a75614585aa2792632158578f589369ce7fbf3591b` |
| `execution/cli-red-2.log` | `6c211e39f95786bbeb117e122ae7e54ae10e7197ae89393a3627add71b91cff9` |
| `execution/oidc-green-1.json` | `1a5c2ca598d18ef3fc4946c0b8232861ac1a9a65dddbe91a7a40f4b5be22bb1b` |
| `execution/oidc-green-1.log` | `40f104415f272bf29c7acb26337e4cc1b80aa943731ee8e24fbda78f6bb5d29a` |
| `execution/oidc-green-2.json` | `7fa41717514c9a272ac5c371ab19a3b71b46106c0258924baf962dad9a69453b` |
| `execution/oidc-green-2.log` | `cefaaeb660ed4daa0ad1e8177a0c5bc64e26c78a63d80629d52cec533760b5f1` |
| `execution/cli-green.json` | `d113e975e8ca2109f7b5c88317ef5efeace78c28e500cc77c36bec2423680893` |
| `execution/cli-green.log` | `9d1301340d94e32b29cad529ef51a3f25fe7c08c8252030ccdb860a54cdc9935` |
| `execution/lock-change-analysis.json` | `84c63a6341fcc193326f9cc394654046ba33dc2dca719251b33e623e1ec776e4` |

### Exact source pins

| Private source path | SHA-256 |
| --- | --- |
| `crates/trellis-server/Cargo.toml` | `4a3e5e7c0bb6da967925532cf89358281c4ddf5ff7d40f1cf2e556639c9fc7ad` |
| `crates/trellis-server/OIDC_STARTUP.md` | `77936e19b927f3f91139f6fa14fe2e2ca3781a7aa0f835803052cfe86c9c5eef` |
| `crates/trellis-server/src/admission.rs` | `8ebfd2d5792a9673096e020d2e5aee61a12519143f0b5e84e71583fb257e60f1` |
| `crates/trellis-server/src/lib.rs` | `834670571ae2e9e5e383cd04129ebe311e6749fc106d35cad4af88cc3a87c91c` |
| `crates/trellis-server/src/oidc_startup.rs` | `71dd47b97397db3c413fae946d426a9216fdb875a9d72f083550b910d368ea63` |
| `crates/trellis-server/src/oidc_startup_tests.rs` | `6334e0b483628f2050b3df639b172d0c9057c6be9ef64e8484e780379653eb60` |
| `crates/trellis-server/src/state.rs` | `440872a0ddbb9fb7ee663ded420db48fbd79c3516045a9d4f410cbec023e534c` |
| `crates/trellis-server/tests/oidc_cli_startup.rs` | `f795d5945dd7c161502ddb129a0b2624875c1a8a6ad65a520b14ba34478670ee` |
| `crates/trellis-service-client/Cargo.toml` | `d25b4d39ec0c051f6bf804c46e498bfe6c45f5a83f4dbee17a1107b1a33e288c` |
| `crates/trellis-service-client/src/current_token_tests.rs` | `59759695fb7d8d6fb2d7ca5ec434dceaa52eede1d69fe282b7145f8d8d988421` |
| `crates/trellis-service-client/src/lib.rs` | `13391c903ffc076bb6f23f979c8d87f79c0c1f81ed5bd6040bd6a53e8b09095e` |
| `Cargo.lock` | `7e813eb1e5bcf408bb8c9f9a1e153748392c6f1415247bbe739a00bc79096e5c` |
