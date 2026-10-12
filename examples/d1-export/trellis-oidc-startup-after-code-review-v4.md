# Trellis OIDC startup — V4 bounded AFTER delta and partial result review

Review ID: TRELLIS-OIDC-STARTUP-AFTER-V4-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Incremental application of full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` and applicable ms-rust/repository guidance, retaining the full eleven-file V3 certificate. Only this certificate written. Reviewer ran no Cargo/compiler/metadata/test/native/provider/database/live commands and changed no source or lock. Qualification owner holds the native window.

## Findings

**APPROVE exact V4 source/test/lock delta; final implementation and host qualification remain pending.** No blocking regression found. This approves the bounded delta and inspected partial receipts, not completion of the still-running qualification.

F1 — RESOLVED / test correctness / crates/trellis-server/src/oidc_startup_tests.rs:95–115. Parallel tests collided because timestamp resolution produced identical process/time directory names. V4 adds a process-local atomic sequence to each name. oidc-green-1.log records two AlreadyExists failures at directory creation, with ten other tests passing. The unchanged assertions rerun as twelve PASS. The fix does not relax production auth or test assertions.

F2 — OBSERVATION / provenance / Cargo.lock and execution/green-original.Cargo.lock. Final lock adds23 registry package identities, no removals and no existing version/source replacement. Existing dependency arrays change due to OIDC feature activation, Unix rustix dependency, client auth edge, transitive feature activation and version disambiguation. The stack-common-typeid→rand_core0.6.4 edge is separately present in the qualified638 closure; it is absent from green-original.Cargo.lock and incorporated here. It must not be labeled already present in that exact starting file or an OIDC-specific dependency. No blocker in this explicit qualification closure; adopting unrelated sibling changes remains separately scoped.

F3 — OBSERVATION / test coverage. Actual startup12 and CLI3 pass; auth14 PASS is also now present in inspected retained output. Posture2, full client suite and final binary/build completion were not yet accepted at this certificate freeze. Final source guard, execution binaries, cleanup/release and aggregate qualification receipt are still needed for final AFTER acceptance. Provider/database/service startup remains outside this native window.

## Patch summary and function trace

Private source root is `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`, baseline eda346c166a71c7b8df55afd8549247456229277. All eleven V3 source hashes except oidc_startup_tests.rs remain identical; Cargo.lock is the twelfth pinned file. The preceding full V3 certificate (`e711d169f459be5b7acd0993ec46bb9ebab15dcf66072564b2d878f50ac89a88`) remains the complete startup/current-grant/client source trace and assertion review. This certificate changes only the bounded delta/result disposition.

| Function / seam | File:line | Inputs → outputs and verified behavior |
|---|---|---|
| Files::new | crates/trellis-server/src/oidc_startup_tests.rs:103 | Time+pid+NEXT_FIXTURE.fetch_add(Relaxed) → distinct temp path per in-process fixture, then existing file creation. Relaxed ordering suffices for unique counter allocation; no shared authority state relies on ordering. |
| NEXT_FIXTURE | same:95 | Test-only AtomicUsize initialized once; each fixture advances before create_dir. Sequence exists only in cfg(test) included module. |
| Files::load/app | same:147,156 | Unchanged profile/grant fixtures feed maintained StartupAuth::load and router; collision fix cannot bypass auth, rewrite requests or alter verdict assertions. |
| Files::drop | same:161 | Removes only this fixture's unique owned directory. No shared temp-directory cleanup introduced. |
| StartupAuth/current grant/client methods | oidc_startup.rs:37–115,354–427; service-client/src/lib.rs:580–628 | Hash-equal V3 production source. Required OIDC before key/DB, exact fresh grants before replay, per-request current token, no redirects/fallback remain intact. |

## Data flow and invariants

The sequence value is created by atomic fetch_add, used only in the owned path, and never escapes into production credentials/grants/HTTP or persisted data. Timestamp+pid remain part of name; counter prevents equal-resolution concurrent timestamps from sharing a directory. Atomic uniqueness is the only required property, so memory ordering does not synchronize unrelated test state. Integer exhaustion is not a plausible native test scenario. Files still clean up their own paths.

Lock additions resolve the already approved maintained OIDC feature and client port; no alternate auth framework or version replacement is introduced. Final lock hash binds the exact graph being exercised. Provider/client/protocol semantics remain owned by the existing source reviewed in V3, not inferred from new lock package names.

## Tests inspected versus executed

Reviewer executed none. Retained owner commands are --offline --locked -j1 using the existing target directory. I read stage receipts/logs, not only parent summaries:

- cli-red-2: actual parent CLI tests both FAIL as intended, observing old key-first startup instead of required-profile refusal; retained setup attempts are not counted as behavioral RED.
- oidc-green-1:10 PASS/2 failures at create_dir AlreadyExists. No production or auth assertion failed on those two paths before the collision.
- oidc-green-2:12 PASS,104 filtered. Same maintained signed-RS256/discovery/JWKS/current-grant/actor/delegation/read-publication assertions reviewed in V3.
- cli-green:3 PASS. Includes both original tests and each-legacy-flag/empty-value rejection branch coverage.
- auth-regressions:14 PASS,102 filtered. This is fresh retained result evidence, not a claim that all server tests passed.

Each inspected stage receipt records argv/cwd/target/status/exit code/pid/groupClear=true. This is owner cleanup evidence, not a new independent process observation. Logs have no receipt-provided hash fields; independently calculated hashes below bind the read bytes. Ongoing stages are deliberately excluded. Actual binary fixture and full result/source-release pins require final receipt refresh.

## Exploration record

H1 production changed during native repair. REFUTED: exact V3→V4 hash comparison shows only included test file and lock changed.
H2 two REDs indicate auth behavior defects. REFUTED by retained panic locations and AlreadyExists errors; directory collision happens before those tests' auth assertions. Sequence repair preserves assertions and twelve-test rerun passes.
H3 lock refresh may replace existing versions. REFUTED by independent package-identity comparison:23 adds,0 removals and no existing version replacement. Dependency edges/disambiguations do change and are disclosed, including separate sibling rand_core baseline edge.
H4 partial native receipts establish final qualification. REFUTED: aggregate receipt/binary/sourceguard/release and remaining stages are pending; current approval stays bounded.

## Exact pins

| Input | SHA-256 |
|---|---|
| qualified V4 packet | `8021af372812eccb144566d36595123f90b42e6e7cfd96692050336cf654f09f` |
| qualified V4 patch | `685b85159cbd22fc6af9d86d15b4bde9b055ae827a8c51846bb89c6e0b85c288` |
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
| `execution/green-original.Cargo.lock` | `21b92c8ec367c1a34319c051e964b547cce86353616c3dbf58be5b1cee4f2ab4` |
| `execution/lock-change-analysis.json` | `84c63a6341fcc193326f9cc394654046ba33dc2dca719251b33e623e1ec776e4` |
| `execution/cli-red-2.json` | `a2477c08bb813355703ac0a75614585aa2792632158578f589369ce7fbf3591b` |
| `execution/cli-red-2.log` | `6c211e39f95786bbeb117e122ae7e54ae10e7197ae89393a3627add71b91cff9` |
| `execution/oidc-green-1.json` | `1a5c2ca598d18ef3fc4946c0b8232861ac1a9a65dddbe91a7a40f4b5be22bb1b` |
| `execution/oidc-green-1.log` | `40f104415f272bf29c7acb26337e4cc1b80aa943731ee8e24fbda78f6bb5d29a` |
| `execution/oidc-green-2.json` | `7fa41717514c9a272ac5c371ab19a3b71b46106c0258924baf962dad9a69453b` |
| `execution/oidc-green-2.log` | `cefaaeb660ed4daa0ad1e8177a0c5bc64e26c78a63d80629d52cec533760b5f1` |
| `execution/cli-green.json` | `d113e975e8ca2109f7b5c88317ef5efeace78c28e500cc77c36bec2423680893` |
| `execution/cli-green.log` | `9d1301340d94e32b29cad529ef51a3f25fe7c08c8252030ccdb860a54cdc9935` |
| `execution/auth-regressions.json` | `31737a3ed930090edf27eccbef98b57178341b50a57956bbdb735e6426ec9bff` |
| `execution/auth-regressions.log` | `07458673e408132862eb8eefd54a0e8b79d650adacdff6c72fbdd79ac9267c08` |

## Conclusion

VERDICT: APPROVE bounded V4 source/test/lock delta and inspected partial execution evidence.

Justification:
- Test namespace repair addresses actual parallel collision without changing production or weakening assertions; lock is additive and explicit.
- Coverage of this incremental delta: ADEQUATE. Final native qualification, whole binary/client checks and actual host/provider/DB: INSUFFICIENT / pending.
- Confidence: HIGH for source/pin/delta and retained stage result checks. No final implementation acceptance, adoption, deployment or D1 claim is granted.
