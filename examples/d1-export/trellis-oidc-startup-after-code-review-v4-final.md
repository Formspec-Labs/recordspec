# Trellis OIDC startup — final V4 AFTER qualification review

Review ID: TRELLIS-OIDC-STARTUP-AFTER-V4-FINAL-2026-10-09. Independent nonauthor reviewer `/root/oidc_code_review`.

## Findings and decision

**APPROVE the exact private V4 implementation and bounded native qualification. No unresolved blocking finding.** The previously pending posture, client and server-build checks now have matching retained receipts and successful logs. This closes the implementation qualification gates named by the preceding V4 certificate. Provider configuration, database/service startup, deployment and actual D1 custody/export remain separate prerequisites.

This is an incremental final evidence review under the full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`, applicable ms-rust guidance and previously read repository instructions. The complete eleven-file source, function, data-flow and assertion review remains in `trellis-oidc-startup-after-code-review-v3.md`; the test/lock delta and prior findings remain in `trellis-oidc-startup-after-code-review-v4.md`. Those certificates are preserved and pinned below. Only this new certificate was written. Reviewer executed no Cargo, compiler, metadata, test, provider, database or live-service command.

F1 — RESOLVED, test correctness, `crates/trellis-server/src/oidc_startup_tests.rs:95–115`: the AtomicUsize sequence fixes the observed parallel temporary-directory collision without changing production logic or assertions. The first startup run remains recorded as 10 passing/2 fixture failures; the corrected run passes all 12.

F2 — OBSERVATION, dependency provenance, `Cargo.lock`: independently compared package identities again: 23 added registry versions, zero removed identities, zero replacement of existing versions/sources. Existing dependency arrays change with feature activation and version disambiguation. The separate stack-common-typeid→rand_core0.6.4 edge belongs to the reused qualified638 closure and is incorporated in this final lock; it was absent from the exact `green-original.Cargo.lock`. It is not an OIDC-specific addition or already present in that starting file.

F3 — CLOSED, execution evidence: startup12, CLI3 and auth14 are joined by posture2, client11 and an actual server binary build. Aggregate 42 means these selected groups, not all server/workspace tests. The immutable source packet's earlier “in progress” status is superseded by the final receipt; its source bytes are unchanged.

## Scope, source and call traces

Source root: `/private/tmp/trellis-native-provenance-qualified-v1-20261009/trellis`. Base: `eda346c166a71c7b8df55afd8549247456229277`. The final patch contains twelve pinned files including Cargo.lock. All twelve match the source packet at this readback. Production remains equal to approved V3; V4 adds only the reviewed test namespace fix and qualified lock.

| Entry / function | Source location | Inputs → behavior → output |
|---|---|---|
| StartupAuth::from_env/load/apply | server/src/oidc_startup.rs:37,57,111 | Required profile and private files → maintained OIDC verifier/current authority plus exact grant adapter → injected production auth before signing-key/DB setup. Legacy CLI settings refuse even when empty. |
| CurrentGrants authorization | server/src/oidc_startup.rs:354–427 | Verified issuer/subject/client and deployment tuple/action/body → stable principal, action scope, freshly loaded exact case grant, actor kind+subject and human selectors → exact authorized context or sanitized refusal. |
| Existing outer authorization | server/src/auth.rs:34,87,123 | Original parsed append body and identity → validate returned permit, fresh read+administer for publication, trusted replay partition → handler/cache only after authority. Original body bytes remain replay-hash input. |
| Private-file read | server/src/oidc_startup.rs:431 | Opened no-follow, nonblocking FD → regular-file/owner/private-mode check and bounded read → typed closed config. Non-Unix path fails closed. |
| Current service token | service-client/src/lib.rs:580,597,634,719,758 | Injected maintained provider → current access_token once per operation before HTTP → all five existing operations; provider failure sends no HTTP, no stale fallback. Redirects disabled; Debug redacted. |
| Test fixture allocation | server/src/oidc_startup_tests.rs:95–115,161 | Atomic sequence+pid+time → unique owned directory → unchanged fixtures/assertions and owned cleanup. Relaxed ordering suffices for unique allocation. |

Paths in the table are under `crates/trellis-`. Full caller/callee exploration and source evidence are incorporated from the pinned V3/V4 certificates. Authentication grants do not establish signature/export validity. Fixed deployment tuple and dedicated DB association remain operator responsibilities; this review does not assert multi-host cross-tenant DB isolation.

## Data flow, invariants and test adequacy

The reviewed flow preserves original request bytes, verifies current token authority before replay, binds authorization to the full deployment tuple/resource/action and stable principal, and checks append actors/delegated human fields on every retry. A grant-file read or validation failure refuses access. Head publication requires current Read and Administer for the same principal. Provider token acquisition occurs on every client operation without a client-local token cache. Private-file checks apply to the opened FD, without claiming every parent directory is protected against replacement.

The tests inspect meaningful observable behavior: maintained signed RS256 discovery/JWKS/introspection protocol paths, revoked tokens/grants/delegation on identical cached requests, foreign tenant/resource/actor refusals, required human-field refusals, malformed/duplicate authority data, private-file rejection, actual CLI ordering and individual legacy-setting branches. Client tests observe changed tokens on all five HTTP operations, zero HTTP on provider failure, no stale-token reuse, ambiguous configuration rejection, redaction and redirect refusal. These controlled protocol fixtures are not live Okta/Keycloak integration proof.

## Actual owner execution, independently read back

Reviewer ran no tests. I verified all ten retained log hashes and byte lengths against the final receipt, then read the passing logs and behavioral RED diagnostics. Commands record exact argv/cwd/target, exit code and groupClear=true. Test/build commands are offline, locked and jobs=1 in the reused target; the lock-preparation metadata command is offline and intentionally not locked. This is incremental dev-profile evidence, not a clean release build or performance measurement.

| Stage | Observed result |
|---|---|
| cli-red | Setup package collision; excluded from behavioral RED. |
| cli-red-2 | Two original CLI assertions fail as intended: old parent asks for signing key before OIDC profile. |
| green-lock | Successful graph metadata preparation; retained final lock. |
| oidc-green-1 | 10 pass/2 AlreadyExists fixture failures; preserved, not counted as final success. |
| oidc-green-2 | 12 pass; 104 filtered. |
| cli-green | 3 pass, including exact two prior RED tests and independent legacy-setting branches. |
| auth-regressions | 14 pass; 102 filtered. |
| router-posture | 2 pass; 114 filtered. |
| client-suite | 11 pass; zero doctests. |
| server-build | Exit 0, Finished dev profile; actual saved server binary verified. |

I independently rehashed all 5,739 sibling files in `foreign-source-before.json`: zero mismatches. The foreign manifest hash matches the receipt. The saved binary is 61,776,720 bytes and its SHA matches. Source packet, patch, all twelve current files and both copies of the final receipt match. Every stage records groupClear=true; clean native release/no remaining compiler processes is owner/Root evidence, not an independent process probe performed by this review.

## Exploration and hypothesis updates

- Production changed during the fixture repair: refuted by prior V3→V4 comparison and renewed exact source pins.
- Initial startup failures show a production auth defect: refuted by directory-creation panic locations and unchanged assertions passing after the namespace fix.
- Lock preparation broadly replaces packages: refuted by exact package-identity comparison; feature/dependency-edge changes and the separate baseline edge remain disclosed.
- Partial receipts suffice for final acceptance: previously rejected; now the final aggregate receipt, remaining logs, source guard and saved binary resolve the bounded implementation gates.
- Forty-two passing tests establish deployment/D1 readiness: rejected. Live provider credentials/endpoints, configured grants, dedicated DB association, service startup and fresh actual custody/export evidence are not exercised here.

## Exact evidence pins

| Input | SHA-256 |
|---|---|
| `trellis-oidc-startup-after-code-review-v3.md` | `e711d169f459be5b7acd0993ec46bb9ebab15dcf66072564b2d878f50ac89a88` |
| `trellis-oidc-startup-after-code-review-v4.md` | `ab6668b364fef3e77f17ec7376c0a4f57d32e495079a412e1e6ab3b444ee1079` |
| `trellis-oidc-startup-qualified-v4.json` | `8021af372812eccb144566d36595123f90b42e6e7cfd96692050336cf654f09f` |
| `trellis-oidc-startup-qualified-v4.patch` | `685b85159cbd22fc6af9d86d15b4bde9b055ae827a8c51846bb89c6e0b85c288` |
| `trellis-oidc-startup-native-qualification-v4.json` | `3fd63d1f64fb8c97fbafb5bc5c7b86c05429cfefccb98331659b7f1fc183fc1e` |
| source `crates/trellis-server/Cargo.toml` | `4a3e5e7c0bb6da967925532cf89358281c4ddf5ff7d40f1cf2e556639c9fc7ad` |
| source `crates/trellis-server/OIDC_STARTUP.md` | `77936e19b927f3f91139f6fa14fe2e2ca3781a7aa0f835803052cfe86c9c5eef` |
| source `crates/trellis-server/src/admission.rs` | `8ebfd2d5792a9673096e020d2e5aee61a12519143f0b5e84e71583fb257e60f1` |
| source `crates/trellis-server/src/lib.rs` | `834670571ae2e9e5e383cd04129ebe311e6749fc106d35cad4af88cc3a87c91c` |
| source `crates/trellis-server/src/oidc_startup.rs` | `71dd47b97397db3c413fae946d426a9216fdb875a9d72f083550b910d368ea63` |
| source `crates/trellis-server/src/oidc_startup_tests.rs` | `6334e0b483628f2050b3df639b172d0c9057c6be9ef64e8484e780379653eb60` |
| source `crates/trellis-server/src/state.rs` | `440872a0ddbb9fb7ee663ded420db48fbd79c3516045a9d4f410cbec023e534c` |
| source `crates/trellis-server/tests/oidc_cli_startup.rs` | `f795d5945dd7c161502ddb129a0b2624875c1a8a6ad65a520b14ba34478670ee` |
| source `crates/trellis-service-client/Cargo.toml` | `d25b4d39ec0c051f6bf804c46e498bfe6c45f5a83f4dbee17a1107b1a33e288c` |
| source `crates/trellis-service-client/src/current_token_tests.rs` | `59759695fb7d8d6fb2d7ca5ec434dceaa52eede1d69fe282b7145f8d8d988421` |
| source `crates/trellis-service-client/src/lib.rs` | `13391c903ffc076bb6f23f979c8d87f79c0c1f81ed5bd6040bd6a53e8b09095e` |
| source `Cargo.lock` | `7e813eb1e5bcf408bb8c9f9a1e153748392c6f1415247bbe739a00bc79096e5c` |
| `execution/cli-red.log` | `c1288d42020c14d771045f2f3ac8744c9ada6e7a05b02464dd4b05815a9b2825` |
| `execution/cli-red-2.log` | `6c211e39f95786bbeb117e122ae7e54ae10e7197ae89393a3627add71b91cff9` |
| `execution/green-lock.log` | `4351c1901463bbee84ba4ce837a56c645064c6b078407067d6486371de6363f5` |
| `execution/oidc-green-1.log` | `40f104415f272bf29c7acb26337e4cc1b80aa943731ee8e24fbda78f6bb5d29a` |
| `execution/oidc-green-2.log` | `cefaaeb660ed4daa0ad1e8177a0c5bc64e26c78a63d80629d52cec533760b5f1` |
| `execution/cli-green.log` | `9d1301340d94e32b29cad529ef51a3f25fe7c08c8252030ccdb860a54cdc9935` |
| `execution/auth-regressions.log` | `07458673e408132862eb8eefd54a0e8b79d650adacdff6c72fbdd79ac9267c08` |
| `execution/router-posture.log` | `d0c6745118775d5e999367da83c6907ee9bc6e1e5ffff67ab4864e3e519bee40` |
| `execution/client-suite.log` | `12022bfe6c9d1d732d9cd28d84f3ca76900dddb5c424abda933c84ab1c722f9b` |
| `execution/server-build.log` | `f0788aa36d1c86b6ccdfb7f4042a5574102d82061c046422a2d42e008a1e4710` |
| `execution/foreign-source-before.json` | `de24062bd15892ee6b60239acf853aa79c38e61b65aa9de6a6d9b9a5a1ab4992` |
| `execution/green-original.Cargo.lock` | `21b92c8ec367c1a34319c051e964b547cce86353616c3dbf58be5b1cee4f2ab4` |
| `execution/trellis-server-oidc-qualified-v4` | `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |

## Final assessment

VERDICT: APPROVE exact V4 private implementation and the selected native qualification gates.

Coverage is ADEQUATE for the reviewed startup/current-grant/client implementation and bounded regressions, with HIGH confidence in inspected source/evidence equality and recorded behavior. This accepts the actual owner execution rather than treating test descriptions as execution. Coverage remains INSUFFICIENT for actual provider/deployment/DB/D1 outcomes. No adoption, push, deployment, provider mutation, DB startup or new D1-history claim is authorized or evidenced by this certificate. Earlier reports and failures remain preserved.
