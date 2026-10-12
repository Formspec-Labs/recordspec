# Trellis18198 operator preparation: static BEFORE architecture review

**VERDICT: RECONSIDER the exact launcher preparation before execution.** Keep strict OIDC, deny-all grants until fresh-case selection, the maintained-provider primary readback path and secondary HTTP instrumentation. Freeze the private database/key selection and use explicit fail-closed checks rather than Python assertions. No script, native command, provider/network/DB operation or service launch was performed or approved by this review.

Reviewer `/root/oidc_arch_review`, independent non-author, October9,2026. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied. Read-only JSON/script/digest inspection; only this certificate written. Retained source architecture and private qualification certificate `trellis-oidc-startup-after-architecture-review-v4-final.md` SHA `044defca2eddc02f905eaad834cdee112bcf0fb2e0d566e47a7d7fe3b50d030c` remains unchanged.

## 1. Artifact summary

`trellis-18198-static-operator-preparation-v2.json` SHA `a19c9989e726368ed06a120e2b238dcaeded7e8ab93189d4b004ef0cd0aed48b`. Private directory `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`. Category: operator preparation and deployment qualification scaffolding. Intended action is future Root-authorized startup of the retained qualified CLI at127.0.0.1:18198 against an existing new isolated database on18185, with unchanged selected COSE key and strict current identity/resource authority.

Profile SHA `c8de0c4bfba003b93c2ef28a937a3e8bef1f21c3d12f26685af7a294c196e057`; grants SHA `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0`; launcher SHA `2bb14db80ce183174c775d8675c448c7e94d949b7f38087ca140cccd65a5a18b`; readback SHA `cc1339fb7564d62b00ca4d18f56f3116fa7e5f41d621dff2ac06fd55777a2c0d`. All independently match the packet. Profile/grants mode0600; scripts0700. Root-selected empty grants remain deny-all. Existing456 history is not reused or retagged as the fresh0.3.1cohort.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| Qualified strict startup | Supplies actual retained binary and current authority semantics | finalv4 certificate:§1,§3; packet binary SHA `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |
| Fixed-deployment BEFORE | Requires permanently dedicated DB/profile quad | `trellis-oidc-startup-before-architecture-review-v2.md:§3.1` |
| Root goal/philosophy | Independent evidence and explicit durable ownership | `GOAL.md:Target Deployment Profile, Governing Data-System Rule`; `DEVELOPMENT-PHILOSOPHY.md:Evidence and responsibility discipline` |
| Current authorization | Read versus publication/administer semantics | maintained `trellis-server/src/auth.rs:authorize_action,authorize_publication`; `http.rs:signing_key_registry,head_bundle` |
| Prepared scripts | Compose existing server / instrument read-only HTTP | private `start-trellis-reviewed-v4.py:main`; `readback-trellis-reviewed-v4.py:main,get` |

| Seam | Owner | Input / output | Limit |
| --- | --- | --- | --- |
| Operator launch | Root/Trellis operator | Frozen configuration → actual qualified binary | Future explicit execution selection |
| Current provider → Trellis client | Common/WOS composition | Maintained service token → exactcase registry200 | Pending owning caller probe |
| Secondary HTTP readback | Trellis operator instrumentation | Provider token onstdin → statuses/raw030digest | No OAuth implementation, not primary provider proof |
| Exact new-case grant | Root/application policy | Fresh0.3.1case/actors → explicit read+append rows | No automatic grant registration |
| Export publication | Separately authorized exporter | Read+administer authority → head publication | Current caller lacks administer |

## 3. Invariants and commitments

- **Strict current authority — PRESERVED in prepared profile.** Explicit Keycloak profile, API audience/base scope/client, actual external subject→stable principal and one fixed tenant quad. Loopback HTTP is explicitly selected for development. Source identity facts are operator-selected inputs; their live validity is not verified here.
- **Deny-all until fresh case — PRESERVED.** Current grant file repeats exact quad and contains zero rows. Launcher requires explicit allow-deny-all selection. A generic403 after token presentation establishes refusal, not positive admitted case access. Root's future exact grant/profile freeze remains required.
- **Exact deployment/key selection — RELIED-UPON but incomplete in launcher.** Launcher checks binary/profile/grant hashes but reads unpinned `database.private.json`; only its bind is compared before taking databaseUrl and signingKeyCosePath into the child environment. The plan's existing isolated DB/retained key commitment is therefore not enforced by its frozen execution path. Current read-only inspection finds the expected host127.0.0.1:18185 and selected key path, but current correctness is not a frozen-input check.
- **Unconditional preflight checks — BROKEN under Python optimization.** Hash, bind, tuple and deny-all checks are Python assert statements; `python -O` removes them. Explicit exceptions are the smaller reliable check. This is a concrete alternate invocation, not an observed execution failure.
- **Maintained migrations only — PRESERVED in intended path.** Launcher execs the actual reviewed server using a narrow environment, no migration replacement or Python OAuth. Server startup applies maintained migrations to the selected DB. That is a write/launch step awaiting Root authority, not a read-only script operation.
- **Least authority / publication — PRESERVED.** Current caller has read+append without administer. Registry readback is suitable; head publication remains unauthorized. Plan explicitly requires a separately authorized exporter/config/grant if publication is needed. No implicit scope elevation follows this review.
- **Proof and retention limits — PRESERVED.** Readback refuses redirects, bounds replies, accepts token only onstdin and stores no token. It requires unauthenticated401, invalid401, foreign403, selected200 and exact raw030digest; non200 does not count as positive. This script is secondary HTTP instrumentation; maintained provider/client positive path remains separately required. Default in-memory export artifact storage is disclosed separately from Postgres event durability.

## 4. User value and simplicity

A tiny environment/exec launcher and read-only registry instrument reuse the qualified binary and maintained auth/client path. Empty grants permit Root to stage a fresh service without granting historical cases. No new provider protocol or policy API is added. The missing input freeze can be corrected with a private-config digest plus selected key path/content digest, without printing credentials or changing storage/auth architecture. No speed/resource claim is measured.

## 5. Counterfactual analysis

Kill criterion: mutable private config points to another DB/key, optimization bypasses safety checks, generic403 is called admitted current-token proof, or read+append becomes implicit publication authority. Removing launcher leaves manual environment preparation with greater mismatch risk. Shared maintained server/provider subsume auth and migrations; secondary Python remains instrumentation only. Six-month critic: operator preparation could be cited as actual startup/readback or durable artifact retention. Packet correctly excludes those claims; retain exclusions.

## 6. Findings

**F1 — BLOCKER; commitment-violation; RESHAPE.** Freeze `database.private.json` using an expected digest checked before exec; compare selected retained key path and raw key digest with the operator receipt. Do not print DB credentials or key bytes. Read-only current private config digest is `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983`; selected key raw digest `62644accd6ef7af276945418ee794ce6428ac63a0a79f78180addd372b053608`. Root must confirm/freeze those exact private inputs in the successor packet. This is preflight binding, not a claimed no-swap guarantee.

**F2 — CONCERN; intent-vs-shape; RESHAPE.** Replace execution/readback safety asserts with explicit validation exceptions. Pin and authority checks must survive optimized Python. Preserve dry default and explicit --execute; never execute during this review.

**F3 — OBSERVATION; named-seam; KEEP.** Maintain primary Common provider→TrellisServiceClient exactcase200/raw030proof; keep secondary script clearly separate. Continue deny-all until fresh case/grant freeze, and keep absent administer/ephemeral artifact limits visible.

**F4 — OBSERVATION; scope; DEFER.** Actual launcher/provider/DB/service readback, new case selection/authority and export publication remain outside this static gate. Owner commit e9f5af9 is parent-supplied handoff lineage; actual binary qualification used its separately recorded worktree closure, including explicitly separate inherited typeid edge. No new build or commit-to-binary identity is inferred here.

## 7. Verdict

**RECONSIDER exact operator preparation before execution:** bind private DB/key inputs and replace removable assertions, then re-pin. Intent MATCHES bounded startup/qualification; user value SUPPORTED; commitment status DRIFTING at private execution-input binding; debt otherwise PAYS DOWN manual setup; sibling subsumption PARTIAL; confidence HIGH for static script facts, actual operational state unverified.

All six phases applied. H1 every exec-selected private input is pinned REFUTED by database.private.json. H2 asserts enforce pins for every Python invocation REFUTED by optimization semantics. H3 current grants give historical case access REFUTED by empty rows. H4 generic403 proves current admitted caller REFUTED and plan correctly distinguishes positive200. H5 read+append grants publication REFUTED by existing administer boundary. No phase skipped. Next action is bounded script/packet correction followed by renewed static review; no operational action follows this certificate.
