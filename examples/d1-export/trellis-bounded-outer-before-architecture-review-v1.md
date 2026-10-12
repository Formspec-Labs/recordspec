# Bounded outer Trellis operator: BEFORE architecture review

**VERDICT: APPROVE the exact static wrapper for Root-selected recovery and first startup.** The wrapper supplies the total recovery deadline and streamed log limit missing from the earlier operator design, retains the maintained launcher and database helpers, and confines cleanup to its newly created process group. This accepts the design and wiring; it does not establish live recovery, startup, positive authorization, export persistence or restart retrieval.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-09. Applied the complete `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`. Only this certificate written. No prepared script was imported or invoked, including dry-run; no Docker, S3, database, service, compiler, Node or native command ran. Python inspection only read source, parsed AST and calculated digests.

## 1. Artifact summary

Reviewed `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1/run-trellis-bounded-v1.py`, SHA256 `f59c9d2d1b07b3b536d6bae3b31643fdbb08bf16a27fbce5ebf4900a46b35ed0` (234 lines). Category: operations scaffolding and proof infrastructure. Selected qualified private Trellis HEAD is `e9f5af9e7eaa1de3fca38be7018220a604e3d0c6`; original shared Trellis HEAD observed `3d59b235a0b3d12c1596529dc9fb1385284f17df`. This wrapper changes neither source tree.

The decision adds a finite recovery supervisor, bounded first-start checks and a resident service-log supervisor around existing reviewed scripts. `recover-start` selects the successful recovery's retained qualification file and hashes it before passing it to the existing launcher. Dry default verifies static helper pins and returns before operational imports or actions (`wrapper:61–73`). Execution still requires explicit `--execute` and Root's selected live window.

Exact independently verified dependencies:

| Input | SHA256 |
| --- | --- |
| Root `fresh010-operator/qualify_readback.py` | `c94f4d8f71bc4fd654626998789cc11ab5a8fc64a0e69739cd93324d601e4679` |
| Root `full-successor-publication-v1/publish_configured.py` | `fd4ed96ad03927c20e1acd962ab313c232da7bfc590f6418e5f5f7175e8cdaf0` |
| Root `full-successor-publication-v1/adopt_reload_hotfix.py` | `796603c1c87122910b9c82cb44125e421238dd0f1bcd04d3db3ac3360d15e949` |
| Source `source-workflow-031-serve-v5/process_identity_v1.py` | `2143e3f6a0053da79fca6300037e7a095b5c9368c75af9eab1285596f817b9a0` |
| Private `recover-rustfs-reviewed-v1.py` | `3a9e2dc2d544ffccd28b55b7f3bd7736455062b10837b44bf26cea48852dac8f` |
| Private `start-trellis-persistent-reviewed-v6.py` | `98101f0ae2426167679897b264929571a3f0b985a58fb7d48030c076fef1bf54` |
| Private `oidc-profile-exporter-v6.json` | `ad47c7186758c9adfefb9974a863124de48ea3d5cb40259857da594267a8f6f3` |
| Retained qualified Trellis binary, launcher pin | `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |

Root helper paths are under `thoughts/plans/benefits-scenarios/execution/reports/root`; Source process helper is under sibling `reports/formspec-server`. Private inputs remain under the reviewed private demo directory. The v6 launcher differs from v5 only in selected profile filename/hash. The profile differs from its preserved predecessor only by one allowed client and one exact issuer/subject/client→`trellis-local-exporter` identity. It adds no grants; identity recognition is not case authorization.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| `GOAL.md` | Evidence must survive the live server; deployment outcome drives this work | `GOAL.md:28,40,166` |
| `DEVELOPMENT-PHILOSOPHY.md` | Buyer proof remains distinct from engineering proof | `DEVELOPMENT-PHILOSOPHY.md:384–388` |
| Recovery/persistent BEFORE | Parent design; its optional external deadline becomes enforced supervision | `trellis-rustfs-recovery-before-architecture-review-v1.md:§3, F3` |
| Corrected operator preparation | Exact selected new database, key/profile and grant freeze | `trellis-18198-static-operator-after-architecture-review-v2.md:§3` |
| Qualified OIDC binary | Retained implementation qualification, not this deployment's proof | `trellis-oidc-startup-after-architecture-review-v4-final.md:§1,§7` |

| Component / seam | Owner | Depends on | Consumer / limit |
| --- | --- | --- | --- |
| Bounded child execution | Root operator | Pinned finite `supervise:59–111` | Recovery300s / combined32MiB; owns only created group |
| First-start preparation | Trellis operator | Reviewed v6 launcher / positive SDK receipt | Exact selected binary, DB, key, OIDC profile, grants, S3 inputs |
| Process identity | Root/Source helper | Bounded macOS KERN_PROCARGS2 reader | Wrapper compares actual argv/environment; auxiliary data separate |
| Database snapshot | Existing Root helper | Read-only repeatable-read PostgreSQL transaction | New selected database only; bounded inventory/rows |
| Readiness | Maintained Trellis/Common | Repository list + artifact put/get | Selected new bucket health key; no archive proof |
| Future case/export admission | WOS and separate exporter | Current identity plus exact case/action grants | Empty current grants remain; successor integration required |

These are named operator/helper seams, not new platform interfaces. Root retains authority over selected container state and execution. Process-reader independent paired review remains Root-owned; this review checks its source and wrapper wiring without claiming its live execution qualification.

## 3. Invariants and commitments

**I1 — Selected resource preservation: PRESERVED in source.** Recovery uses the previously reviewed exact-container script. Startup checks old18088 PID16414, actual argv/environment, binary and referenced configuration digests before and after; new18198 must be absent before launch (`wrapper:142–153,193–196`). No command stops the old service, Docker or RustFS, restores the database, deletes keys or removes evidence. Old in-memory application rows are explicitly not compared (`:196`). Failure preserves partial new DB/storage state (`:204–225`). PID reuse/process drift rejects the run rather than granting broader authority.

**I2 — Owned cleanup: PRESERVED.** SIGINT/SIGTERM handlers are installed before either operational branch, ignore repeated stops and raise so finite cleanup can run (`:74–81`). Service child starts a new session; failure kills only that child's group, waits/polls boundedly, and records `ownedGroupEmpty` including cleanup failure (`:155–158,204–225`). Recovery finite helper always cleans its own group in `finally`. SIGKILL of the supervisor itself cannot be handled; no such guarantee is claimed.

**I3 — Honest bounds: NEWLY INTRODUCED / PRESERVED.** Recovery uses monotonic300s and combined32MiB streamed output; its success requires no truncation/error and empty group (`:86–100`). Startup uses180s absolute alarm plus monotonic `operation_end`; readiness retries cannot consume the whole-operation timeout silently (`:141,165–180,195`). Preflight has20s/1MiB; readiness30s and64KiB response bound. Resident service output is32MiB streamed; one excess byte fails and cleans up (`:129–139,200–225`). Resident lifetime is intentionally indefinite. This is a stream-size and operation-deadline claim, not a universal memory or all-receipt size cap. Filesystem/OS delays and bounded cleanup may extend elapsed wall time beyond the named operation deadline.

**I4 — Exact configuration/current authority: PRESERVED.** Target DSN is checked before read-only snapshot; existing launcher validates selected bind/key/profile/grants/positive receipt. Input hashes are checked before/after launch, actual binary and full actual environment compared exactly (`:114–122,148–153,182–187`). `capture_process` ends the real environment at its terminator, rejects duplicate keys and separates later Apple auxiliary fields (`process_identity_v1.py:12–57`); the wrapper uses it for every process comparison (`wrapper:105–110`). No environment-key exclusion masks a real configured variable. The static exporter identity addition grants no resource action; empty grants need explicit deny-all selection.

**I5 — Readiness scope/trust: PRESERVED with disclosure.** Maintained `trellis-server/src/state.rs:519–543` lists repository scope `__healthz__` and puts/gets static `trellis-health-probe` at `__healthz__/artifact-roundtrip`. Thus `/readyz` causes a retained write/read under selected new bucket prefix `trellis`; wrapper records this (`:172–176`). Root's selected startup/readiness authority reasonably includes this maintained health operation. It does not touch an application event or publication row. It exercises the configured S3 adapter roundtrip, not immutable export publication, current bearer admission or restart retrieval.

**I6 — First-start data boundary: PRESERVED.** Before snapshot must contain no public tables; after inventory must equal three maintained Trellis tables, migration versions1–4, zero event/publication rows (`:146–147,188–192`). Existing helper `publish_configured.py:258–294` uses read-only repeatable-read bounded snapshots. Maintained migrations declare these tables/versions. This wrapper is deliberately first-start preparation; it is not the eventual restart operator, which must accept retained application state without losing evidence.

## 4. User-value analysis

Root receives one reviewable command path for selected recovery→pinned receipt→first startup, with privately retained evidence and a resident log bound. This reduces manual handoff errors and reuses maintained scripts instead of adding storage, OAuth or migration implementations. The conceptual cost is one small operational coordinator with explicit owner and finite first-start scope. No measured performance/resource improvement is claimed beyond the implemented output-size limits.

A bare launcher would leave recovery elapsed time, service log growth and old-service preservation unchecked. A general supervisor framework would add configuration and lifecycle seams without improving this selected first-start proof. Six months later, a missing retained recovery/startup receipt or a claim of durable export based only on `/readyz` would refute the intended value.

## 5. Counterfactual analysis

Kill criterion: helper/input pin mismatch, another listener, old process/config drift, nonempty starting DB, false migration inventory, bad readiness bytes/status, output overflow, or failed owned-group cleanup. Opposite decision runs scripts separately without bounded evidence handoff; removal first breaks Root's enforceable recovery/output bounds. Existing finite helper subsumes child supervision; existing launcher subsumes deployment configuration; the wrapper reuses both. The most likely future criticism is mistaking first-start snapshots and provider health for archive/restart proof. Keep the explicit result limitations and retain a separate restart qualification path.

## 6. Findings

**F1 — KEEP; OBSERVATION; ownership/simplicity.** Reuse pinned finite supervisor, launcher, read-only database helper and shared process reader. The wrapper introduces no new OAuth, S3 signing, database migration or consumer-specific policy implementation. Exact selected resources and private receipts support the authorized scope.

**F2 — RESHAPE completed; OBSERVATION; intent-vs-shape/bounds.** Earlier source installed stop handlers only for startup and caught the absolute alarm as an ordinary readiness timeout. Current exact digest installs handlers before recovery and checks monotonic operation deadline in the catch and before publishing success (`:74–81,180,195`). These corrections remove the concrete detached-child and silent-deadline risks identified during this review.

**F3 — RESHAPE completed; OBSERVATION; named-seam/trust.** Earlier process comparison merged or excluded Apple auxiliary names. Current source pins and reuses `process_identity_v1.py`, compares only exact real argv/environment, and retains auxiliary diagnostics separately (`:105–110,185,197`). Independent helper qualification remains Root's responsibility; this is source-level wiring acceptance.

**F4 — KEEP; OBSERVATION; scope.** The v6 exporter identity/profile selection and recover-start receipt handoff remain narrow: one identity addition, no grants, no fallback profile, no changed provider semantics. Retain preserved v5/profile and selected empty grants until Root supplies the fresh exact case and separate exporter actions.

**F5 — DEFER; OBSERVATION; evidence.** Execute the authorized selected recovery/first-start path and inspect all actual receipts, group cleanup, before/after identity and database results. Separately qualify maintained current-token provider→Trellis client exact-case admission, actual acknowledged export→restart→same checkpoint bytes, conflict refusal and owning offline ZIP verification. SDK412 evidence and health put/get cannot substitute for those gates. No REVERSE finding is warranted.

## 7. Verdict and limitations

**APPROVE static BEFORE shape and exact wiring.** Intent versus shape MATCHES; user-value SUPPORTED; commitments HONORED in source; conceptual debt PAYS DOWN manual operator duplication; sibling subsumption PARTIAL and reused; confidence HIGH for static paths/digests, MEDIUM for OS/provider/runtime behavior until actual retained execution evidence.

All six phases applied. H1 existing script reuse supplies a whole-operation bound was REFINED: wrapper adds finite recovery and monotonic startup checks. H2 new service cleanup can affect old resources was REFUTED by newly owned group selection. H3 readiness is read-only was REFUTED by maintained health put/get and disclosed retained key. H4 exporter identity implies grants was REFUTED by unchanged grant authority. H5 helper argv/env conflation can be hidden safely was REFUTED; current distinct process-reader seam preserves exact comparison. No phase skipped.

Static AST parsing establishes syntax only. This certificate neither runs nor authorizes live operations independently of Root. It establishes no actual container liveness, credential validity, unchanged historical rows, durable export, restart retention, agency trust or full D1 qualification. Any wrapper/helper/profile change requires a new digest-bound review.
