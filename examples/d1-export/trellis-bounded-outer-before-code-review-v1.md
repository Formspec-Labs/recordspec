# Trellis bounded outer operator — focused static BEFORE review

Review ID: TRELLIS-BOUNDED-OUTER-BEFORE-V1-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Applied full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` to this bounded wrapper and behavior-critical helper calls. Only this certificate written. No script invoked/imported, Docker/S3/DB/service/native/compiler/Node operation. Read-only files, hashes and AST parsing only.

## Findings

**Initial snapshot: REQUEST CHANGES; final corrected snapshot: APPROVE static readiness (see successor review below).** The selected-resource, narrow environment, bounded recovery and startup/readback paths otherwise match their stated static intent.

F1 — RESOLVED in corrected snapshot / correctness / run-trellis-bounded-v1.py:115–118,175–189. SIGINT/SIGTERM handlers raise InterruptedError. On first signal execution enters except BaseException and attempts owned-group kill/reap/receipt. Those same handlers remain active throughout cleanup: a second Ctrl-C/stop raises inside the exception handler, bypasses remaining reap/group observation/failure receipt and proceeds to finally. A signal just before killpg can leave the service alive with the operator exiting. On cleanup entry ignore/mask further stop signals; finish bounded group cleanup and evidence recording unconditionally. Restore handlers only after cleanup has completed, if appropriate. Also wait/poll group absence through a bounded interval, rather than a single immediate group_exists check after leader wait; record retained ownership clearly if not absent. This is a concrete stop-path issue for a resident supervisor, not a hypothetical unrelated risk.

F2 — OBSERVATION / test coverage. No wrapper tests supplied/executed. AST passes, helper hashes match, but these do not exercise signal interruption, process descendants or log-limit behavior. An isolated mocked subprocess/signal test should cover repeated stop during cleanup, descendant after leader exit, exact output boundary and overflow; live service execution is unnecessary for that test.

## Patch summary and function traces

Scope is the full new private run-trellis-bounded-v1.py plus pinned helper implementations. It adds finite recovery supervision and resident service log supervision around previously reviewed recovery/persistent startup scripts, preserving old18088 and checking only the selected new database before/after. No replacement business writer/auth/provider code. Dry-run checks source pins and returns before imports or live operations.

| Function / caller | File:line | Inputs → outputs / verified behavior |
|---|---|---|
| require/sha/save | wrapper:34,38,41 | Unconditional checks, SHA-256, O_EXCL0600 private evidence; no assert bypass. |
| load | wrapper:45 | Pinned module path → imported definitions. Helpers' module guards do not invoke main on import. sys.dont_write_bytecode prevents cache writes. |
| listener | wrapper:51 | Selected port → PID text; absolute lsof,5s timeout and bounded expected output. |
| main / module guard | wrapper:56,197 | Mode/flags/pins → dry-run or owned operator. Explicit --execute required. |
| recovery branch | wrapper:74–82 | Reviewed recovery child → finite300s/32MiB helper receipt; requires zero exit/no supervisorError/no truncation/groupEmpty. |
| database/process preparation | wrapper:83–94,121–128 | Private pinned DB URL and old process → read-only snapshots; query/fragment override refused; exact18088PID16414 and empty18198 required. |
| drain | wrapper:103 | Nonblocking merged service pipe → at most32MiB retained log; overflow throws; EOF unregisters stream. |
| stopped | wrapper:115 | SIGINT/SIGTERM → InterruptedError; initiates normal cleanup but remains active during it (F1). |
| startup branch | wrapper:120–170 |180s absolute deadline, dry launcher preflight, start_new_session child → readiness/identity/DB/preservation receipts. Actual binary and selected env checked. |
| resident loop | wrapper:171–174 | Owned process/pipe → continuous bounded draining; no whole lifetime timeout intended; exit throws and cleans. |
| failure/finally | wrapper:175–195 | Failure/signal → SIGKILL owned pgid, leader wait2s, group observation, private receipt; F1 interruption gap. No Docker stop or DB rollback. |
| finite.supervise/group_exists | qualify_readback.py:49,59–110 | Pinned Root helper: deadline+combined output cap, owned session, kill/reap/poll2s, receipts. |
| Operator.process | publish_configured.py:211 | Selected PID → macOS sysctl argv/env; no mutation. |
| Operator.database/snapshot | same:258,267 | Selected DSN → repeatable-read read-only connection,5s connect/statement bound, scalar size admission then complete bounded rows. __new__ wrapper usage supplies only required wos_dsn; no limit/run initializer-dependent method called. |
| absolute_deadline/NoRedirect | adopt_reload_hotfix.py:22,28 | Startup alarm deadline and redirect refusal; outer catches failures, subject to F1. |

## Data flow and invariants

Mode/flags originate in argparse. All five helper source hashes are checked before execution; child receives PATH and PYTHONDONTWRITEBYTECODE only. Reviewed launcher creates explicit final service environment. Recovery uses its existing selected-container/profile checks and retains partial state. Start binds only18198 and observes old18088 without killing/restarting it. Hardcoded baseline PID is an explicit selected-instance requirement, not dynamic discovery.

Old argv/env, binary and readable TRELLIS file pins are saved privately, compared again after startup. Selected new DB must initially have zero public tables; after startup it must contain exactly the three expected tables, zero events/publications and migration versions1–4. These are read-only observations around server-owned migrations, not DB restoration. Success receipt expressly leaves positiveOidcQualified and artifactAdapterQualified false.

Service log counter monotonically increases, admits no bytes beyond LIMIT, and overflow triggers cleanup. The merged pipe is drained during readiness and resident supervision; intermediate DB snapshots are bounded but may temporarily backpressure the child. Owned pgid comes from start_new_session child PID; cleanup targets only that group. SIGKILL cannot be caught by the service; wrapper's own repeated-stop interruption is the unresolved gap. Files are0700-directory/0600 evidence, which may contain credentials and remain private.

## Tests, edge cases and hypotheses

No execution claims. Wrapper and all pinned helpers parse. Expected source branches: dry-run cannot reach load/listener/DB; missing startup pins refuse before service launch; failed preflight refuses; wrong listener/binary/env/DB inventory/preservation refuses and kills newly owned group; excess logs refuse; normal resident child exit refuses and cleans; RustFS/DB partial state is deliberately retained. Repeated signal during cleanup currently escapes evidence/reaping (F1). Any positive admission/export conclusion from readiness is explicitly excluded.

H1 wrapper expands resource mutation: REFUTED by selected script calls and read-only helper reuse. H2 all supervisor cleanup is unconditional: REFUTED by active signal handler in cleanup. H3 32MiB log admission is enforced: CONFIRMED by remaining+1 read/overflow exception. H4 imports invoke unrelated helper live actions: REFUTED by read implementations/module guards. Next: amend cleanup only, freeze exact successor and rereview; no live commands required for correction.

## Exact pins

| Input | SHA-256 |
|---|---|
| `run-trellis-bounded-v1.py` | `475aaaa126bcf49092b37a26a22f9e6e66eb72c2c3680c009949e902059152dd` |
| `qualify_readback.py` | `c94f4d8f71bc4fd654626998789cc11ab5a8fc64a0e69739cd93324d601e4679` |
| `publish_configured.py` | `fd4ed96ad03927c20e1acd962ab313c232da7bfc590f6418e5f5f7175e8cdaf0` |
| `adopt_reload_hotfix.py` | `796603c1c87122910b9c82cb44125e421238dd0f1bcd04d3db3ac3360d15e949` |
| `recover-rustfs-reviewed-v1.py` | `3a9e2dc2d544ffccd28b55b7f3bd7736455062b10837b44bf26cea48852dac8f` |
| `start-trellis-persistent-reviewed-v5.py` | `aba250439f1203accdb2afc77e33aada33516a65448de51c2d7f4bc8136b72f7` |

All five current helper hashes equal wrapper PINS. Wrapper AST contains zero Assert nodes; imported timer has its preexisting nested-timer assert but wrapper establishes no nested timer and does not depend on removing that guard.

## Original snapshot conclusion (superseded below)

Original VERDICT: REQUEST CHANGES.

The wrapper meets the selected operation/source/log-bound intent except its repeated-stop cleanup path. Coverage: ADEQUATE for static traces; INSUFFICIENT for signal/process execution. Confidence: HIGH for inspected finding and pins. No live execution or service/provider/export qualification granted. Preserve prior certificates and frozen scripts while fixing the wrapper.

## Corrected successor review and final conclusion

Reviewed the full current wrapper again, SHA-256 `475aaaa126bcf49092b37a26a22f9e6e66eb72c2c3680c009949e902059152dd`. Original snapshot hash/table and traces above preserve finding history; current locations follow. No script or live command executed during rereview. AST parses, zero Assert nodes; five pinned helper bytes remain the same previously checked inputs.

F1 RESOLVED: stopped at73–79 ignores SIGINT/SIGTERM before raising. It is installed before recovery, so the finite helper's finally cleanup also resists repeated stops. Startup except194–215 ignores both signals before owned-group work, catches lookup/permission failures, waits leader and polls group absence through a shared two-second bound, records ownedGroupEmpty and cleanupError, then saves private failure evidence. This addresses the concrete repeated-stop gap and immediate-absence race. Failure does not become success if cleanup cannot establish absence; operational review must inspect the retained ownedGroupEmpty value.

Additional reviewed changes:

- recover-start mode66,84–98 combines the finite recovery with subsequent startup. Requires explicit grant pin, consumes only successful bounded recovery output, confines chosen qualification directory to HERE with recovery prefix, hashes its actual receipt, then the reviewed launcher validates passing/profile/byte preservation/running facts. No external proof is inferred from an arbitrary status string alone; caller still trusts the pinned recovery source and private output custody.
- Database target108–110 is validated before any snapshot: exact scheme/loopback18185/database/username and no query/fragment/params. Existing pinned private DB input remains checked.
- Expected environment148 is compared exactly at176–177 after excluding only three OS-injected executable metadata values. Input hashes149–150 and178 are checked before/after launch. Auth/storage/artifact settings cannot silently drift into actual child environment.
- Startup listener/process/binary/config preservation and database receipts remain at134–188. Result now correctly says old18088ProcessBinaryConfigPreserved and oldMemoryRowsReadbackCompared=False. No original in-memory row equality claim.
- Readiness164–168 uses the maintained readyz probe. I read server state.rs:511–548: it lists the dedicated probe scope and writes/reads `__healthz__/artifact-roundtrip` through the configured artifact adapter. The retained health object under selected bucket/prefix is disclosed; this is a known readiness write in addition to the SDK isolated test object. It is not business-event creation or whole-export/restart qualification. Result flags positiveOidcQualified/artifactAdapterQualified remain false.

Updated hypotheses: unconditional stop cleanup is now supported by source; repeated stop no longer interrupts its own handling. Exact child configuration equality is stronger than initial subset checks. Combined mode preserves the same pinned single recovery and single launcher; no duplicate provider/writer added. Source-derived edge cases include failed recovery refusing startup, malformed/unconfined recovery output refusing, wrong DSN refusing before snapshot, any final env/input drift refusing and killing newly owned service. No runtime signal/log/process tests supplied; F2 remains an explicit coverage observation.

Intermediate VERDICT: APPROVE exact corrected wrapper SHA475aaaa1… for static execution readiness.

Coverage: ADEQUATE for the focused static corrections/call traces; INSUFFICIENT for actual recovery/startup, signal execution, row comparisons or export/provider outcomes. Confidence: HIGH for inspected source and pin consistency. Root's separate live grant/window remains required. Only this review certificate changed; no wrapper/helper/production files modified by reviewer.

## Exporter-profile successor — final exact review

Final wrapper SHA `05571d9b1a64f6fac9c40b47a64e6a6fc9ef4c7823abfe8cbc6ebd1603de5f56`; V6 launcher SHA `98101f0ae2426167679897b264929571a3f0b985a58fb7d48030c076fef1bf54`; exporter profile SHA `ad47c7186758c9adfefb9974a863124de48ea3d5cb40259857da594267a8f6f3`. All independently read and hashed; Python AST parses. Original profile and V5 preserved.

Compared full V5→V6 launcher: only PROFILE_FILE constant, profile digest and profile_path selection change. Wrapper updates pinned launcher/import/argv plus expected environment/startup input maps to launcher.PROFILE_FILE. Cleanup correction and other behavior remain as reviewed above.

Compared original→successor profile: only allowedClients adds formspec-trellis-exporter-dev, and exact issuer/subject/client binding adds stable principal trellis-local-exporter. Independent private provider-identity file under local-demos/trellis-exporter-20261009-v1 hashes `0647a70797f0eaa6a512d6810722c44e18762f0dc1b9572b2fe22be423337ddf` and its issuer/clientId/subject equal the added binding (subject e3b2f43f-4656-471d-8be3-b32e9c4d658c). Credential details were not printed/copied. This is configuration provenance from Root's retained provider facts, not live token qualification by this reviewer. Required scopes, action scopes, tuple, introspection configuration and deny-all grants remain identical. Adding identity admission alone grants no case Read/Administer; exact exporter grants and current token200 remain future gates.

FINAL VERDICT: APPROVE exact final wrapper05571d9b…, V6 launcher98101f0a… and exporter profilead47c718… for static preparation/execution readiness only. No new blocker. Prior failure finding is resolved; no live operation/test/DB/provider action performed. Root's explicit execution grant/window, actual receipts, provider admission, owning adapter/export/restart retrieval and agency/ZIP qualification remain separate.
