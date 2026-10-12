# Trellis bounded outer operator — successor static AFTER review

Review ID: TRELLIS-BOUNDED-OUTER-AFTER-V2-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Full `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md` applied incrementally with preserved preceding full BEFORE certificate. Only this certificate written. No wrapper/helper invocation/import, process capture, Docker, S3, DB, service, compiler or native operation. Source reads, file digests and AST parsing only.

## Findings and decision

**APPROVE exact successor wrapper f59c9d2d… for bounded static readiness. No new blocking finding.** Root's actual guard finding supersedes the prior process-environment method; this certificate accepts the corrected helper wiring without converting prior static expectations into runtime proof.

F1 — RESOLVED / correctness / wrapper:141,168,179–180,195. Previously the inherited alarm raises TimeoutError and readiness caught it as an ordinary HTTP timeout, potentially swallowing the one-shot whole-operation alarm. Current operation_end uses a monotonic clock; ready_end is capped at that end; caught timeouts verify the whole deadline; final success again requires time before operation_end. A swallowed timeout cannot yield successful late startup. This is a bounded deadline/admission correction, not a hard real-time scheduler guarantee: finite subcalls and cleanup may finish after deadline before recording refusal.

F2 — RESOLVED / correctness / wrapper:27–29,105–110,144,160,183–185,193. All old/new process comparisons now use the pinned capture_process helper. The previous Operator.process parser and filtering of three keys are no longer used. New helper stops environment parsing at its terminator, retains later Apple auxiliary bytes as separate diagnostics, and rejects duplicate/empty environment keys. New environment equality is exact; no key exclusion or normalization. Original service equality compares argv and real environment and retained binary/config pins; auxiliary differences do not redefine environment.

F3 — OBSERVATION / test coverage. No execution tests added or run by this reviewer. Both current files and all imported sources parse; this establishes syntax/source structure, not actual macOS process parsing or signal/timing execution. Root's live finding and helper provenance are supplied operational context, not a new runtime observation here. Guard/parser isolated tests remain valuable; their absence does not block this explicitly bounded source review.

## Patch summary and function traces

Read the entire current wrapper and entire new helper. Prior full recovery, launcher, database snapshots, cleanup and source pin traces remain in the pinned BEFORE certificate. This successor changes monotonic deadline handling and process parsing/wiring; production server, launch credentials/provider flow, business writers and frozen V6 profile remain unchanged.

| Function / caller | File:line | Inputs → outputs / verified behavior |
|---|---|---|
| main/PINS | wrapper:27–34,70–74 | Helper files → exact hashes checked before execution; dry-run returns before module loading. |
| process_snapshot | wrapper:107–110 | PID → capture_process argv/env, append separate auxiliary diagnostics; returns only real argv/env for equality. |
| startup deadline/readiness | wrapper:141–180 |180s monotonic operation_end and timer alarm → bounded readiness or refusal; HTTP TimeoutError branch rechecks end. |
| process admission | wrapper:183–195 | Actual PID/env/binary/config/DB → exact equality and final time check before success. |
| diagnostics save | wrapper:197 | Captured auxiliary metadata →0600 file under0700 output; separate from equality and startup claims. |
| parse_process_args | process_identity_v1.py:12 | Raw KERN_PROCARGS2 bytes → argv/environment/auxiliary |1MiB max buffer, argc1–256, fields≤65536, strict UTF-8, terminated fields, duplicate/empty environment keys refuse. First empty field ends real environment. |
| capture_process | helper:57 | Positive integer PID → bounded sysctl buffer → parser | Size checked before allocation and after capture; no process mutation. |
| owned cleanup | wrapper:204–231 | Failure/signal → ignore repeats, owned kill/reap/poll2s, private failure evidence | Previously resolved cleanup retained. Resident loop remains intentionally without whole-lifetime deadline, with32MiB log cap. |

Immediate caller is wrapper module guard→main. main loads the already pinned process helper via importlib only after explicit execute; process_snapshot is the sole caller of capture_process, which calls parse_process_args. No Operator.process call remains. Imported publication helper still supplies only read-only database snapshot behavior.

## Data flow and invariants

Monotonic operation_end is created at startup phase, read by readiness and final admission, never modified or persisted as authority. TimeoutError cannot be silently accepted at/after end. Actual process bytes originate in bounded sysctl, are decoded by field boundaries, and split into real argv/env plus auxiliary diagnostic hash/names. Only argv/env escape into equality checks. Auxiliary metadata is saved separately, so an auxiliary name matching an environment key cannot replace that value. Existing environment values named executable_* remain real values and are compared, not discarded.

Readiness still exercises repository scope listing and the maintained artifact put/get health object; it does not prove positive OIDC admission or immutable full export/restart retrieval. Old18088 process/binary/config preservation remains narrower than old-memory row equality, which stays explicitly false. Child group ownership, failure partial-state retention, source/input pins, DB schema/application-row checks and exact AWS allowlist remain as previously reviewed.

## Tests, edges and exploration

Reviewer executed no tests/scripts/helpers. All seven pinned Python sources pass AST parsing. Plausible source-derived cases: alarm delivered during HTTP read is caught but end check refuses; ordinary early HTTP timeout retries within ready_end; final DB/process checks exceeding time cannot issue successful startup result; duplicate env key or oversized/unterminated capture refuses; auxiliary key collision does not merge into environment; real unexpected environment key fails exact equality; repeated stop still cannot interrupt cleanup.

H1 deadline can be swallowed into late success: REFUTED by monotonic catch and final checks. H2 Apple auxiliary metadata is actual environment or requires key exclusion: REFUTED by helper's terminated environment parsing. H3 every old/new comparison uses new reader: CONFIRMED by full wrapper read. H4 static parser review proves current PID/env: REJECTED; no process capture performed. Next operation requires Root's separate live window and retained actual receipts.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-bounded-outer-before-code-review-v1.md` | `8c2030a7bff884a85231aae58020c852b89b5a142274e6c3623af038c8b40852` |
| `run-trellis-bounded-v1.py` | `f59c9d2d1b07b3b536d6bae3b31643fdbb08bf16a27fbce5ebf4900a46b35ed0` |
| `process_identity_v1.py` | `2143e3f6a0053da79fca6300037e7a095b5c9368c75af9eab1285596f817b9a0` |
| `qualify_readback.py` | `c94f4d8f71bc4fd654626998789cc11ab5a8fc64a0e69739cd93324d601e4679` |
| `publish_configured.py` | `fd4ed96ad03927c20e1acd962ab313c232da7bfc590f6418e5f5f7175e8cdaf0` |
| `adopt_reload_hotfix.py` | `796603c1c87122910b9c82cb44125e421238dd0f1bcd04d3db3ac3360d15e949` |
| `recover-rustfs-reviewed-v1.py` | `3a9e2dc2d544ffccd28b55b7f3bd7736455062b10837b44bf26cea48852dac8f` |
| `start-trellis-persistent-reviewed-v6.py` | `98101f0ae2426167679897b264929571a3f0b985a58fb7d48030c076fef1bf54` |

All six helper hashes match current wrapper PINS. Prior certificate preserved unchanged. This exact source approval supersedes its older wrapper05571d9b… approval.

## Conclusion

VERDICT: APPROVE exact successor static source and readiness gate.

Coverage: ADEQUATE for bounded successor source/call traces; INSUFFICIENT for actual timing/signals/process capture/recovery/startup/provider/export outcomes. Confidence: HIGH in inspected source/pins and corrections. No operational execution or deployment acceptance is claimed; Root must separately authorize live use and check actual receipts.

## Detached dispatch recipe addendum

Read `run-trellis-bounded-v1.command.txt`, SHA `da0799fa860054b6370e669b37d683afcc1a9a1a09ee7373bad205c0916b639e`; parsed its embedded Python without running it. It checks the exact f59c9d2d… wrapper digest unconditionally, uses absolute Python/wrapper, explicit deny-all grant pin and recover-start mode, narrow environment, DEVNULL stdin and a new operator session with private O_EXCL0600 bootstrap log. Dispatched status reports only dispatch, not startup success; actual startup-result/failure evidence remains required. The resident operator owns the separately started service group and retains prior cleanup/log bounds. Recipe is APPROVED for static readiness under the same Root live-window restriction. No dispatch performed.
