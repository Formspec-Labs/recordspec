# Trellis bounded outer operator — V3 static successor review

Review ID: TRELLIS-BOUNDED-OUTER-AFTER-V3-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Full semi-formal-code-review method applied incrementally under `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`; prior full source/call traces retained in V1/V2 certificates. Only this certificate written. No script/helper invocation/import, DB connection, Docker/S3/network/service/compiler/native action. Read-only diff/file/hash/AST inspection only.

## Findings and patch summary

**APPROVE exact V2 wrapper11429bab… and start-only recipe87d5003c… for static readiness. No blocking finding.** The sole wrapper source change correctly admits the already pinned selected DSN's exact query without admitting arbitrary database overrides. Prior refusal was an operator-guard mismatch, not a successful DB/startup outcome.

F1 — RESOLVED / correctness / run-trellis-bounded-v2.py:117. Previous `not address.query` rejects the frozen database URL because it contains sslmode=disable. Successor requires exact `address.query == 'sslmode=disable'`. Scheme, loopback host18185, database name, username, absent fragment/params remain required. The private DB digest remains d15d5c86… and is checked before parsing. I verified the selected private input's query without printing credentials.

F2 — OBSERVATION / evidence. Supplied six-case isolated AST guard result reports exact selected acceptance, absent/duplicate/override/different-mode/different-host refusal and original guard RED. I read that result and predicate; reviewer did not execute those cases. Static AST passes, zero Assert nodes. No current server launch or database migration success is claimed.

## Function trace and data flow

| Function / caller | File:line | Inputs → outputs / verified behavior |
|---|---|---|
| main DSN admission | wrapper:113–118 | Pinned private DB bytes → parsed exact address/query → selected read-only snapshot DSN. Only literal sslmode=disable admitted. |
| existing startup path | wrapper:101–225 | Exact existing qualification/grant pins → reviewed launcher, bounded startup, exact env/process/config/DB checks and owned cleanup; byte-identical to approved f59 wrapper except single predicate. |
| detached recipe | run-trellis-bounded-v2-start-only.command.txt:6–13 | Exact wrapper hash → private log and detached start-mode operator | Unconditional digest guard, explicit retained receipt path/hash, explicit unchanged deny-all grant pin, narrow env/DEVNULL/new session; dispatch status only. |
| launcher receipt guard | start-trellis-persistent-reviewed-v6.py:35–38 | Retained private receipt → passing/profile/preserved-bytes/running checks | Existing reviewed caller path unchanged; source checks plus explicit expected receipt hash bind the selected input. |

Full wrapper diff against approved f59 is exactly one predicate. Recipe uses `start`, so wrapper's recover/recover-start branch is skipped: no repeated SDK recovery writes or container restart. A later /readyz still uses the known maintained health-object put/get disclosed in prior review. Selected SQL setting disables TLS only for the fixed local PostgreSQL target; exact query comparison does not allow appended options, encoding variations, fragments or duplicate settings.

## Tests, retained evidence and edge cases

No reviewer executions. Read the actual existing recovery receipt c8ea70d6…: passed SDK probe, selected container started, bucket created, initial200, identical412, conflicting412, three49-byte exact reads. Independently rehashed all three retained read files; each matches receipt60d973fb… and49 bytes. These are owner-retained results, not current object-store liveness proof or execution of the Rust immutable export helper.

Cases in isolated static receipt: exact query true; missing query, duplicate sslmode, target override, different sslmode and host false; original guard rejects selected DSN. Source supports those dispositions. Private-file/source/receipt mismatch, failed launcher preflight, deadline, unexpected process/env/schema or excessive logs retain existing refusal/owned cleanup paths. Actual start-only invocation remains pending. No profile/grant changes, new exporter authority or live provider call introduced.

## Exploration record

H1 successor broadly permits DB options: REFUTED by exact literal query and unchanged host/port/database/user conditions plus private digest. H2 patch includes unrelated behavior: REFUTED by exact one-line diff. H3 recipe repeats successful recovery: REFUTED by explicit start mode and existing receipt path/hash. H4 passed SDK receipt proves server readiness/export durability: REJECTED; no such claim accepted. No unresolved static blocker.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-bounded-outer-after-code-review-v2.md` | `62adb01147bd1abf1a6934e5c65ad8b4eb881baabe5d5062aa7bbf7c1ab56cff` |
| `run-trellis-bounded-v1.py` | `f59c9d2d1b07b3b536d6bae3b31643fdbb08bf16a27fbce5ebf4900a46b35ed0` |
| `run-trellis-bounded-v2.py` | `11429bab85631f43c7ec86acdd6c39de579a9cda50ebb368bb4d1f15148c1958` |
| `run-trellis-bounded-v2-start-only.command.txt` | `87d5003ce53bfc8e19ed0f6c81cdac3636cf2f03b4838ee4c3a4aa041194c879` |
| `trellis-bounded-outer-static-check-v3.json` | `7355c2a22d60401604b57f4a39ab4066f8753a5435b938ac84bde6d578b4cccc` |
| `qualification.json` | `c8ea70d60d88f569dd2e0b35c08d689864e8b37208e8a31906926a00a468d819` |
| `database.private.json` | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |

Supplied successor/recipe/qualification hashes match current bytes; original wrapper remains f59c9d2d…. All prior certificates preserved.

## Conclusion

VERDICT: APPROVE exact bounded static successor and start-only recipe.

Coverage: ADEQUATE for one-predicate change, recipe and retained input readback; INSUFFICIENT for actual server startup, provider admission or export/restart outcomes. Confidence: HIGH for source equality and pinned evidence. Root's separate live-window authorization and actual startup-result/failure inspection remain required. No live action performed or operational success inferred.
