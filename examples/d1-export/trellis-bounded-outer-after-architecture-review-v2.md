# Bounded outer operator v2: focused AFTER architecture review

**VERDICT: APPROVE the exact static successor and start-only recipe.** The sole wrapper change admits the exact `sslmode=disable` query already present in the pinned loopback database configuration. It preserves rejection of additional or changed query options. Reuse the exact retained passing recovery receipt; do not repeat recovery. Startup readiness still performs the previously reviewed retained health-key write/read.

Reviewer `/root/oidc_arch_review`, independent non-author, 2026-10-09. Full retained `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md` applied proportionally to this one-predicate successor. Only this certificate written. Read-only source/digest/AST inspection; no prepared script invocation/import, DB connection, provider/network request, service or native command.

## 1. Artifact summary

Private files are under `/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1`.

| Exact input | SHA256 |
| --- | --- |
| Approved `run-trellis-bounded-v1.py` | `f59c9d2d1b07b3b536d6bae3b31643fdbb08bf16a27fbce5ebf4900a46b35ed0` |
| Successor `run-trellis-bounded-v2.py` | `11429bab85631f43c7ec86acdd6c39de579a9cda50ebb368bb4d1f15148c1958` |
| `run-trellis-bounded-v2-start-only.command.txt` | `87d5003ce53bfc8e19ed0f6c81cdac3636cf2f03b4838ee4c3a4aa041194c879` |
| `rustfs-recovery-96abbe2b6f3a49d89b10c601d7d438ba/qualification.json` | `c8ea70d60d88f569dd2e0b35c08d689864e8b37208e8a31906926a00a468d819` |
| `database.private.json` | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |
| `current-grants.json` | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |
| Report `trellis-bounded-outer-static-check-v3.json` | `7355c2a22d60401604b57f4a39ab4066f8753a5435b938ac84bde6d578b4cccc` |

All listed hashes independently match. Category: operator scaffolding. The source diff contains exactly one changed predicate at wrapper line117: `not address.query` becomes `address.query == 'sslmode=disable'`. AST parses. No helper, profile, grant, binary, deadline, cleanup or deployment-selection change accompanies it. Native source identity remains inherited from the preceding certificate; this successor does not alter or requalify the binary.

## 2. Lineage and relationships

| Prior artifact | Relation | Citation |
| --- | --- | --- |
| `trellis-bounded-outer-before-architecture-review-v1.md` SHA `ffbdadb0393fbcc67b3e0ee7d838f1bd3e2a1fd40732ca4f3debb75a89525d19` | Parent; all unchanged helper pins, invariants and limits retained | §1–7 |
| Pinned database profile | Actual selected input rejected by predecessor | Private `database.private.json:databaseUrl`; wrapper:114–117 |
| Passing recovery receipt | Exact retained prerequisite for start-only | Receipt `status`, `profileSha256`, `originalExactBytesPreserved`, `afterState` |
| Static guard evidence | Original refusal and six successor cases | `trellis-bounded-outer-static-check-v3.json:successorGuardCases` |
| Product goal | Persistent, inspectable proof remains successor outcome | `GOAL.md:28`; `DEVELOPMENT-PHILOSOPHY.md:384–388` |

| Seam | Owner | Input / output | Limit |
| --- | --- | --- | --- |
| Exact DB URL selection | Trellis operator | Pinned local DSN → existing read-only snapshot and maintained startup | Exact loopback18185/database/user plus exact query |
| Recovery receipt reuse | Root operator | Exact existing passed receipt → pinned launcher prerequisite | Receipt is historical evidence, not a fresh liveness check |
| Start-only dispatch | Root operator | Pinned wrapper + unchanged empty-grant pin → resident bounded startup | No recovery branch; actual readiness retains health-key writes |

## 3. Invariants and commitments

**Exact selected deployment — PRESERVED.** Database raw digest is checked before URL parsing, then scheme, host, port, database, username, exact query, absent fragment and absent params are required (`wrapper:114–118`). Allowing one exact query neither permits arbitrary SSL policy nor weakens host/database selection. This is the existing selected local development configuration; it creates no production TLS policy.

**Source preservation — PRESERVED.** Independent diff confirms exactly one predicate changed. All inherited finite bounds, signal handling, process identity, actual environment comparison, before/after input pins, private evidence and owned cleanup remain unchanged. The original wrapper and certificate remain available.

**No unnecessary recovery repeat — PRESERVED.** Recipe pins wrapper SHA before launching and selects mode `start`, exact qualification path/hash, exact grants hash and explicit deny-all selection. Existing launcher requires the retained receipt to state passed, selected artifact profile, original exact bytes preserved and running recovery result. Reviewer confirms those fields in the retained file; reviewer does not independently confirm current provider state.

**Evidence boundaries — PRESERVED.** Static receipt says operator/database were not executed during the AST checks. Its six cases cover selected exact query accepted; absent query, duplicate sslmode, target override, different sslmode and different host refused. This reviewer read those results and independently checked syntax/diff/pinned selected query; did not rerun the prepared guard harness. Actual recovery PASS and pre-DB refusal are Root-reported execution facts, supported here only by the retained recovery receipt and source ordering. No startup success follows this review.

## 4. User-value analysis

The correction allows the already selected database configuration to reach the maintained startup path while retaining exact authority boundaries. It removes a contradictory preflight assumption with one predicate rather than adding another configuration mode or changing storage. The prior review accepted a blank-query restriction without checking it against the pinned DSN; that mismatch caused a safe refusal and is corrected explicitly here. No performance claim applies.

Falsifier: successor reaches a different database or accepts an extra query option. The smallest correct shape is this exact literal predicate because the profile is already digest-pinned. Removing query validation altogether would add unnecessary ambiguity.

## 5. Counterfactual analysis

Kill criterion: any source delta beyond the predicate, changed database/grant/profile/receipt pin, or recipe invoking recovery again. Counter-decision changes the pinned database profile or removes all query checks, increasing scope without solving another requirement. Removing this successor leaves the same selected startup impossible. Existing launcher continues to own binary/configuration selection; no sibling replacement or new protocol is needed. Future critic: a historical recovery receipt might be mistaken for current storage availability. Actual readiness remains the live check, with its exact health write disclosed.

## 6. Findings

**F1 — RESHAPE completed; OBSERVATION; intent-vs-shape.** The predecessor's blank-query assertion contradicted the selected pinned DSN. Successor admits only exact `sslmode=disable` while retaining all other checks. Keep original refusal and static six-case evidence.

**F2 — KEEP; OBSERVATION; scope/preservation.** Start-only recipe reuses the exact passing recovery receipt and unchanged empty grants. It avoids repeating container/bucket qualification. “No recovery repeat” does not mean “no provider writes”: maintained `/readyz` still puts/gets `trellis/__healthz__/artifact-roundtrip`, as accepted in parent §3 I5.

**F3 — DEFER; OBSERVATION; user-value/evidence.** Actual first-start receipt, old-service preservation, migration/readiness results, positive current-token admission and actual acknowledged export/restart/pinned bytes remain execution gates. No REVERSE recommendation or blocking static finding remains.

## 7. Verdict and limits

**APPROVE exact static successor and start-only recipe.** Intent MATCHES; user-value SUPPORTED; commitments HONORED in the inspected delta; conceptual debt PAYS DOWN one incorrect assumption; sibling subsumption PARTIAL/reused; confidence HIGH for bounded static delta, actual startup unverified.

All six phases applied. Hypothesis that the blank-query policy matched the pinned DSN REFUTED by read-only URL inspection. Hypothesis that the correction admits arbitrary options REFUTED by exact literal predicate and retained mutation cases. Hypothesis that start-only repeats recovery REFUTED by recipe mode. All unchanged relationships inherit the fully traced parent certificate; no phase skipped. No live/native operation occurred, and this review grants no independent execution authority beyond Root's selected window.
