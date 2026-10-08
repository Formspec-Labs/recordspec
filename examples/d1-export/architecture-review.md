# D1 Trellis authored export architecture certificate

**VERDICT: APPROVE the bounded authored candidate and retained fixture evidence.** No blocking architecture correction remains in this slice. Approval does not establish a completed D1 case, a current-source Rust build, an authorized field-filtered export, independent agency trust, durable storage or runtime activation.

Independent reviewer: `/root/oidc_arch_review`, October 8, 2026; non-author. Skill read in full: `/Users/mikewolfd/.codex/skills/semi-formal-architecture-review/SKILL.md`. Review performed only source/artifact reads and digest/Need-text comparisons. No Cargo, builds, verifier reruns, network/live calls, signing, or source changes. Only this certificate was written. Existing `Cargo.lock` and sibling work preserved.

## 1. Artifact summary and exact evidence binding

Category: proof infrastructure supporting the applicant/reviewer's complete permitted case record and offline verification. Decision: use one native authored graph; Integrity owns `BundleCreateRequest` and the complete verifier candidate, Bindings owns accepted source bytes/signing and actor association/append inputs, Trellis owns archive composition and retrieval. Root/runtime owns actual operations.

| Reviewed input | SHA-256 |
| --- | --- |
| `examples/d1-export/writer-qualification.md` | `04c48c8f3f98534d0260961f7bcd8d86983807642bbe362822dd58240545c38d` |
| `examples/d1-export/retrieval.http` | `a1cb65249c9c4b2d37e5ed94bd483ba1bf93e7f00fd986155ba99bea2f809153` |
| `examples/d1-export/probes/native-fixture-results.json` | `15614c6cf78dfaa151221b6f8a58db2ec219083c9365af5db10d31368c9c6973` |
| `examples/d1-export/review-input-pins.json` | `b7ac159c6260c2b425ef433594ffad2f2e573a7c8b2135b213c9c432fcdcca11` |
| Initial inspected Integrity complete verifier candidate snapshot | `85eb389f53f387d34301a5d8234bf53031f7ebbaf879c4e4386bcf6113534491` (historical snapshot only) |

Final Trellis document revision removes a stale cross-owner candidate digest and explicitly delegates exact candidate version/review pins to Integrity. This preserves one shared graph without certifying concurrently changed sibling bytes; Integrity candidate later readback `b66d35465a90823c67fdcceaf7a92acdd0dcd30e18a69e03228c39613fc082d4` is drift detection, not accepted here. Consult its owner certificate before execution. Final receipt adds argv, working directory, fixture/source HEAD and Python source digests; retained verdict/limitations remain unchanged.

All three input digests match `review-input-pins.json` by independent readback. Exact HEADs: root `219198f3587c5e2486ca4fa3b189e69fb70c4637`; Trellis `3d1380ba00749b8c6b6ac0d3672216fc24bcd19f`; Integrity `d2dd4827cd294aaecc470e6a49dd8954a48880cf`; Bindings `d279d5058b00d610f9ff3e94aca410a4847398a0`. Uncommitted authored inputs are bound by digest, not inferred from these HEADs.

Source digests: writer `crates/trellis-export-writer/src/lib.rs` = `955cac11ad0dc1966b4484aed25a096eab58386229345871ad7f522d560db60b`; server profile `crates/trellis-server/src/export_profile.rs` = `31c42a9eea217e1cec972bd23c20317ecfb37253e23ab15cb78a7515a835dcd4`; HTTP `crates/trellis-server/src/http.rs` = `7d8efedb29e93f4a1eb37a8c987a0c39401655f9dbd487e37f41e74d7e8752f6`.

Problem: desired full D1 evidence exceeds the qualified baseline and current writer inputs. Artifact correctly distinguishes desired member coverage from observed synthetic fixture support. Prior documents cited: Core §§18–19 and writer/server source; relevant upward commitments are GOAL's one independently verifiable production cell and DEVELOPMENT-PHILOSOPHY's evidence/wire discipline, already read in this reviewer's earlier lineage pass. Current direct owner restrictions govern this report-only scope.

## 2. Lineage and relationship tables

| Artifact | Relation | Evidence |
| --- | --- | --- |
| `GOAL.md` | Parent outcome: signatures, export and offline proof survive the service | Product Claim; Critical Path 5; Release Gates |
| `DEVELOPMENT-PHILOSOPHY.md` | Parent method: one mechanism, existing names, byte fixtures before claims | Naming discipline; Evidence and responsibility; Wire format discipline |
| `trellis/CLAUDE.md` | Dependency direction and consumer ownership | Architecture; Verification independence |
| `specs/trellis-core.md` | Normative archive composition, optional catalogs and verification | §§16.1,18.2–18.3,19 |
| Integrity `full-d1-export/README.md` | Single desired graph and native request; baseline is not full 0.3 | Opening paragraphs; Evidence being acquired |
| Bindings `full-d1-export-bridge.md` | Retained original bytes/actor evidence; receipt is insufficient | Need table; Maintained bridge entrypoints |
| `crates/trellis-server/src/export_profile.rs` | Existing sibling support prevents duplicate catalog design | `build_export_profile_members:129–158` |

| Component / seam | Owner | Dependencies / consumers | Named? |
| --- | --- | --- | --- |
| `BundleCreateRequest` | WOS schema; Integrity candidate | Process, tier selection; runtime/Presenter | Yes, `work-spec/schemas/api/bundle.schema.json#/$defs/BundleCreateRequest` |
| Accepted-evidence bridge | Bindings/source application | Original Response/Definition/Locale/document bytes; export host | Yes, bridge's maintained entrypoints; no new wire body |
| `ExportWriterInput` | Trellis composition | Integrity archive bytes; verifier | Yes, writer `lib.rs:247–289` |
| `build_export_profile_members` | Trellis server consumer composition | Sealed events and policy artifacts; writer 066/067/068 | Yes, profile `129–158`, server `lib.rs:223–259` |
| Head/pinned retrieval | Trellis service | Authorization, repository, writer/store; root runtime | Yes, HTTP `138–157,177–208` |
| Offline export verification | Integrity CLI plus WOS validator | Archive bytes, internal registry; independent reader | Yes, CLI `102–105,266–275`; WOS verifier `lib.rs:46–47` |
| Independent trust pin and recipient disclosure | Integrity trust owner; application export policy | Actual accepted evidence and reader grants | Desired gate named; not implemented/qualified by this slice |

## 3. Invariants and commitments

1. **Single native graph — PRESERVED.** Writer document opening links the single Integrity-owned candidate and delegates exact version pins to that owner; it adds retrieval requests and a check index, no duplicate creation payload, server branch or manifest. Failure would create competing export formats.
2. **Historical accepted evidence remains historical — PRESERVED.** Writer Input and acceptance boundary and Bindings Need table separate baseline `420804727` pending review from mutable 0.3 construction. Failure would fabricate newer workflow/retention/signing history in an older case.
3. **Optional member absence is not blanket Core failure — PRESERVED.** Core §18.2 explicitly allows optional omissions; writer coverage table distinguishes D1 coverage requirements from Core conformance. Failure would demand catalogs unsupported by source events or call valid minimal archives invalid.
4. **Consumer semantics stay outside byte center — PRESERVED.** Writer `247–289` exposes typed composition inputs; profile `129–158` derives 066/068 and conditional 067; server `223–259` wires them. The corrected table acknowledges this existing support. Failure would reimplement consumer projection logic or force D1 names into core.
5. **Independent verification does not inherit agency trust from archive registry — RELIED-UPON, unresolved gate.** Core §16.1 requires service-independent verification; current CLI accepts path/format only and calls WOS ZIP verifier (`102–105,266–275`). Artifact explicitly reserves independent trusted-key qualification to Integrity. Failure would claim agency authority from a self-contained key supplied by the same archive.
6. **Whole-scope access is not field visibility — RELIED-UPON, unresolved gate.** Writer Input boundary and Bindings X4 row require reader-specific disclosure; HTTP `read_authorized` checks scope and returns a bundle, without certifying field selection (`http.rs:258–279`). Failure leaks fields beyond recipient authority even when cryptographic verification passes.
7. **Exact pinned history differs from current head — PRESERVED.** Retrieval HTTP requests separate head and exact digest; head republishes from current events (`http.rs:144–155`). Later evidence changes the head, so a prior valid archive cannot prove later history. No live retrieval occurred here.
8. **Installed binary is not current-source evidence — PRESERVED.** Probe qualification records binary digest and retained outputs. Rust fixtures passed 5/5; Python 010 passed after a preserved import failure/retry. Both 010 reports retain missing-policy-closure advisory. They certify those synthetic inputs only, not this source build or D1.

## 4. User-value analysis

Desired outcome: the recipient can inspect all permitted actual case history and exact signer/text/document evidence offline, with a truthful list of limits. The authored check graph is useful proof infrastructure because it identifies missing evidence before implementation, rather than adding another exporter.

Independent read-only comparison found all 39 Need IDs and all 39 exact `statement.done` texts in writer-qualification.md against the pinned Full Need import. This is desired coverage, not fulfillment. Accessibility, live clock actions, notices, visibility and signing ceremony require their own native executed evidence; a ZIP verifier cannot establish them from this index.

Debt delta: neutral to pays down through reuse of the existing writer/profile/verification seams. No runtime behavior or measured performance improvement is claimed. Smaller shape is already chosen: one Integrity candidate plus Trellis retrieval/coverage slice. Existing profile support subsumes 066/067/068 design work; missing other inputs warrant a failing native case emission check before a generic owning-layer fix.

Falsifiability: a future “complete D1” archive lacks actual sent notices, response correction, decision, clocks, signed text, permitted document bytes, or latest late/reopen events while its report claims full history. A valid synthetic fixture cannot refute that failure.

## 5. Counterfactual analysis

- Kill criterion: a writer fix constructs catalogs without sealed source events or copies current 0.3 wording into baseline history. Reject that fix regardless of archive verification success.
- Counter-decision: a D1-specific exporter would simplify the demo superficially but duplicate archive semantics, break native reuse and conceal real admission/trust gaps.
- Removal probe: deleting these candidate files breaks no shipped runtime. It removes the qualification checklist and repeatable native request templates; that is their bounded value.
- Sibling subsumption: PARTIAL. Existing profile derives 066/068 and eligible 067; fixture corpus demonstrates verifier/catalog formats for other members. Fixtures do not establish current writer emission of those members.
- Six-month critic: would flag promotion of fixture success to full D1, an unqualified trust root, forgotten recipient visibility, or failure to include subsequent actual history.

## 6. Findings and dispositions

**F1 — KEEP.** Severity OBSERVATION; category ownership/sibling-conflict; location writer Native member coverage. The corrected 066/067/068 rows match the existing typed writer and profile derivation (`writer:270–289`, `profile:129–158`, `server lib:223–259`). Keep this reuse; no duplicate SDK or exporter.

**F2 — KEEP.** Severity OBSERVATION; category scope; location Full Need graph review index and Input boundary. All 39 exact Done texts are present, explicitly desired. Baseline pending review cannot fulfill full D1; preserve that refusal in every downstream certificate.

**F3 — DEFER.** Severity OBSERVATION; category user-value/trust-posture; location Executable checks and remaining gates. Field disclosure, independent trusted key, actual signer identification and full case history remain gates. Require actual source-qualified bytes, recipient permission tests and trusted-key consumption; fixture verdicts and public registry retrieval do not close them.

**F4 — KEEP.** Severity OBSERVATION; category intent-vs-shape; location probes and retrieval. Retained failed Python attempt, successful retry, Rust/Python advisory and existing-binary qualification are honest. Root alone executes head/pinned requests; preserve warning that GET can publish, so retrieval is not operationally inert.

**F5 — RESHAPE only if future implementation proposes a fix without failing evidence.** Severity OPTIONAL; category debt-accretion; location writer closing paragraph. The artifact already requires a failing native emission check. Select the minimal generic missing member/input seam from that failure; do not infer an all-catalog implementation obligation merely because catalogs are listed as desired.

## 7. Verdict and limits

APPROVE this authored candidate and fixture-evidence qualification. Intent vs shape MATCHES; user-value claim SUPPORTED for proof preparation; commitments HONORED; conceptual debt NEUTRAL/PAYS DOWN by existing-seam reuse; sibling subsumption PARTIAL; confidence HIGH for exact artifact/source traces, MEDIUM for eventual live composition because original D1 bytes and runtime calls are absent.

All six review phases completed. Hypothesis trace: H1 there is one shared native candidate CONFIRMED by one owner-linked path and owner documents; sibling candidate drift was detected and exact execution qualification remains with Integrity; H2 all optional catalogs are unsupported REFUTED by profile 066/067/068; H3 full39 text proves completion REFUTED by explicit desired status and pending baseline; H4 fixture verification establishes independent agency trust REFUTED by CLI input shape and retained limits. No alternative implementation was selected before those traces.

No live source records, archive download, current-source rebuild, trust-root intake, field-filtering execution, full 0.3 history, durability, legal signature validity, or runtime activation is accepted. Existing build/runtime holds persist. Source and report drift requires fresh pin binding before using this certificate for a changed candidate.
