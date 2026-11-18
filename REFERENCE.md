# Trellis — document outline reference

Per-file inventories of **H1** (`#`) and **H2** (`##`) headings with one-line summaries. Use this for navigation and grep alignment; narrative and relationships are in [`README.md`](README.md).

Paths are relative to `trellis/`.

Archived material under `specs/archive/` and `thoughts/archive/` is intentionally omitted from this reference. See [`README.md`](README.md) for archive pointers.

---

## `thoughts/product-vision.md`

**H1 — Formspec + WOS + Trellis — Product Vision & Roadmap**
Authoritative product roadmap: three-tier framing (Formspec / WOS / Trellis), four-phase delivery arc, 15 non-negotiable Phase 1 envelope invariants, ledger/log vocabulary, tracks A–E.

| H2 | Summary |
|----|---------|
| The vision, in one sentence | Single-sentence pitch tying intake → adjudication → air-gapped-verifiable appellate record. |
| The product | Three tiers, their roles, and the coherent composition claim. |
| Who it's for | Federal/state public-sector intake, regulated enterprise, adjacent privacy-forward markets. |
| Why it wins | Competitive framing against Adobe AEM Forms, ServiceNow, and DocuSign. |
| How we build — the operating model | Agreement-first sequencing, specs-as-prompt-guidance, the closed loop with per-spec centers of gravity. |
| Current state (honest assessment) | Status matrix for Formspec / WOS / Trellis across agreement, spec, schema, lint, conformance, runtime, tools. |
| Delivery arc | Four phases + "Terminology — ledger vs log" + **Phase 1 envelope invariants (non-negotiable)** (#1–#15) + per-phase descriptions. |
| Non-goals | Explicit list (not a BPM engine, not an identity platform, not DMS, not BI, not a cost play). |
| Next steps — the concrete plan | Tracks A (Trellis from zero), B (in-flight specs/runtimes), C (first-sale certs), D (engineering), E (cross-cutting bindings). |
| The unifying test | The stranger-test acceptance bar. |
| The single-sentence pitch | External framing for Trellis + WOS + Formspec together. |

---

## `specs/trellis-agreement.md`

**H1 — Trellis Agreement Document**
Non-normative sign-off gate. Names scope, primitives, invariants, seams, delivery shape, and success criterion precisely enough that a sign-off here either proceeds or blocks the rest of Track A.

| H2 | Summary |
|----|---------|
| 1. Purpose | What Trellis is, why now, the two already-written deferrals (Respondent Ledger §13, WOS §10.5) it answers. |
| 2. Scope | IS/IS-NOT bullets; non-goals verbatim from the product vision. |
| 3. Primitives | One-line definitions: event, envelope, chain, checkpoint, export bundle, signature, response ledger, case ledger, agency log, federation log. |
| 4. Trust posture | "Difficult and obvious," not "system-owner-proof." Per-phase bar from Phase 1 (bundle reissue detectable) to Phase 4 (equivocation-proof via witness). |
| 5. Phase 1 non-negotiable invariants | All 15 invariants in `#N title — essence` form with RFC 2119 MUST/MUST NOT language. |
| 6. Seams | Respondent Ledger §13 `LedgerCheckpoint`, §6.2 `eventHash`/`priorEventHash`; WOS `custodyHook` §10.5; Track E §21 case-ledger / agency-log extension. |
| 7. Phase sequencing commitment | One sentence per phase; strict-superset claim anchored to invariants #10 and #12. |
| 8. Delivery shape | Two W3C specs (Core + Operational Companion) + ~50 vectors + Rust reference + CLI/WASM + independent second implementation. |
| 9. Out of scope for Phase 1 | Explicit list (external witnessing infra, BBS+ implementation, threshold custody, respondent-held keys, federation, PQ signature shipping). |
| 10. Success gate | Stranger-test verbatim. |
| 11. Sign-off | Two-line signature block. |

---

## `specs/trellis-core.md`

**H1 — Trellis Core Specification (Phase 1)**
Normative Phase 1 byte protocol. dCBOR canonical encoding, Ed25519/COSE_Sign1 signature suite, SHA-256 hash construction, signing-key registry, HPKE Base-mode payload-key wrap, reserved commitment and causal-dependency slots, append idempotency, export ZIP layout, verification algorithm.

| H2 | Summary |
|----|---------|
| Abstract | Purpose, Phase 1 scope, and Phase 2/3 superset commitment. |
| Status of This Document | Phase 1 Core; Operational Companion is a separate normative document. |
| Table of Contents | Section navigation. |
| 1. Introduction | Three-scope terminology (event / response ledger / case ledger / agency log / federation log) and non-goals. |
| 2. Conformance | RFC 2119 statement; conformance classes (Fact Producer, Canonical Append Service, Verifier, Derived Processor, Export Generator). |
| 3. Terminology | Glossary of normative nouns. |
| 4. Non-goals and authority boundaries | What Trellis Core does not specify; Formspec/WOS authority split. |
| 5. Canonical Encoding | **Invariant #1.** dCBOR (RFC 8949 §4.2.2 deterministic profile) pinned with CDDL. |
| 6. Event Format | CDDL for the atomic append unit; field-by-field normative definitions. |
| 7. Signature Profile | **Invariant #2.** Ed25519 over COSE_Sign1 (`alg = -8`); `suite_id` registry reserving ML-DSA / SLH-DSA / hybrid codepoints. |
| 8. Signing-Key Registry | **Invariant #3.** `SigningKeyEntry` with Active/Revoked lifecycle; registry snapshot embedded in exports. |
| 9. Hash Construction | **Invariant #4.** Encrypt-then-hash; domain separation tags; crypto-shredding semantics. |
| 10. Chain Construction | **Invariant #5.** Phase 1 strict linear `prev_hash`; reserved `causal_deps` field for Phase 2 HLC/DAG upgrade. |
| 11. Checkpoint Format | COSE_Sign1 over `(tree_size, tree_head_hash, suite_id, timestamp, anchor_ref?)`; OpenTimestamps slot reserved. |
| 12. Header Policy | **Invariant #9.** Enumeration of plaintext vs committed fields; declaration-table form. |
| 13. Commitment Slots Reserved | **Invariant #8.** CDDL reservation for Pedersen/Merkle per-field commitments; BBS+ implementation deferred. |
| 14. Registry Snapshot Binding | **Invariant #6.** Content-addressed digest of domain registry in export manifest. |
| 15. Snapshot and Watermark Discipline | **Invariant #14.** `(tree_size, tree_head_hash)` watermarks on derived artifacts and agency-log entries. |
| 16. Verification Independence Contract | Verifiers MUST NOT depend on derived artifacts, workflow runtime, or mutable DBs. |
| 17. Append Idempotency Contract | **Invariant #13.** Stable idempotency key; replay semantics; rejection classes. |
| 18. Export Package Layout | **Invariant #10 + #12.** Deterministic ZIP; Phase 1 envelope IS Phase 3 case-ledger event format. |
| 19. Verification Algorithm | Step-by-step pseudocode; no network calls; time/memory bounds. |
| 20. Trust Posture Honesty | **Invariant #15.** `provider_readable` / `reader_held` / `delegated_compute` / `external_anchor_required` declaration; no overclaiming. |
| 21. Posture / Custody / Conformance-Class Vocabulary | **Invariant #11.** Three-namespace disambiguation; Respondent Ledger owns `Profile A/B/C`. |
| 22. Composition with Respondent Ledger | Track E §21(a) + §21(b); promotion of §6.2 `eventHash`/`priorEventHash` to MUST; case-ledger composition. |
| 23. Composition with WOS `custodyHook` | Track E §22; how WOS uses Trellis as custody backend. |
| 24. Agency Log (Phase 3 Superset Preview) | Agency log as log-of-case-ledger-heads; extension points reserved in Phase 1. |
| 25. Security and Privacy Considerations | Metadata leakage, equivocation, side channels, replay, key compromise, PQ migration, crypto-shred/backup interaction. |
| 26. IANA Considerations | `suite_id` registry request; content-type registration. |
| 27. Test Vector Requirements | ~50 vectors across `append / verify / export / tamper`; second-implementation byte-match gate. |
| 28. Appendix A — Full CDDL | Complete grammar. |
| 29. Appendix B — Example Events and Exports | Hex CBOR + decoded dCBOR worked examples. |
| 30. Traceability Anchors | TR-CORE-NNN row anchors for cross-reference from the matrix. |
| 31. References | Normative + informative. |

**Handoff status:** Groups A/B/C closed in commit `3a143a1`.

---

## `specs/trellis-operational-companion.md`

**H1 — Trellis Operational Companion**
Normative Phase 2+ operator obligations. Custody models, posture-transition auditability, metadata budgets, projection discipline, snapshot watermarks, respondent-history and workflow-governance sidecars, delegated-compute honesty, monitoring/witnessing seams.

| H2 | Summary |
|----|---------|
| Abstract | Phase 2 companion to Trellis Core. |
| Status of This Document | Cites Core; Core wins on any conflict. |
| Relationship to Trellis Core | Boundary statement: Core handles bytes; Companion handles obligations. |
| Table of Contents | Section navigation. |
| 5. Introduction | Operator-obligations framing. |
| 6. Conformance | RFC 2119 statement; operational maturity tiers. |
| 7. Terminology | Reuses Core glossary; adds projection, watermark, staff view, custody model, sidecar. |
| **Part I — Posture and Disclosure Discipline** | |
| 8. Access Taxonomy | Provider-readable / reader-held / delegated-compute; MUST be declared per deployment. |
| 9. Custody Models | Six custody models (renamed from legacy Trust Profiles A–E); required declaration fields; disambiguation from Respondent Ledger Profile A/B/C. |
| 10. Posture-Transition Auditability | Custody-model or disclosure-profile change is itself a canonical event. |
| 11. Posture-Declaration Honesty | Required declaration document; overclaiming prohibited. |
| 12. Metadata Budget Discipline | Per-fact-family declaration tables of visible metadata. |
| 13. Selective Disclosure Discipline | How commitment slots (Core §13) are populated; disclosure manifest; redaction auditability. |
| **Part II — Derived Artifacts and Projections** | |
| 14. Derived-Artifact Discipline | All derived artifacts carry watermark + rebuild path. |
| 15. Projection Runtime Rules | Rebuild equivalence, staleness indication, purge cascade, integrity sampling. |
| 16. Snapshot-from-Day-One | Required cadence for checkpoint snapshots; integrity binding. |
| 17. Staff-View Integrity | Adjudicator UI watermark propagation and stale-view signaling. |
| **Part III — Operational Contracts** | |
| 18. Append Idempotency (Operational) | Retry budgets, TTL, dedup-store lifecycle. |
| 19. Delegated-Compute Honesty | AI-agent scope, authority attestation, audit trail, attribution. |
| 20. Lifecycle and Erasure | Sealing, legal-hold precedence, crypto-shredding scope, derived-plaintext invalidation cascade. |
| 21. Rejection Taxonomy | Rejection classes and observable semantics. |
| 22. Versioning and Algorithm Agility | Suite rotation, key-registry migration, payload-format evolution. |
| **Part IV — Sidecars** | |
| 23. Respondent History Sidecar | Stable paths, item keys, amendment cycles, migration outcomes. |
| 24. Workflow Governance Sidecar | Operational workflow state vs canonical facts; WOS `custodyHook` path. |
| 25. Grants and Revocations as Canonical Facts | Per-contract authority and decision ledgers, conditional append, ordered reads with starting hashes, and erasure. |
| **Part V — Witnessing and Monitoring (Phase 4 Preview)** | |
| 26. Monitoring and Witnessing Seams | STH publication cadence; equivocation-detection primitives; implementation deferred. |
| **Part VI — Assurance** | |
| 27. Operational Conformance Tests | Projection rebuild, crypto-shred cascade, rejection semantics, metadata-budget compliance. |
| 28. Security and Privacy Considerations (Operational) | Side channels, staff-view leakage, projection poisoning, idempotency-key leakage, delegated-compute supply chain. |
| 29. References | Normative + informative. |
| Appendix A — Declaration Document Template | A.1 top-level, A.2 access taxonomy, A.3 metadata budget, A.4 custody-model registry, A.5 posture-transition event. |
| Appendix B — Sidecar Examples | B.1 respondent history, B.2 workflow governance, B.3 disclosure manifest, B.4 delegated-compute grant, B.5 projection watermark. |
| C. Traceability Anchors | TR-OP-NNN row anchors. |

**Handoff status:** Groups A/B/C closed in commit `3a143a1`.

---

## `specs/trellis-requirements-matrix.md`

**H1 — Trellis Requirements Matrix (Consolidated)**
Traceability matrix. 79 TR-CORE + 47 TR-OP rows, legacy ULCR-* / ULCOMP-R-* provenance, gap log for dropped legacy rows. Prose in Core and the Operational Companion wins on conflict.

| H2 | Summary |
|----|---------|
| Purpose | Supersession of legacy matrices; relationship to Core + Companion. |
| Column Schema (traceability) | ID, Scope, Invariant, Requirement, Rationale, Verification, Legacy, Notes. |
| Section 1 — Core-Scope Requirements (`TR-CORE-NNN`) | 79 rows; contracts, ontology, canonical order, hash, signature, key-bag, fact-admission, idempotency, verification, manifest bindings, head format, snapshots, trust honesty, versioning, cross-repo authority, conformance, sidecar boundary. |
| Section 2 — Operational-Companion-Scope Requirements (`TR-OP-NNN`) | 47 rows; projections, custody models, delegated compute, grants, metadata budget, offline authoring, durable-append, protected payloads, selective disclosure, privacy, lifecycle, versioning, subordination. |
| Section 3 — Mapping Tables | Invariants → TR-CORE rows; legacy ULCR/ULCOMP-R → TR-*; terminology reconciliation. |
| Section 4 — Profile-Namespace Disambiguation (Invariant #11) | Respondent Ledger Profile A/B/C, legacy core Conformance Classes, legacy companion Custody Models. |
| Section 5 — Gap Log (Legacy Rows Dropped) | 23 gap-log entries with justification buckets (superseded by invariant, upstream-owned, duplicate). |
| References | Cross-spec references. |

**Handoff status:** Groups A/B/C closed in commit `3a143a1`.

---

## `specs/cross-reference-map.md`

**H1 — Trellis Cross-Reference Map**
Living document recording upstream homes for concepts removed from Trellis specs when the three-spec dependency direction (Formspec ← WOS ← Trellis) was formalized. Implementation aid, not normative.

| H2 | Summary |
|----|---------|
| Purpose | Preserves Trellis-to-Formspec/WOS rehoming traceability. |
| Removed ULCR rows (from legacy core matrix) | Map of legacy ULCR IDs to their new Formspec / WOS homes. |
| Removed ULCOMP-R rows (from legacy companion matrix) | Map of legacy ULCOMP-R IDs to their new homes. |

---

## `specs/README.md`

**H1 — Trellis Specs**
Reading order, authority claims, archive pointers for the `specs/` directory.

| H2 | Summary |
|----|---------|
| Reading Order | Agreement → Core → Operational Companion → Requirements Matrix. |
| Normative Authority | Only Core and Operational Companion are normative; Agreement is a sign-off gate; Matrix is traceability. |
| Archived Inputs | Archive folder pointers for the superseded 8-spec family. |
| Checks | Lint invocation for `scripts/check-specs.py`. |

---

## `thoughts/archive/specs/2026-04-17-trellis-normalization-handoff.md`

**H1 — Trellis Spec Normalization Handoff**
Outstanding architectural work ordered such that byte-protocol decisions land before cosmetic alignment.

| H2 | Summary |
|----|---------|
| Context | Directional alignment with vision; drift between vision and generated prose is the residual problem. |
| Verified findings | Three factual claims confirmed with file:line evidence (signature zero-fill, JCS-vs-dCBOR, stale Core §N refs). |
| Reasoning | Prose-first vs matrix-first tradeoff; prose-first adopted. |
| Tasks | Group A byte-protocol repair (1–7), Group B document hygiene (8–10), Group C vocabulary/traceability (11–13), Group D automation (14). |
| Acceptance Bar | Six concrete implementor-facing tests that make the handoff complete. |

---

## `ratification/`

Process gates (not protocol specs) for moving the two normative Trellis specs toward ratification. See [`ratification/README.md`](ratification/README.md) for layout.

---

## Heading-reference policy

- Active documents only. Archived files are deliberately omitted.
- When section numbers change, this file updates alongside the spec edit.
- `scripts/check-specs.py` enforces that `§N` cross-references resolve to headings that still exist.
