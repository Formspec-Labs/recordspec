# Trellis Phase-1 MVP — Principles and Format ADRs

**Status:** Accepted, 2026-04-20.

> **AMENDED 2026-04-23 — mechanism names in ADRs 0001-0003 differ from ratified spec.**
> The ADR *intents* are in force and the envelope reservations exist; the field-name / shape prescriptions below diverge from [`specs/trellis-core.md`](../../specs/trellis-core.md) v1.0.0 in three places. Future readers should treat the ratified Core as authoritative for byte-level names and consult this doc for the decision rationale:
>
> - **ADR 0001 — DAG-capable topology.** ADR prescribes `priorEventHash: [Hash]` (list form). Ratified spec uses scalar `prev_hash: digest / null` in `EventPayload` for Phase-1 chain linkage, with `causal_deps: [* digest] / null` as the separate reserved DAG slot. Phase-1 lint requires `causal_deps` be `null` or `[]`. Architecturally equivalent; names differ.
> - **ADR 0002 — List-form anchors.** ADR prescribes `anchor_refs: [AnchorRef]` in `CheckpointPayload` with Phase-1 lint `len(anchor_refs) ≥ 1` and “accept if any entry verifies.” Ratified spec uses scalar `anchor_ref: bstr / null` in `CheckpointPayload` where **Phase 1 MUST accept `null` and MUST NOT require a non-null anchor** (Core §11.5), plus an `external_anchors` list at the export-manifest layer for multi-anchor capacity. So the ADR and ratified Core agree on *reserving anchor capacity* and federation posture, but **differ on Phase-1 mandatory checkpoint anchoring**: historical ADR leaned operator-default “always one anchor”; ratified Core keeps the witness **optional until a deployment class elevates it**.
> - **ADR 0003 — Federation extension points.** ADR prescribes named optional fields. Ratified spec uses generic `extensions: { * tstr => any } / null` containers with an event-type registry (Core §6.7). Stronger and more general mechanism.
>
> ADR 0004 (Rust byte authority) is an exact match; no divergence.
>
> Header stamp added 2026-04-23 per the design-doc audit at [`thoughts/audit-2026-04-23-design-docs-vs-specs-and-code.md`](../audit-2026-04-23-design-docs-vs-specs-and-code.md) §13.

**Aligned narrative:** Phase 1 wire discipline supports the **Phase 3 unified case ledger** target in [ADR-0059 program summary](../../../work-spec/thoughts/plans/0059-unified-ledger-as-canonical-event-store.md) and [`trellis/thoughts/product-vision.md`](../product-vision.md) (strict superset; no envelope break at Phase 3).

Captures the vision model used to decide the three open format lock-ins
(event topology, anchor cardinality, federation hooks) and the
Rust-vs-Python authority question from `TODO.md`. The principles below are
load-bearing for ADRs 0001–0004 that follow. Revise the principles before
revising the ADRs; downstream decisions flow from them mechanically.

**User posture (captured 2026-04-20):**

- **Issuance vs software:** No **production Trellis records** (canonical
  append / export packages consumers would treat as authoritative) ship
  under the ratified Phase-1 wire shape until **G-5** has commissioned the
  stranger second implementation against that shape. That does **not**
  block shipping **software** (verifiers, services, CI) toward PROD-MVP;
  it blocks treating emitted records as “done” until G-5.
- PROD-MVP deployable as fast as possible; G-5 is soon-next for **record**
  issuance readiness, not for every engineering milestone.
- **Maximalist envelope, restrictive Phase-1 runtime.** Reserve architectural
  capacity in the wire format; enforce Phase-1 scope via lint rules, not
  via absence-of-capacity.
- Integrity maintained via two independent byte-level implementations
  (Rust + Python) that must agree.

Authority: this posture overrides the earlier Trellis placeholder in
[`.claude/vision-model.md`](../../../.claude/vision-model.md) (“minimalism
over reservation”). The stack-wide vision model is maintained in lockstep
with this accepted document (see **Implications for vision-model** below).

---

## Principles (the vision model)

1. **Phase-1 scope is Phase-1 scope.** Ship the Phase-1 runtime fast. Do not
   widen Phase-1 runtime to accommodate Phase 2+ use cases; do not narrow
   Phase 1 by deferring prerequisites. "MVP" is about runtime scope and
   delivery speed, not about envelope expressiveness.

2. **Zero Phase-1-shape records before G-5.** The revision window is now
   through G-5 commissioning. After commissioning: stranger re-work. After
   issuance: data migration. Exploit the cheap window for ENVELOPE decisions;
   rely on it less for RUNTIME decisions (runtime evolves under SemVer).

3. **"Format-breaking" is lifecycle-dependent.** Three cost tiers, often
   conflated:
   - **Pre-G-5 commissioning** — free. Regenerate fixtures via CI.
   - **Post-G-5, pre-issuance** — moderate. Stranger re-reads the spec
     delta and re-implements affected surface.
   - **Post-issuance** — expensive. Data migration across deployed records.
     Not applicable pre-deployment.

   Envelope additions post-issuance are especially expensive if the existing
   envelope can't carry them. Hence Principle 5.

4. **Rust is the byte authority.** The reference architecture is G-4 Rust.
   For decisions spec prose can't pin (CBOR ordering, COSE headers, ZIP
   metadata, Merkle step composition), the Rust implementation is canonical.
   The spec prose and Rust impl are co-authorities (see
   [`.claude/vision-model.md`](../../../.claude/vision-model.md) stack Q2):
   when normative spec text is **precise** and disagrees with bytes, **spec
   wins** and Rust is fixed; when prose is **silent or ambiguous** on a
   byte-level detail, **Rust wins** as reference oracle until prose is
   tightened (ADR 0004).

5. **Maximalist envelope, restrictive Phase-1 runtime.** Reserve envelope
   capacity for Phase 2/3/4 use cases now — fields, hash slots, extension
   hooks. Enforce Phase-1 scope at the RUNTIME layer via lint rules
   ("MUST NOT populate", "length MUST equal 1", etc.). Reserving is
   architecturally cheap; format revision post-issuance is architecturally
   expensive (Principle 3, tier three). When Phase 3/4 runtime capability
   lands, lint rules relax and the envelope is unchanged — no format break.

   Reconciles user_profile:65 (prefer architectural right over cheap now)
   with user_profile:59 (default to more restrictive): envelope maximally
   expressive, runtime maximally constrained in Phase 1.

6. **G-5 is the integrity anchor; Python/Rust cross-check is secondary
   integrity surface.** G-5 is the only external witness of spec-prose ↔
   implementation correctness. Internal Python/Rust agreement adds value
   (catches typos, catches spec-ambiguity bugs resolved differently between
   team members working from the same spec). Per Principle 5 applied to
   implementation: maintain two implementations where both are cheap, not
   one where cost-of-retirement is low.

7. **Architectural-capacity tie-break.** When two paths are both defensible
   under Principles 1–6, prefer the one that reserves more architectural
   capacity (broader envelope, more extension seams, stronger abstraction
   boundaries). DRY/KISS applies only when architectural capacity is
   already tied.

---

## ADR 0001 — Event topology: multi-parent DAG envelope, single-parent Phase-1 runtime

> **Ratified wire vs this section:** Byte-level names and shapes are defined
> in [`specs/trellis-core.md`](../../specs/trellis-core.md) (`prev_hash`,
> `causal_deps`). The subsections below preserve the **2026-04-20 decision
> rationale** using historical field names; do not treat them as
> normative over Core.

**Decision.** Envelope: `priorEventHash: [Hash]` (list form, DAG-capable).
Phase-1 runtime lint: `len(priorEventHash) MUST equal 1` for all events
in Phase-1 scope.

**Principles applied.** #5 maximalist envelope + restrictive runtime,
# 3 cost-at-moment (envelope cheap now, expensive post-issuance), #4 Rust
is byte authority (implements both envelope and Phase-1 lint rule).

**Cost analysis.**

- Single-parent cases under list form: envelope carries `[hash]` instead
  of `hash`. Trivial runtime cost; zero semantic cost (list-of-one
  degenerates).
- Phase 3/4 arrival (consolidated adjudications, cross-case merges,
  federation composition): lint relaxes; envelope unchanged; no format
  break; no fixture regeneration; stranger impl already handles list.
- If we had shipped `priorEventHash: Hash` and Phase 3 demanded DAG:
  envelope change, fixture regeneration, stranger re-commissioning,
  record migration.

**Counter-argument considered.** Single-parent chain is simpler to read
and implement; list-of-one is visual noise for Phase-1 readers. Accepted
trade-off: one extra bracket in fixtures in exchange for eliminating the
Phase 3 format-break risk.

**Phase-1 obligations (ratified Core).** Strict linear chain via scalar
`prev_hash` (Core §10.2); `causal_deps` MUST be `null` or `[]` in Phase 1
(Core §10.3). Requirements matrix traceability: **TR-CORE-020**, **TR-CORE-024**
([`trellis-requirements-matrix.md`](../../specs/trellis-requirements-matrix.md)). *Historical ADR
prescription:* length-1 `priorEventHash` list — naming superseded; intent
(linear Phase 1 + reserved DAG slot) matches `prev_hash` + empty
`causal_deps`.

**Revisit when.**

- Real Phase-1 consolidation use case emerges (relax lint; runtime
  semantics specified in an amendment).
- Phase 3 scoping begins (formal DAG-semantics spec).

---

## ADR 0002 — Anchor cardinality: list-form envelope, single-anchor Phase-1 default

> **Ratified wire vs this section:** Checkpoint anchoring is **scalar**
> `anchor_ref` plus manifest `external_anchors` (Core §11.5, §16.3). Phase-1
> checkpoint verification **must not** fail solely for a null `anchor_ref`.
> Text below is the historical list-form rationale.

**Decision.** Envelope: `anchor_refs: [AnchorRef]` (list form). Phase-1
runtime lint: `len(anchor_refs) MUST be ≥ 1` (no upper bound);
operators SHOULD populate with one substrate at Phase-1 deployment.
Multi-anchor is legal from day 1; threshold verification semantics defer
to the Phase 4 Federation Profile.

**Substrate choice for Phase-1 deployment.** Adapter-tier concrete choice
per [`user_profile.md`](../../../.claude/user_profile.md) and **ε — Anchor substrate choice at deployment** in
[`.claude/vision-model.md`](../../../.claude/vision-model.md) (Trellis
Active uncertainties). Candidates: Bitcoin OpenTimestamps, Sigstore Rekor,
agency-operated Trillian. Deferred to a bounded spike; not in scope for
this ADR.

**Principles applied.** #5, #3, #7 (architectural-capacity tie-break:
list form beats scalar on capacity).

**Cost analysis.**

- List-of-one in Phase-1 deployments: trivial envelope cost.
- Phase 4 multi-witness federation: envelope ready; threshold semantics
  added via the Federation Profile without format break.
- Single-slot alternative: Phase 4 envelope revision + record migration.

**Counter-argument considered.** Threshold-of-N verification semantics
are not specified in Phase 1. True — but the envelope carries the anchors;
verifiers can enforce Phase-1 "first-anchor-valid" semantics until the
Profile lands. *Ratified caveat:* Core §11.5 does **not** require a
checkpoint anchor in Phase 1; optional `anchor_ref` and manifest-level
`external_anchors` carry the “more than zero witness material when the
operator opts in” story without making anchoring a hard Phase-1 verifier
failure.

**Phase-1 obligations (ratified Core).** Core §11.5 (`anchor_ref` optional);
§16.3 (`external_anchors` on export manifest). Requirements matrix:
**TR-OP-092** (external witnessing optional and subordinate to canonical
append semantics). *Historical ADR prescription:* non-empty `anchor_refs`
with “any entry verifies” — **stricter than ratified Phase-1**; treat as
deployment guidance, not as a Core MUST.

**Revisit when.**

- Operational experience reveals substrate fragility (add a second anchor
  per-deployment).
- Phase 4 Federation Profile scoping begins.
- Regulatory / procurement forces specific multi-substrate semantics.

---

## ADR 0003 — Federation extension points: envelope-reserved, Phase-1-locked

> **Ratified wire vs this section:** Federation and case/agency composition
> use registered keys inside `EventPayload.extensions`,
> `CheckpointPayload.extensions`, and related containers (Core §6.7), not
> the named top-level `case_ledger_ref` / `agency_log_head` fields sketched
> below. Intent (“reserve growth without Phase-1 population”) matches Core.

**Decision.** Reserve envelope fields for Core §22 case ledger and §24
agency log as optional-but-validated fields. Phase-1 runtime lint:
`MUST NOT populate` (the reserved fields must be absent in Phase-1
records).

**Reserved fields (proposed; confirm in Core prose):**

- §22: `case_ledger_ref: Optional[CaseLedgerRef]` with content-addressable
  ID + cross-case-ledger reference shape + version pinning slots.
- §24: `agency_log_head: Optional[AgencyLogHeadRef]` with head digest +
  log identifier.

**Principles applied.** #5 maximalist envelope + restrictive runtime,
# 4 Rust is byte authority (implements both envelope fields and lint),
# 7 architectural-capacity tie-break.

**Cost analysis.**

- Reserved-absent fields in Phase-1 records: zero bytes on the wire
  (optional CBOR encoding omits absent fields). Zero runtime cost.
- Reader-cognitive cost of reserved fields: nonzero but bounded; mitigated
  by Phase-1 lint + explicit "Phase 4 use" docstring in Core prose.
- Phase 4 federation arrival: lint relaxes; envelope carries the
  references; no format break.
- Without reservation (prior minimalist ADR): Phase 4 envelope bump +
  record migration for cross-agency records.

**Federation Profile co-defers.** Shape A (cooperative trust-anchor
network) remains the inherited default for Phase 4 (see **Federation
Profile substance** under Trellis Active uncertainties in
[`.claude/vision-model.md`](../../../.claude/vision-model.md)). This ADR
reserves the envelope surface but NOT the Profile design; Profile
specification defers with Phase 4 scoping.

**Counter-argument considered.** "Reserved-unused is a few optional
envelope fields, no runtime effect" — true of the wire, nonzero of the
reader. Per Principle 5, the architectural-capacity gain dominates the
cognitive cost.

**Phase-1 obligations (ratified Core).** Phase-1 producers emit
`*.extensions` maps as `null` or empty except for **Phase-1-registered**
identifiers (Core §6.7); case-ledger and agency-log heads land under
registered extension keys in later phases, without new top-level
payload fields. Requirements matrix (continuity / superset posture):
**TR-CORE-080**, **TR-CORE-081**. *Historical ADR prescription:* absent
top-level `case_ledger_ref` / `agency_log_head` — mechanism superseded by
the `extensions` registry model, which is **stronger** (amendment above).

**Revisit when.** Phase 4 federation enters scoping.

---

## ADR 0004 — Rust is the byte authority; Python generators retained as cross-check

**Decision.** Rust is the byte authority (Principle 4). Python generators
in `fixtures/vectors/_generator/` are **retained** as a parallel
implementation, not retired. Both implementations MUST produce
byte-identical output for every committed vector; disagreement is a
high-priority investigation (spec ambiguity OR impl bug).

**Principles applied.** #4 Rust is byte authority, #6 dual-impl
cross-check is secondary integrity surface, #5 applied to implementations
(maintain architectural capacity; don't retire what's cheap).

**Integrity model.**

- **G-5 stranger** — the primary external integrity anchor. Reads spec
  prose alone; byte-matches Rust output.
- **Python ↔ Rust cross-check** — CI-enforced on every PR. Catches:
  - Rust impl typos (cheap to fix, caught immediately).
  - Spec-ambiguity bugs where the same spec prose is reasonably read two
    different ways by two team members writing the two impls.
  - Both impls agreeing but being wrong — only G-5 catches this.
- **Authority resolution.** When Rust and Python disagree on a
  byte-level decision **that normative spec prose does not pin**, Rust
  wins (it's the reference impl); Python updates to match; the disagreement
  becomes a spec-prose clarification ticket. When prose **does** pin the
  bytes, Principle 4 applies: spec wins, Rust is fixed.

**CI discipline.**

- `python3 scripts/check-specs.py` runs both generators for every vector;
  asserts byte-identity.
- Disagreements fail the PR. Investigation ticket is load-bearing; don't
  silence the check.

**Principles applied to retention (why NOT retire despite DRY/KISS
appeal).**

- Principle 5: maintaining two byte-level implementations is
  architectural capacity (two independent witnesses of byte correctness).
  Retiring one loses that capacity irreversibly once muscle memory
  departs.
- user_profile:59: "default to the more restrictive" — two impls
  constrain the byte surface more than one.
- user_profile:65: "prefer architectural decisions over engineering
  speed" — engineering cost of maintaining Python in parallel is low
  under minutes-not-days; architectural value of dual-impl cross-check
  is high.

**Counter-argument considered.** Python duplicates byte-level logic —
not DRY. Accepted: DRY applies when the duplication is likely to drift
unsupervised. Here CI guarantees byte-identity, so the "duplication" is
actively verified to be semantically identical. Not drift; cross-check.

**Revisit when.**

- After G-5 commissioning + first month of production deployment: if the
  Python/Rust cross-check has caught zero interesting bugs (only noise)
  across a representative sample of PRs, reconsider retirement. Decision
  criterion is empirical.
- If Python maintenance burden grows disproportionately to its
  integrity contribution.

**Addendum 2026-05-12 — substrate split.** Per `formspec-stack/thoughts/archive/plans/2026-05-12-integrity-stack-case-boundary-refactor.md` Phase 6
/ Task 6.2, the Rust byte authority for primitive byte protocols (CBOR
encoding, COSE_Sign1 envelope, length-prefixed domain separation,
deterministic ZIP) now lives in `integrity-stack/crates/` (`integrity-cbor`,
`integrity-cose`, `integrity-canonical`, `integrity-bundle`,
`integrity-event`). Trellis Rust composes those substrate crates; Trellis
spec prose composes their byte rules (Trellis Core §1.5 introduces the
substrate authority pattern, §5 / §7 / §9.1 / §18.1 reference the
substrate crates at their byte-protocol sections, and TR-CORE-177 anchors
the substrate-authority requirement in the matrix). ADR 0004's "Rust is
the byte authority" claim is unchanged in substance — Rust still wins on
byte disagreement — but the authoritative Rust crates for the primitives
are upstream substrate crates, not Trellis-local crates. Python
generators in `fixtures/vectors/_generator/` remain the dual-impl
cross-check for the Trellis profile composition.

---

## Implications for TODO.md

- ADRs 0001–0003 resolve the **Blocker — this week** section. Replace each
  bullet with a one-line pointer to this doc.
- ADR 0004 resolves the **Architecture fork** section. Remove the fork;
  replace with a pointer: "Dual-impl cross-check is the lock-in; Python
  is not scheduled for retirement."
- G-3's acceptance criterion stays as-is: "byte-exact vectors across
  Rust + Python generators." The allowlist-free coverage matrix stays.
- Phase-1 lint and vector authoring follow **ratified** field names and
  rules in Core (`prev_hash` / `causal_deps`, `anchor_ref` /
  `external_anchors`, `extensions` per §6.7), implemented in
  `scripts/check-specs.py` alongside the fixture corpus.

## Implications for `.claude/vision-model.md`

Synced **2026-04-24**: the Trellis section’s **Format ADRs** bullets now echo
ratified Core field names while preserving ADR intent; the stack-wide doc
is canonical for Q1–Q4 posture. Changelog entry records the sync. Older
line-number notes in pre-2026-04-24 drafts are obsolete.

---

## Validation checklist

Validated by owner signal on 2026-04-20 when dispatch moved from task
construction to execution. Checklist rows below name **ADR acceptance
intent**; ratified Core + the amendment at the top of this file govern
**wire names** and **Phase-1 MUST** text.

- [x] Principles 1–7 match intent under the maximalist directive.
- [x] ADR 0001 (DAG envelope, length-1 runtime) is the correct synthesis
      of "be maximalist" for event topology.
- [x] ADR 0002 (list-form anchor envelope, multi-anchor legal from day 1,
      substrate choice deferred to spike) matches.
- [x] ADR 0003 (§22 + §24 envelope hooks reserved, MUST-NOT-populate at
      Phase 1) is the right reservation scope.
- [x] ADR 0004 (retain Python as cross-check, not retire) is the right
      reading of "maximalist" applied to implementations.
- [x] "Revisit when" triggers on each ADR are the right conditions to
      re-open the decision.
