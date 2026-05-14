# ADR 0011 — `profile_id` Value Sub-Registry

**Status:** Accepted 2026-05-13

## Context

Trellis Core already assigns the COSE protected-header label `-65539` to `profile_id`, but the spec did not yet define the value registry carried under that label. UWU-1 in `formspec-stack/thoughts/archive/plans/2026-05-12-integrity-stack-case-boundary-refactor.md` Phase 9 allocates the Formspec authored-signature profile value, and the verifier dispatcher needs a canonical registry home.

## Decision

1. Trellis Core §26.2.1 is the canonical `profile_id` value sub-registry.
2. Values are sequential `u64` allocations starting at 1.
3. Allocated values at this decision:
   - `1` = WOS workflow event.
   - `2` = Formspec authored signature.
4. The stack-root `thoughts/registries/profile-ids.md` file is a coordination mirror only.

## Consequences

- `integrity-verify::profile` declares constants for allocated stack profiles.
- Formspec Core §2.1.6 names value `2` distinctly from protected-header label `-65539`.
- Future profile allocations update this ADR family, Trellis §26.2.1, and the stack-root mirror together.

## References

- `formspec-stack/thoughts/archive/plans/2026-05-12-integrity-stack-case-boundary-refactor.md` Phase 9 UWU-1.
- `formspec-stack/thoughts/registries/profile-ids.md`.
- `formspec-stack/thoughts/adr/0087-formspec-cose-sign1-universal-wire.md`.
