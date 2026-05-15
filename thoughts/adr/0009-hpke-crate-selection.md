# ADR 0009 — HPKE Crate Selection

**Date:** 2026-04-24 (selection); promoted to ADR 2026-04-27 (Wave 18).
**Status:** Accepted; implementation landed Wave 16, hardened Wave 18.
**Supersedes:** [`thoughts/specs/2026-04-24-hpke-crate-spike.md`](../specs/2026-04-24-hpke-crate-spike.md) (kept as non-normative archive pointer).
**Superseded by:** —
**Related:** ADR 0001 (Phase-1 MVP principles — pure-Rust dep posture); ADR 0004 (Rust is byte authority — RFC 9180 conformance proven by `append/004` byte equality, not by branded library agreement); Core §9.4 (HPKE suite 1: RFC 9180 Base mode, X25519-HKDF-SHA256-ChaCha20Poly1305); Core §16 (verification independence — `integrity-verify` MUST NOT pull HPKE deps); ADR 0008 §ISC-05 (sibling-crate isolation discipline — same architectural pattern); `thoughts/specs/2026-04-24-anchor-substrate-spike.md` (sibling spike on adapter-tier substrates).

## Decision

Adopt the [`hpke`](https://github.com/rozbb/rust-hpke) crate (published on crates.io as `hpke`, repo `rozbb/rust-hpke`) for the Trellis HPKE wrap/unwrap path. Pin to a single exact version in `integrity-stack/crates/integrity-hpke/Cargo.toml`; pin every transitive crypto dep that drives byte-equal reproducibility for `append/004-hpke-wrapped-inline` (the byte oracle) at the resolved versions. Implementation lives in a sibling `integrity-hpke` crate — never in `trellis-core` or `integrity-cose` — so the dep graph cannot reach `integrity-verify` (Core §16 verification independence).

Pinned deps as of Wave 16 + 18:

| Crate | Pin |
|---|---|
| `hpke` | `=0.13.0` |
| `chacha20poly1305` | `=0.10.1` |
| `hkdf` | `=0.12.4` |
| `x25519-dalek` | `=2.0.1` |
| `sha2` | `=0.10.9` |
| `rand_core` | `=0.9.5` |

The fixture-only `wrap_dek_with_pinned_ephemeral` API — required for byte-exact reproduction of `append/004` — sits behind a `test-vectors` Cargo feature (default off). Production crate-graphs cannot link the carve-out path even by mistake.

The verifier-isolation invariant is asserted by `scripts/check-verifier-isolation.sh` (CI-runnable; `make check-verifier-isolation`). `cargo tree -p integrity-verify` (workspace manifest: `trellis/Cargo.toml`) MUST NOT list package lines for `hpke`, `x25519-dalek`, `chacha20poly1305`, or `hkdf`.

## Context

Core §9.4 pins the HPKE suite to X25519-HKDF-SHA256-ChaCha20Poly1305 (RFC 9180 KEM ID `0x0020`, KDF ID `0x0001`, AEAD ID `0x0003`) and specifies per-`KeyBagEntry` ephemeral freshness. `append/004-hpke-wrapped-inline` exists as the byte-exact reference vector; its bytes were authored with real HPKE via the inline RFC 9180 Base implementation in `fixtures/vectors/_generator/gen_append_004.py`. G-5 closed with `trellis-py` matching every committed vector byte-for-byte, but until Wave 16 the Rust reference implementation round-tripped `append/004` HPKE fields without performing the crypto work. The sequence-item closing that asymmetry is the work this ADR governs.

Until the Rust HPKE path landed, the G-5 stranger-test claim weakened on every new HPKE-using vector: vectors matched because bytes matched, not because both implementations independently derived them.

## Options considered

### Option 1 — `hpke` (rozbb/rust-hpke) — **selected**

- Pure Rust, no C deps. Apache-2.0 / MIT dual license.
- Implements RFC 9180 Base, Auth, PSK, AuthPSK modes. Phase-1 needs only Base.
- Supports the exact Trellis suite: X25519, HKDF-SHA256, ChaCha20Poly1305.
- Actively maintained; last release within the freshness window for production crypto libraries.
- Used in production in several ECH (Encrypted Client Hello for TLS 1.3) and MLS-adjacent implementations.
- `no_std` friendly — leaves the door open without committing.
- Clean `Serializable`/`Deserializable` traits over ephemeral pubkeys, encapsulated keys, and AEAD ciphertexts. Single-shot API (`single_shot_seal_in_place_detached` / `single_shot_open_in_place_detached`) matches per-`KeyBagEntry` usage exactly.

### Option 2 — `hpke-rs` (franziskuskiefer/hpke-rs)

- Pure Rust, MPL-2.0.
- More generic backend abstraction (can swap crypto providers).
- Less directly aligned with the single fixed suite; the abstraction tax buys flexibility we don't need.
- Used in OpenMLS.

### Option 3 — hand-rolled

- We already hand-roll COSE_Sign1 in `trellis-cose` (stricter-than-coset discipline). Hand-rolling HPKE is also achievable — RFC 9180 §5–6 pin the construction fully.
- Rejected: HPKE involves KDF expansion, HPKE context construction, AEAD key derivation, and nonce sequence management. Five more surfaces for subtle byte bugs than COSE_Sign1 has. The stranger test catches divergence but hand-rolling invites it.
- Keep as a fallback if the selected crate develops a blocking issue.

## Rationale

- **Byte-match risk minimization.** The `hpke` crate name on crates.io is unrelated to any PyPI package name collision — only RFC 9180 semantics matter. Phase 1 suite 1 pins empty `info` and empty wrap `aad` (Core §9.4); the oracle is the committed fixture plus the generator's inline RFC implementation. The Rust crate is a second RFC-backed implementation; divergence surfaces as failing the `append/004` integration test or a spec clarification, not as a "same branded library on both sides" guarantee.
- **Single-suite fit.** We pin exactly one ciphersuite in Phase 1. Option 1's API surface covers this without leaving unused knobs exposed.
- **Dependency weight.** Pure Rust, no OpenSSL, no `ring`. Fits the existing `trellis-core` / `trellis-cose` posture.
- **Maintenance trajectory.** The crate has steady maintenance and an active issue tracker. Not abandonware.
- **PQ-suite migration path.** The crate has KEM-generic traits; if Phase-2+ ever uses a PQ HPKE suite (Kyber-based, per `suite_id` registry reservation), the same API shape applies.

## Architectural posture

### Sibling crate, not embedded in core

`trellis-hpke` / `integrity-hpke` is a sibling crate at the same architectural tier as `trellis-core` / `integrity-cose`. Reasoning:

1. **Verification independence.** `integrity-verify` depends on `integrity-cose` and stack types; it MUST NOT depend on HPKE. Sibling-crate isolation makes the boundary structural — `cargo tree -p integrity-verify` is the assertion. ADR 0008 §ISC-05 enforces the same pattern for ecosystem libraries; HPKE follows the same hygiene contract because Core §16 forbids HPKE deps from leaking into the offline verifier path.
2. **Smaller blast radius on bumps.** A `hpke = "=0.13.0"` → `=0.14.0` pin bump touches only `integrity-hpke` and crates that explicitly depend on it; `integrity-cose` and below stay unaffected.
3. **CI assertion target.** `scripts/check-verifier-isolation.sh` runs a single `cargo tree -p integrity-verify` filter check. The sibling-crate boundary is what makes that assertion possible to write at all.

### Test-vector carve-out path

Suite 1 inputs (Core §9.4, `append/004` derivation): `SetupBaseS` / `Seal` with `info = h''` and wrap `aad = h''`. A future suite MAY define non-empty `info` or `aad`; keep parameters on the API so callers are not hard-wired to empty only, but Phase 1 production paths pass empty slices for both.

Wire shape: `KeyBagEntry.wrapped_dek` is the single AEAD ciphertext **concatenated with** the 16-byte Poly1305 tag. Callers assembling CBOR join those two; `unwrap_dek` accepts the wire `wrapped_dek` as one slice and splits internally for `single_shot_open_in_place_detached`.

Three call shapes:

```rust
// Production seal.
pub fn wrap_dek(
    recipient_pubkey: &[u8; 32],
    dek_plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<WrapResult, HpkeError>;

// Production / verifier open.
pub fn unwrap_dek(
    recipient_privkey: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    wrapped_dek: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError>;

// FIXTURE ONLY — gated behind the `test-vectors` Cargo feature.
// Production paths MUST NOT call this.
#[cfg(feature = "test-vectors")]
pub fn wrap_dek_with_pinned_ephemeral(
    recipient_pubkey: &[u8; 32],
    ephemeral_privkey: &[u8; 32],
    dek_plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<WrapResult, HpkeError>;
```

`wrap_dek_with_pinned_ephemeral` bypasses `hpke::setup_sender` (which always derives the ephemeral via DeriveKeyPair on fresh randomness, RFC 9180 §7.1) and reaches the lower-level public KDF helpers (`labeled_extract`, `extract_and_expand`) plus `x25519-dalek` + `chacha20poly1305` directly — the only way to feed a raw 32-byte X25519 scalar as the ephemeral, which is the carve-out shape the Python generator and the committed fixture commit to.

Three of those KDF helpers are `#[doc(hidden)]` but `pub` in `hpke 0.13.0`. Treating them as load-bearing surface IS a risk; the mitigations are: (a) `=`-pin `hpke`; (b) the `# DO NOT BUMP` comment block in `Cargo.toml` calling out the helpers by name; (c) the byte-oracle test (`tests/append_004_byte_match.rs`) which fails loudly if a future bump silently changes their behavior; (d) this ADR's lifecycle clause requiring a re-read on every bump.

The receiver side is unchanged — `setup_receiver` (per `unwrap_dek`) reproduces the same shared secret from `enc + sk_recip` regardless of how the sender chose `sk_eph`.

## Out of scope

- Multi-recipient wrap. Trellis invariant is per-`KeyBagEntry` single-recipient; Base mode is correct.
- PSK / Auth / AuthPSK modes. Phase-1 suite does not use them.
- `no_std` compilation. Keep the option open but don't commit.
- Key-encapsulation caching / pooling. Each wrap uses a fresh ephemeral; no caching.

## Verification approach

1. Import the crate at the pinned version. Pin all five transitive crypto deps (`chacha20poly1305`, `hkdf`, `x25519-dalek`, `sha2`, `rand_core`) at the exact resolved versions. Document each pin in this ADR + the `Cargo.toml` `# DO NOT BUMP` comment.
2. Implement `wrap_dek_with_pinned_ephemeral` first (matches the test-vector carve-out).
3. Integration test (`integrity-stack/crates/integrity-hpke/tests/append_004_byte_match.rs`): feed `append/004-hpke-wrapped-inline`'s pinned recipient pubkey + pinned ephemeral privkey + DEK plaintext + empty `info` and empty wrap `aad` (suite 1) through `wrap_dek_with_pinned_ephemeral`; assert output `ephemeral_pubkey` + `ciphertext` + `aead_tag` concatenated byte-match `KeyBagEntry.wrapped_dek` in the committed vector.
4. Once the test-vector path matches, implement `wrap_dek` (real ephemeral generation) + one round-trip test.
5. Gate the carve-out path behind `--features test-vectors` so production binaries cannot link it.
6. CI assertion (`scripts/check-verifier-isolation.sh` + `make check-verifier-isolation`): `cargo tree -p integrity-verify` does not list package lines for `hpke`, `x25519-dalek`, `chacha20poly1305`, or `hkdf`.

## Risk

- **Crate abandonment or breaking change.** Primary mitigation: `=`-pin in `Cargo.toml`. Secondary: the `# DO NOT BUMP` comment block names the `#[doc(hidden)]` symbols (`labeled_extract`, `extract_and_expand`, `LabeledExpand`) the carve-out leans on. Fallback: Option 3 (hand-roll) — a 1-week spike using RFC 9180 directly; the integration test corpus stays the same.
- **`#[doc(hidden)]` API drift.** `wrap_dek_with_pinned_ephemeral` reaches into `hpke::kdf::{labeled_extract, extract_and_expand, LabeledExpand}` (all `#[doc(hidden)]` but `pub`). A minor-version bump of `hpke` may make these symbols private. The byte-oracle test fails loudly in that case; the §Lifecycle clause below requires this ADR to be re-read on every bump.
- **RFC-compliance divergence.** The Rust `hpke` crate, the inline generator (`gen_append_004.py`), and any future third-party HPKE library used in CI are independent implementations of the same RFC. A real divergence is an RFC-compliance bug in one path or a spec ambiguity. Discovery surface: the `append/004` Rust integration test (and regeneration checks against the generator) fail; resolution is spec clarification and/or upstream issue.
- **PQ migration.** Not a current risk. When Phase-2+ adds a PQ HPKE suite, the crate's trait-generic design supports adding it; separate implementation work.
- **Test-vector feature getting silently enabled in a release build.** `default = []` for the feature; the `# DO NOT BUMP` comment names the discipline; CI assertion would flag downstream consumers that enable `test-vectors` in production via the verifier-isolation check (because `chacha20poly1305` / `x25519-dalek` would re-enter the graph on consumers that pull `integrity-hpke --features test-vectors`).

## Lifecycle

Promote-on-bump: any version bump of `hpke`, `chacha20poly1305`, `hkdf`, `x25519-dalek`, `sha2`, or `rand_core` MUST trigger a re-read of this ADR and an entry in §"Decision log" below. The byte-oracle test (`tests/append_004_byte_match.rs`) is the load-bearing canary; if it stays green after a bump, the bump is acceptable; if it goes red, the bump is rejected pending a deeper investigation.

The non-normative spike doc (`thoughts/specs/2026-04-24-hpke-crate-spike.md`) is preserved as historical context. Cite this ADR — never the spike — for normative HPKE crate-selection authority going forward.

## Follow-ons triggered

- **HPKE duplicate-ephemeral detection lint** — closed Wave 17 as `scripts/check-specs.py` rule R17. Walks the committed key-bag entries across a ledger scope and verifies ephemeral-pubkey uniqueness.
- **Verifier-isolation CI assertion** — landed Wave 18 as `scripts/check-verifier-isolation.sh` + `make check-verifier-isolation`.
- **`§8.6 / §9.4` alignment** — a verifier reading §9.4 who also verifies LAK rotation chains enforces the `unique per wrap` constraint against actual Rust wrap output.

## Decision log

- **2026-04-24** — Selected `hpke` (rozbb/rust-hpke). Rationale §"Rationale" above.
- **2026-04-27 (Wave 16)** — Executed against TODO item #2 (post-Wave-15 renumber). Pinned `hpke = "=0.13.0"` (latest stable), not `0.14.0-pre.2` — the pre-release pulls in `sha3 0.11.0-rc.7` whose `keccak::p1600` API drift breaks the build chain. Crate selection is what is load-bearing; the pinned version is a solvable downstream concern. Landed in a new `trellis-hpke` sibling crate (not in `trellis-core` / `trellis-cose`) to preserve Core §16 verification independence — `trellis-verify`'s dep tree does not pull HPKE crypto crates. The fixture-only `wrap_dek_with_pinned_ephemeral` path bypasses `hpke::setup_sender` and reaches the lower-level public KDF helpers + `x25519-dalek` + `chacha20poly1305` directly. Production `wrap_dek` and `unwrap_dek` go through `hpke`'s RFC-blessed public API.
- **2026-04-27 (Wave 18)** — Hardening from Wave 16 review. (a) `=`-pinned all five transitive crypto deps at the resolved versions. (b) Added `# DO NOT BUMP` comment block in `Cargo.toml` adjacent to the `=0.13.0` `hpke` pin. (c) `wrap_dek_with_pinned_ephemeral` and the related fixture-only KDF / X25519 / AEAD imports now sit behind a `test-vectors` Cargo feature (default off); production crate-graphs cannot link the carve-out path. (d) Promoted the 2026-04-24 spike to this ADR. (e) Landed `scripts/check-verifier-isolation.sh` + `make check-verifier-isolation` as a CI assertion that `cargo tree -p trellis-verify` stays HPKE-clean (package ID later retargeted to `integrity-verify` — see 2026-05-15 entry).
- **2026-05-15 (TWREF-039)** — Delete-surface hygiene: removed `trellis-verify` / `trellis-hpke` workspace packages; HPKE implementation lives under `integrity-stack/crates/integrity-hpke`, offline verifier under `integrity-stack/crates/integrity-verify`. Verifier-isolation gate now runs `cargo tree -p integrity-verify` against `trellis/Cargo.toml` (path dependency into integrity-stack).

---

*End of ADR. Implementation: `integrity-stack/crates/integrity-hpke/`. Byte oracle: `integrity-stack/crates/integrity-hpke/tests/append_004_byte_match.rs`. Carve-out fixture: `fixtures/vectors/append/004-hpke-wrapped-inline/`. CI assertion: `scripts/check-verifier-isolation.sh` (`cargo tree -p integrity-verify`).*
