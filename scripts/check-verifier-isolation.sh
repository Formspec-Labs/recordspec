#!/usr/bin/env bash
# Trellis verifier-isolation CI assertion.
#
# Asserts that `integrity-verify`'s dependency graph does NOT include any
# HPKE-or-related crypto crate. The Phase-1 verifier MUST stay free of
# HPKE so an offline core-bytes verify (Core §16 — Verification
# Independence) does not pull in the HPKE / X25519 / AEAD / HKDF
# transitive graph.
#
# Why the sibling-crate architecture rests on this:
#   - `trellis-hpke` is a sibling crate at the same level as
#     `trellis-core` / `trellis-cose`. The boundary is what makes Core
#     §16 enforceable structurally (not just by prose discipline).
#   - A future change to `integrity-cose` that pulls HPKE helpers in as
#     a dep would silently breach the verifier-isolation invariant
#     because every consumer of `integrity-cose` (including
#     `integrity-verify`) would inherit HPKE.
#   - This script is the loud-fail gate: `cargo tree -p integrity-verify`
#     MUST NOT mention `hpke`, `x25519-dalek`, `chacha20poly1305`, or
#     `hkdf`. Run via `make check-verifier-isolation` (Trellis-local)
#     or directly in CI.
#
# Authority:
#   - Core §16 (Verification Independence)
#   - ADR 0009 §"Architectural posture" (sibling-crate boundary)
#   - ADR 0008 §ISC-05 (same hygiene contract for ecosystem libs)
#   - `crates/trellis-hpke/Cargo.toml` `# DO NOT BUMP` block (cites
#     this script as the firewall)

set -euo pipefail

# Resolve the trellis root: this script lives at <root>/scripts/, and
# `cargo tree` resolves the manifest from the workspace root.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The forbidden crates. `trellis-verify` MUST NOT list any of these in
# its dependency tree. ADR 0009 names these exactly.
FORBIDDEN_RE='hpke|x25519-dalek|chacha20poly1305|hkdf'

# Always target Trellis's own workspace manifest directly. The parent
# repository root is *not* guaranteed to expose `integrity-verify` as a
# package ID, which causes `cargo tree -p integrity-verify` to fail before
# we can evaluate forbidden deps.
#
# Test hook: `TRELLIS_MANIFEST_PATH` may override this path in unit tests.
TRELLIS_MANIFEST="${TRELLIS_MANIFEST_PATH:-$ROOT_DIR/Cargo.toml}"

echo "Asserting integrity-verify is HPKE-clean (Core §16; ADR 0009)..."
echo "  manifest: $TRELLIS_MANIFEST"
echo "  forbidden: $FORBIDDEN_RE"

# `cargo tree -p integrity-verify` lists every dep + transitive in the
# graph. We grep for any forbidden crate name; a hit (exit 0) is a
# regression. We invert by treating a hit as failure and absence
# (`grep -E ... || true` returning empty) as success.
#
# Test hook: if `TRELLIS_VERIFY_TREE_OUTPUT_FILE` is set, read the tree
# output from that file rather than invoking cargo.
if [ -n "${TRELLIS_VERIFY_TREE_OUTPUT_FILE:-}" ]; then
    TREE_OUTPUT="$(cat "$TRELLIS_VERIFY_TREE_OUTPUT_FILE")"
else
    TREE_OUTPUT="$(cargo tree -p integrity-verify --edges normal,build,dev --manifest-path "$TRELLIS_MANIFEST" 2>&1)"
fi

# Filter the tree to lines that mention any of the forbidden crates.
# Words may appear in `name vX.Y.Z` form or `(*)` repetition lines;
# either form is a regression.
HITS="$(printf '%s\n' "$TREE_OUTPUT" | grep -E "\b($FORBIDDEN_RE)\b" || true)"

if [ -n "$HITS" ]; then
    echo
    echo "FAIL: integrity-verify dependency graph includes a forbidden HPKE-related crate." >&2
    echo "      Core §16 (Verification Independence) requires the offline verifier path" >&2
    echo "      to not depend on HPKE / X25519 / AEAD / HKDF. ADR 0009 §'Architectural" >&2
    echo "      posture' explains why; the sibling-crate firewall is what enforces it." >&2
    echo >&2
    echo "Hits:" >&2
    printf '%s\n' "$HITS" | sed 's/^/  /' >&2
    echo >&2
    echo "Diagnose: probably a transitive add to trellis-cose or trellis-types pulled" >&2
    echo "an HPKE-related crate into the graph. Move that work into trellis-hpke (or" >&2
    echo "a new sibling crate) and re-run." >&2
    exit 1
fi

echo "OK: integrity-verify is HPKE-clean."
exit 0
