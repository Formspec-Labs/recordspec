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
#   - HPKE wrap/unwrap lives in `integrity-hpke` (integrity-stack), separate from
#     the offline verifier crate graph. That boundary is what makes Core §16
#     enforceable structurally (not just by prose discipline).
#   - A future change to `integrity-cose` that pulls HPKE helpers in as a dep would
#     silently breach the verifier-isolation invariant because every consumer of
#     `integrity-cose` (including `integrity-verify`) would inherit HPKE.
#   - This script is the loud-fail gate: `cargo tree -p integrity-verify`
#     MUST NOT list package lines for `hpke`, `x25519-dalek`, `chacha20poly1305`, or
#     `hkdf`. Run via `make check-verifier-isolation` (Trellis-local)
#     or directly in CI.
#
# Authority:
#   - Core §16 (Verification Independence)
#   - ADR 0009 §"Architectural posture" (sibling-crate boundary)
#   - ADR 0008 §ISC-05 (same hygiene contract for ecosystem libs)
#   - `integrity-stack/crates/integrity-hpke/Cargo.toml` version pins (cites ADR 0009)

set -euo pipefail

# Resolve the trellis root: this script lives at <root>/scripts/, and
# `cargo tree` resolves the manifest from the workspace root.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The forbidden crates. `integrity-verify` MUST NOT list any of these in its
# dependency tree. ADR 0009 names these exactly.
#
# Match only `cargo tree` package lines (`<name> v<semver>`), not substrings inside
# unrelated crate names, and avoid `\b` (not portable across legacy grep).
FORBIDDEN_RE='(^|[[:space:]])(hpke|x25519-dalek|chacha20poly1305|hkdf)[[:space:]]+v[0-9]'

# Always target Trellis's own workspace manifest directly. The parent
# repository root is *not* guaranteed to expose `integrity-verify` as a
# package ID, which causes `cargo tree -p integrity-verify` to fail before
# we can evaluate forbidden deps.
#
# Test hook: `TRELLIS_MANIFEST_PATH` may override this path in unit tests.
TRELLIS_MANIFEST="${TRELLIS_MANIFEST_PATH:-$ROOT_DIR/Cargo.toml}"

echo "Asserting integrity-verify is HPKE-clean (Core §16; ADR 0009)..."
echo "  manifest: $TRELLIS_MANIFEST"
echo "  forbidden package lines: hpke, x25519-dalek, chacha20poly1305, hkdf (name + semver)"

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
    set +e
    TREE_OUTPUT="$(cargo tree -p integrity-verify --edges normal,build,dev --manifest-path "$TRELLIS_MANIFEST" 2>&1)"
    TREE_STATUS=$?
    set -e
    if [ "$TREE_STATUS" -ne 0 ]; then
        echo "FAIL: cargo tree -p integrity-verify exited ${TREE_STATUS} (manifest: ${TRELLIS_MANIFEST})." >&2
        echo "      Core §16 gate could not evaluate the dependency graph. Output:" >&2
        printf '%s\n' "$TREE_OUTPUT" >&2
        exit "$TREE_STATUS"
    fi
fi

# Filter the tree to lines that mention any of the forbidden crates.
# Words may appear in `name vX.Y.Z` form or `(*)` repetition lines;
# either form is a regression.
HITS="$(printf '%s\n' "$TREE_OUTPUT" | grep -E "$FORBIDDEN_RE" || true)"

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
    echo "Diagnose: probably a transitive add to integrity-cose or upstream integrity crates" >&2
    echo "pulled an HPKE-related crate into the graph. Move that work into integrity-hpke" >&2
    echo "(or another non-verifier sibling) and re-run." >&2
    exit 1
fi

echo "OK: integrity-verify is HPKE-clean."
exit 0
