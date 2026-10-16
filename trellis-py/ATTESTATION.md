# G-5 independence attestation

**Role:** Second implementor (Python) for Trellis Phase-1 vector conformance.

**Allowed inputs:** Only paths listed in `ALLOWED-READ-MANIFEST.txt` (and normative references cited from those specs).

**Forbidden inputs:** `crates/`, `fixtures/vectors/_generator/`, `thoughts/`, `ratification/`, `scripts/`, repo `README.md` except `fixtures/vectors/README.md`, prior implementation excerpts, or generator-derived hints.

**Independence:** The G-5 core (append, verify, export, as of the closing run below) was written from a clean-room thread that read only the allowed inputs above and was not transcribed from the Rust sources. That claim covers the code that existed at that run. Later additions were not clean-room: many carry "Mirrors Rust ..." docstrings because they were ported after Rust implemented them, and the certificate-of-completion v2 and operator-authority-status work (ADR 0016) was written against the Core and ADR text with the parity gate as feedback. Treat those paths as a second implementation checked by the parity gate, not as independent derivations.

**Byte match:** The clean-room conformance run against `fixtures/vectors/` produced `BYTE-MATCH-REPORT.json` with `total_vectors = 63` and `failed = 0`. (The corpus has grown from the G-5 close-out count of 45 as subsequent adopter work added vectors; the stranger implementation tracks Rust byte-for-byte on every added vector.)

**Discrepancies:** `DISCREPANCY-LOG.txt` records no spec or vector discrepancies for the closing run.

**G-O-5 re-close 2026-04-23.** G-O-5 was retroactively reopened in the ratification checklist on 2026-04-23 after the design-doc audit surfaced that `trellis-verify`'s `decode_transition_details` handled only custody-model posture transitions. The Rust fix extended the decoder to `trellis.disclosure-profile-transition.v1` and added a parallel `shadow_disclosure_profile` baseline; the Python stranger (this package) mirrored the fix; `tamper/016-disclosure-profile-from-mismatch` is the new negative oracle. Both implementations now exercise both transition axes symmetrically; the updated byte-match report above covers the new vector.
