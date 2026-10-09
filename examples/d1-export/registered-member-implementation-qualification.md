# Registered export member inputs: implementation qualification

Status: all required scoped checks passed: 23 writer tests, three positive native probes, the expected missing-inline refusal, independent Python verification, Clippy, formatting, and the modified server caller compile check. The independent AFTER certificates record final approval against the accompanying exact input pins. No live export, history, custody, creator or disclosure result is established here.

The maintained `ExportWriterInput` gains one closed `evidence_members` list. Six variants cover ciphertext payloads, attachment, signature, intake and completion-certificate catalogs, and open-clock JSON. One preparation path validates fixed paths, uniqueness, ciphertext hash, canonical CBOR array bytes and format-level clock count; it produces existing `BundleEntry` values and registered bindings. A single merge path replaces owned stale bindings from actual bytes. Existing witness, signed-act and policy inputs remain intact. The server initializes the list empty: service member derivation is a separate owning task.

The change reuses the existing Integrity ZIP assembler, canonical CBOR encoder, digest primitives and JSON parser. It adds no dependencies, serializer, archive backend, business-record derivation or permissions. The fixed five-family table centralizes paths and digest keys. This is a local Rust input API change implementing existing wire obligations; it introduces no new normative format or requirement.

The original controlled writer RED and both BEFORE certificates remain historical evidence in local commit `5326fe56eed60918fdc7f7d0ce9c9bbf7ccf25a3`. Its input pins describe that commit, not the implementation now being qualified. Original receipts, outputs and failed prerequisite attempts remain unchanged.

Acceptance checks:

- Existing export001 remains byte-for-byte identical; all writer tests and Clippy pass.
- The same010 native source supplies exact060/061/065 bytes through the new input, changes RED to GREEN and passes independent verification.
- Isolated006 signature and007 intake chains retain their own source events, native catalog bytes and existing066/067/068 inputs. No joined artificial history.
- A010 negative retains the inline attachment claim and061/065 bytes while omitting060; independent verification must report a missing presentation attachment.
- Focused tests cover all fixed catalog paths/digests, certificate reference/count, payload presence/hash, every duplicate family and payload, malformed/unsorted/duplicate-key CBOR, advertised binding without member, unknown extension retention, stale binding replacement, native clock count/digest, signed-count tampering and malformed/noncanonical JSON. Clock tests qualify format/binding, not genuine D1 clock history.
- The modified server input initializer compiles; formatting passes. No service is started or changed.

Writer and initial caller commands ran serially through `probes/run-member-input-qualification.py`; the final minimally repaired caller check used `probes/run-caller-minimal-repair.py`, with bounded timeout, retained logs/receipts, compiled-input/fixture hashes, owned process group cleanup and exact starting lock restoration. Output paths are distinct from the original RED. Retained receipts and nonauthor CODE+ARCH certificates bind the exact implementation and limitations for the scoped local checkpoint.

## Observed native and independent verification

All 23 writer tests pass, including six new focused tests and existing export001 exact ZIP/member parity. Native010 now passes with original060/061/065 bytes; isolated006 and007 pass with all required source member bytes unchanged. Native010 with only060 withheld exits1 and reports the required integrity failure. Python independently reports all three positive ZIPs valid and the missing-inline ZIP invalid with `presentation_artifact_attachment_missing`.

- `writer-tests` receipt SHA-256 `61b9e4f8c3c2b21ef544df6f2abd29c3e86529de55bdb80627534de0d4f69420`: exit 0, owned process group absent, starting lock restored, no source/fixture drift.
- `probe-010` receipt SHA-256 `f8d105e2124eb7b8e95f11c530845737753a73273f5b7c4a87ce2f95de571fe9`: exit 0, owned process group absent, starting lock restored, no source/fixture drift.
- `probe-006` receipt SHA-256 `cc52e82c98e181d5980e8a1c35d1393d77531209d490ec23c6a4b2b019ce9e8b`: exit 0, owned process group absent, starting lock restored, no source/fixture drift.
- `probe-007` receipt SHA-256 `334fe09a12ca6cac7a7e3ea02feeb122cc7cb9ca923e0f500f5414cff40421c1`: exit 0, owned process group absent, starting lock restored, no source/fixture drift.
- `probe-010-missing-inline` receipt SHA-256 `4dc7d2327c9c262fd1e415bd4b59e9149ede45859254d6bd3bb9fa242c8e3731`: exit 1, owned process group absent, starting lock restored, no source/fixture drift.
- `original-python-baselines.json` SHA-256 `1abf3d51ce771648582147d304aff29b1bce6594a9f16ffe617c687cc4db7086`; exact commands, ZIP hashes and verifier source hashes retained.
- `generated-python-verification.json` SHA-256 `66556b3c5ce7df4d360def289608007b9321061fe8070a13ae66ebdf3bc0b00e`; exact commands, ZIP hashes and verifier source hashes retained.

Raw ZIP SHA-256 values identify retained files; they do not replace the domain-separated manifest/checkpoint digests. These synthetic receipts do not establish real D1 source history, custody, agency trust or recipient disclosure authority.

Clippy passed with `--all-targets --features fixture-inputs -- -D warnings`. Receipt SHA-256 `3deeef9015616c14c9cadc78b68435cb5ffb2c1216861613ce082f4fc8a4c6c1`; cleanup, lock restoration and input stability passed.

The first server caller check reached its 300-second bound during dependency checking, before `trellis-server` compilation. Receipt SHA-256 `bd46eeda18b50329c2a06ea16cb13ca4d972ab0ab157c20c12948b3d87385ff4`; exit -15/timeout wrapper124, owned group absent, exact starting lock restored, no source/fixture drift. This is neither a caller compilation pass nor a source failure. The native window is released directly to WOS; a cached continuation requires explicit handoff. All completed writer checks remain qualified on unchanged bytes.

The second 300-second server caller continuation also stopped in dependency checking before compiling `trellis-server`. Receipt SHA-256 `b7608109ab6be66baa801d56e63aabf7f256cd603c2e82904edbf35f61db6411`; PG71624 absent, exact starting lock restored, source/fixture drift empty. The two bounded attempts consumed 600 seconds of dependency checking without an owning caller compile verdict. Both remain retained prerequisites, not source failures or passing checks. Trellis handed the window directly to Core and remains off Cargo pending another explicit grant.


## Final caller qualification and lock diagnosis

The third caller check passed, compiling `trellis-server` in 91 seconds after WOS explicitly released the native window. Receipt SHA-256 `4422ec5d37da2846d71d959b1549eb53f7675b63637bda6910ed063f8a9d5b85`; log `696748bcaba9e44a0170d6993ab4eaafad67591eacca7a0caec2869921cb64f7`. The Cargo-managed minimal repair adds only the existing `async-trait` dependency to `stack-common-auth`'s lock dependency list. Package/version additions, removals and replacements are all empty. The resolved temporary lock SHA-256 is `e8db9355f0959eebb70c3d951168497ae579224fb7d1ee07ab71f4c90e6b8523`; no dependency adoption is part of this change. Future checks use this frozen resolved lock with `--locked`.

The final runner captures explicit non-secret build environment and configuration plus external build-schema and literal include inputs. These expand the earlier caller guards; the earlier attempts did not guard those external bytes or capture historical environment overrides, so their stability claims apply only to their recorded inputs. Final recorded drift is empty. Owned group7300 was independently confirmed absent and the starting lock was restored exactly, including the unrelated `rand_core` line. The immutable third-window summary SHA-256 is `bfa28d140804edc6de2556f07ad7b848635ea791a69632479d2277d6ec0fc6c1`. Trellis directly released the window to Core and remains off Cargo during final read-only review.

The read-only cache diagnosis distinguishes initial broad temporary lock resolution from later cache progress. The two unsuccessful attempts used a broad generated dependency set unchanged between attempts; 49 of the second attempt's53 dependency status lines were new. The final minimal repair preserves every package/version selection. The observed91-second pass establishes this caller check only; it does not establish a general speed improvement. Both failed attempts remain retained evidence.
