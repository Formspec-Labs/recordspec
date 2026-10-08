# Controlled writer result: required native members omitted

The current-source native writer executed against the valid committed synthetic export010 chain and stopped with exit 1 at the first missing native member. The original fixture passed structure and integrity verification. The newly written ZIP passed structure verification but failed integrity verification, omitting its 060 presentation payload, 061 attachment catalog and 065 completion-certificate catalog while preserving their registered manifest binding claims.

This is the first actual writer member-carriage RED. It is separate from live head404/custody and does not represent real D1 completion history. Full requested D1 member-set construction stops at this necessary subset; its remaining business/history records and catalogs have not been constructed or qualified.

Exact evidence:

- Native source: `crates/trellis-export-writer/examples/full-member-qualification.rs`, SHA-256 `0317ae9bc322d901b404d90672d6c7e2ba7163c41824f355d3313782ae51fe9b`.
- Actual run receipt: `probes/controlled-native-cached-run-receipt.json`, SHA-256 `ef2763626a0a39a0e36d50be51089858f63125b0d7d834d0e9ae55741a9cb601`.
- Generated controlled ZIP: `probes/controlled-native-output/controlled-writer-output.zip`, SHA-256 `969a421696cfbb44baccb87598281a58625ab57dceac1d8acf2eee64667bbf72`.
- Result JSON: `probes/controlled-native-output/controlled-writer-output.json`, SHA-256 `2cf7a4c82af57d49f44025ea2c5d9102a7faa8caf9bd778b12ca078acec8ca38`.
- Consumed-input guard covers 85 local source files and 49 synthetic fixture files; post-run comparison found no drift. Core's authorized edits were outside the compiled dependency set.

The first command failed before compilation because `--locked` required a lockfile update. An offline-generated transient lock enabled the build; that first cold compile timed out before writer execution. Its process group exited. The cached continuation compiled and executed the probe. All three attempts and both lock snapshots are retained separately, so prerequisites cannot be mistaken for writer evidence.

After native cleanup, the exact starting lockfile SHA-256 `34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b` was restored, preserving its unrelated pre-existing rand_core entry. The final owned process group was absent. The native build window was explicitly handed to Core. No service, accepted source record, case history or live ledger changed.

The smallest proposed owning change is the closed registered evidence-byte input in `registered-member-input-proposal.md`. It reuses `ExportWriterInput`, manifest binding and `integrity_bundle`; it creates no second writer or D1 request format. Independent BEFORE reviews must resolve proposal findings and bind this actual RED before production implementation. No generic writer fix has been implemented yet.

An independently executed maintained Python verifier also reports the generated ZIP as invalid: structure passes, cryptographic integrity fails, and the missing attachment manifest, presentation attachment and certificate catalog block acceptance. Its process exit 0 means the checker completed; it does not mean the archive passed. Receipt: `probes/controlled-python-crosscheck.json`, SHA-256 `2cfb3b84d3bd3d28fbb916d4ce57ae49dd1a37c26694a5519145a0eef7a17758`. The receipt pins the ZIP and Python verifier sources.
