# Service-assembled export, eight events

The maintained Rust test `exports_assembled_at_five_and_eight_events_verify` (trellis-service-core) generated these retained bytes with `TRELLIS_ASSEMBLED_EXPORT_VECTOR_DIR` set to a new private output directory. It appends 8 controlled `wos.kernel.case_created` events through the reference server, each checkpoint issued from the previous checkpoint's stored frontier, and fetches the export pinned at the head checkpoint through `GET /v1/scopes/{scope}/bundles/{checkpointDigest}`, which runs `export::assemble`. The test verifies the archive with the maintained WOS resolver before retaining it. Event timestamps are the generating run's; replay from these committed bytes is deterministic.

The tree sizes cover both Merkle shapes the frontier handles: five events leave a three-peak-free partial right edge (one perfect subtree of four plus one leaf), eight a single perfect tree. Core fixture key `issuer-001` is public development material and establishes no operator authority.

These are byte/protocol fixtures: the Rust writer and verifier legs replay them in `trellis-conformance`, and `trellis-py` verifies the same ZIPs in the `substrate-export-verifier` parity gate. Companion §18.5a's determinism holds for a fixed signing configuration.
