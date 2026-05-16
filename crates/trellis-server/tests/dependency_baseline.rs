//! Trellis DI topology boundary gate (TRELLIS-DI-TOPOLOGY-TODO.md Boundary Gate).
//!
//! This is a deterministic source + manifest scanner that enforces the
//! Trellis-internal injection boundary. Generic Trellis service code must not
//! depend on domain admission vocabulary, Formspec binding/server crates,
//! fixture/conformance/verifier-only crates, and must not derive
//! profile/schema/direct-submit metadata from event-type string prefixes.
//!
//! See `TRELLIS-DI-TOPOLOGY-TODO.md` "Boundary Gate" and "Injection Boundary"
//! sections for the policy. Model patterned on the precedent in
//! `formspec-server/crates/formspec-server/tests/dependency_baseline.rs`.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates whose normal (non-dev) dependency tables must stay free of
/// WOS/Formspec domain vocabulary and admission adapter crates.
const NEUTRAL_CRATES: &[&str] = &[
    "trellis-core",
    "trellis-export-writer",
    "trellis-server-ports",
];

/// Tokens that must not appear under `[dependencies]` of any [`NEUTRAL_CRATES`]
/// manifest. Dev-dependencies are intentionally allowed for fixture-bearing
/// tests inside the same crate.
const FORBIDDEN_NEUTRAL_DEPS: &[&str] = &[
    "wos-events",
    "formspec-trellis-binding",
    "trellis-admission-wos",
    "trellis-admission-formspec",
    "trellis-verify-wos",
    "trellis-conformance",
    "trellis-interop-c2pa",
    "trellis-interop-did",
];

/// Generic `trellis-server` source files that must not import domain admission
/// vocabulary directly. Only `composition.rs` may name the admission adapter
/// crates and `wos-events` re-exports.
const GENERIC_SERVER_FILES: &[&str] = &[
    "src/lib.rs",
    "src/append.rs",
    "src/http.rs",
    "src/state.rs",
    "src/admission.rs",
    "src/artifacts.rs",
    "src/event_repository.rs",
    "src/openapi.rs",
    "src/scope_startup.rs",
];

/// Production code in generic service files must not import these crate roots.
/// Tests (`#[cfg(test)] mod tests { ... }`) may pull them as dev-dependencies.
const FORBIDDEN_PROD_IMPORT_TOKENS: &[&str] = &[
    "use wos_events",
    "use trellis_admission_wos",
    "use trellis_admission_formspec",
    "use formspec_trellis_binding",
];

/// String-prefix dispatch tokens forbidden in generic service code; the
/// admission contract supplies `event_family` / `profile_id` instead.
const FORBIDDEN_PREFIX_DISPATCH_TOKENS: &[&str] = &[
    "starts_with(\"wos.\")",
    "starts_with(\"substrate.append.\")",
];

#[test]
fn neutral_crates_have_no_domain_dependencies() {
    for crate_name in NEUTRAL_CRATES {
        let manifest_path = trellis_root().join("crates").join(crate_name).join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("read {manifest_path:?}: {err}"));
        let deps_section = normal_dependency_section(&manifest);
        for forbidden in FORBIDDEN_NEUTRAL_DEPS {
            assert!(
                !deps_section.contains(forbidden),
                "{crate_name} must not depend on `{forbidden}` (Boundary Gate)"
            );
        }
    }
}

#[test]
fn admission_adapters_do_not_depend_on_each_other() {
    let wos_manifest = read_manifest("trellis-admission-wos");
    let formspec_manifest = read_manifest("trellis-admission-formspec");
    assert!(
        !wos_manifest.contains("trellis-admission-formspec"),
        "trellis-admission-wos must not depend on trellis-admission-formspec (Boundary Gate)"
    );
    assert!(
        !formspec_manifest.contains("trellis-admission-wos"),
        "trellis-admission-formspec must not depend on trellis-admission-wos (Boundary Gate)"
    );
}

#[test]
fn service_client_has_no_formspec_or_admission_dependencies() {
    // D12 permits `trellis-service-client -> wos-events` for the shared WOS
    // typed-helper surface. Formspec ceremony and admission adapters must not
    // appear in the shared client crate.
    let manifest = read_manifest("trellis-service-client");
    let deps_section = normal_dependency_section(&manifest);
    for forbidden in [
        "formspec-trellis-binding",
        "trellis-admission-wos",
        "trellis-admission-formspec",
        "formspec-server",
    ] {
        assert!(
            !deps_section.contains(forbidden),
            "trellis-service-client must not depend on `{forbidden}` (D12 / DI-004)"
        );
    }
}

#[test]
fn generic_server_files_do_not_import_domain_vocabulary_in_production() {
    let server_root = trellis_root().join("crates").join("trellis-server");
    for relative_path in GENERIC_SERVER_FILES {
        let file_path = server_root.join(relative_path);
        let source = fs::read_to_string(&file_path)
            .unwrap_or_else(|err| panic!("read {file_path:?}: {err}"));
        let production_source = strip_test_modules(&source);
        for forbidden in FORBIDDEN_PROD_IMPORT_TOKENS {
            assert!(
                !production_source.contains(forbidden),
                "{relative_path}: production code must not contain `{forbidden}` (Boundary Gate). \
                 Move domain wiring into `composition.rs`."
            );
        }
    }
}

#[test]
fn generic_server_files_do_not_use_prefix_dispatch_for_profile_metadata() {
    let server_root = trellis_root().join("crates").join("trellis-server");
    for relative_path in GENERIC_SERVER_FILES {
        let file_path = server_root.join(relative_path);
        let source = fs::read_to_string(&file_path)
            .unwrap_or_else(|err| panic!("read {file_path:?}: {err}"));
        let production_source = strip_test_modules(&source);
        for forbidden in FORBIDDEN_PREFIX_DISPATCH_TOKENS {
            assert!(
                !production_source.contains(forbidden),
                "{relative_path}: profile/schema/direct-submit dispatch must not match on \
                 event_type prefixes (`{forbidden}`); consult `AdmittedEvent` instead."
            );
        }
    }
}

#[test]
fn neutral_port_crate_does_not_import_domain_vocabulary() {
    let ports_lib = fs::read_to_string(
        trellis_root()
            .join("crates")
            .join("trellis-server-ports")
            .join("src")
            .join("lib.rs"),
    )
    .expect("trellis-server-ports lib.rs");
    let production_source = strip_test_modules(&ports_lib);
    for forbidden in [
        "use wos_events",
        "use trellis_admission",
        "use formspec_",
    ] {
        assert!(
            !production_source.contains(forbidden),
            "trellis-server-ports must not contain `{forbidden}` (Boundary Gate)"
        );
    }
}

/// Returns the dependency block excluding `[dev-dependencies]` / `[build-dependencies]`.
fn normal_dependency_section(manifest: &str) -> String {
    let mut out = String::new();
    let mut in_normal_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_normal_deps = trimmed == "[dependencies]";
            continue;
        }
        if in_normal_deps {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Strips `#[cfg(test)] mod ... { ... }` blocks (using brace counting) so tests
/// may freely pull dev-dependency vocabulary without tripping production scans.
///
/// Walks chars (not bytes) so doc comments containing multibyte characters do
/// not produce a UTF-8 boundary panic.
fn strip_test_modules(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut remaining = source;
    while let Some(start) = remaining.find("#[cfg(test)]") {
        out.push_str(&remaining[..start]);
        let after_marker = &remaining[start..];
        let Some(open_offset) = after_marker.find('{') else {
            // No body found: copy the remainder and stop.
            out.push_str(after_marker);
            return out;
        };
        let body_start = open_offset + 1;
        let mut depth = 1usize;
        let mut closing_index: Option<usize> = None;
        for (offset, ch) in after_marker[body_start..].char_indices() {
            let cursor = body_start + offset + ch.len_utf8();
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        closing_index = Some(cursor);
                        break;
                    }
                }
                _ => {}
            }
        }
        match closing_index {
            Some(end) => {
                remaining = &after_marker[end..];
            }
            None => {
                // Unbalanced braces — drop the rest defensively.
                return out;
            }
        }
    }
    out.push_str(remaining);
    out
}

fn read_manifest(crate_name: &str) -> String {
    let path = trellis_root().join("crates").join(crate_name).join("Cargo.toml");
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {path:?}: {err}"))
}

fn trellis_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("trellis root")
        .to_path_buf()
}
