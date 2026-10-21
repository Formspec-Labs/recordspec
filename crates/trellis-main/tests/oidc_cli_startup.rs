//! Exercises the actual CLI's fail-closed authentication selection.
// Rust guideline compliant 2026-02-21

use std::process::Command;

/// The deployment file every start reads first: one scope in `cell-a`.
static DEPLOYMENT: std::sync::LazyLock<tempfile::TempDir> = std::sync::LazyLock::new(|| {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("deployment.json"),
        br#"{"cell":"cell-a","scopes":[{"tenant":"acme","workspace":"benefits","environment":"prod"}]}"#,
    )
    .unwrap();
    directory
});

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trellis-server"));
    command.env_clear().env("TRELLIS_STORAGE", "memory").env(
        "TRELLIS_DEPLOYMENT_FILE",
        DEPLOYMENT.path().join("deployment.json"),
    );
    command
}

#[cfg(unix)]
fn private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
#[test]
fn oidc_cli_refuses_partial_completion_before_signing_key_or_storage() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    private(&profile, &serde_json::to_vec(&json!({
        "issuer":"https://issuer.example/realm", "audience":"trellis-api", "requiredScopes":["trellis.access"],
        "allowedClients":["producer"], "profile":"keycloak", "introspectionEndpoint":"https://issuer.example/introspect",
        "introspectionClientId":"introspection", "introspectionClientSecretFile":"secret", "grantsFile":"grants.json",
        "identities":[{"issuer":"https://issuer.example/realm","subject":"producer","clientId":"producer","principal":"producer"}],
        "actionScopes":{"read":"trellis.read","append":"trellis.append","administer":"trellis.administer"}
    })).unwrap());
    private(
        &directory.path().join("secret"),
        b"private-test-only-secret",
    );
    private(
        &directory.path().join("grants.json"),
        &serde_json::to_vec(&json!({"grants":[]})).unwrap(),
    );
    for setting in [
        "TRELLIS_SOURCE_CONTENT_CONFIG_FILE",
        "TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE",
    ] {
        let output = cli()
            .env("TRELLIS_OIDC_CONFIG_FILE", &profile)
            .env(setting, "/public-test-missing-completion.json")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("completion startup configuration is invalid"),
            "{error}"
        );
        assert!(!error.contains("TRELLIS_SIGNING_KEY_COSE_PATH"));
    }
}

#[test]
fn oidc_cli_requires_profile_before_signing_key_or_storage() {
    let output = cli().output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("TRELLIS_OIDC_CONFIG_FILE"), "{error}");
    assert!(!error.contains("TRELLIS_SIGNING_KEY_COSE_PATH"));
}

#[test]
fn oidc_cli_legacy_flags_cannot_supply_missing_current_authority() {
    let output = cli()
        .env("TRELLIS_PERMISSIVE_SCOPE_AUTH", "1")
        .env("TRELLIS_JWT_HS256_SECRET", "public-test-only-legacy-secret")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("TRELLIS_OIDC_CONFIG_FILE"), "{error}");
}

#[test]
fn oidc_cli_refuses_each_legacy_setting_before_opening_profile_or_storage() {
    for setting in ["TRELLIS_PERMISSIVE_SCOPE_AUTH", "TRELLIS_JWT_HS256_SECRET"] {
        for value in ["", "public-test-only-value"] {
            let output = cli()
                .env(
                    "TRELLIS_OIDC_CONFIG_FILE",
                    "/public-test-missing-profile.json",
                )
                .env(setting, value)
                .output()
                .unwrap();
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("refuses legacy authentication settings"),
                "{error}"
            );
            assert!(!error.contains("TRELLIS_SIGNING_KEY_COSE_PATH"));
        }
    }
}

#[test]
fn a_start_without_a_deployment_file_is_refused_before_anything_else() {
    let output = cli()
        .env_remove("TRELLIS_DEPLOYMENT_FILE")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("TRELLIS_DEPLOYMENT_FILE"), "{error}");
}

/// `config-check` reads the configuration serve reads, prints each scope's key and opens nothing.
#[cfg(unix)]
#[test]
fn config_check_prints_the_scope_key_map_without_opening_storage() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    private(&profile, &serde_json::to_vec(&serde_json::json!({
        "issuer":"https://issuer.example/realm", "audience":"trellis-api", "requiredScopes":["trellis.access"],
        "allowedClients":["producer"], "profile":"keycloak", "introspectionEndpoint":"https://issuer.example/introspect",
        "introspectionClientId":"introspection", "introspectionClientSecretFile":"secret", "grantsFile":"grants.json",
        "identities":[{"issuer":"https://issuer.example/realm","subject":"producer","clientId":"producer","principal":"producer"}],
        "actionScopes":{"read":"trellis.read","append":"trellis.append","administer":"trellis.administer"}
    })).unwrap());
    private(
        &directory.path().join("secret"),
        b"private-test-only-secret",
    );
    private(&directory.path().join("grants.json"), br#"{"grants":[]}"#);
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/vectors/_keys/issuer-001.cose_key"
    );
    let check = |profile_name: &str| {
        cli()
            .arg("config-check")
            .env("TRELLIS_OIDC_CONFIG_FILE", &profile)
            .env("TRELLIS_SIGNING_KEY_COSE_PATH", key)
            .env("TRELLIS_PROFILE", profile_name)
            .output()
            .unwrap()
    };
    let development = check("development");
    let printed = String::from_utf8_lossy(&development.stdout);
    assert!(
        development.status.success(),
        "{}",
        String::from_utf8_lossy(&development.stderr)
    );
    assert!(printed.contains("scope acme/benefits/prod "), "{printed}");
    assert!(printed.contains("cell cell-a"), "{printed}");
    // Production refuses this start (a world-readable fixture key, in-memory storage); the
    // signing-purpose rule itself is pinned in trellis-service-core's posture tests.
    let production = check("production");
    assert!(!production.status.success());
}

/// `migrate` holds the owner credential and the serving role's name, nothing else: it reads no
/// signing key, OIDC profile or serving URL, and without the owner's URL it refuses before
/// connecting anywhere.
#[test]
fn migrate_needs_only_the_deployment_the_role_name_and_the_owner_url() {
    let output = cli()
        .arg("migrate")
        .env("TRELLIS_APP_ROLE", "trellis_app")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TRELLIS_MIGRATION_DATABASE_URL is required"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_validates_startup_and_records_the_cell_without_serving() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    private(
        &profile,
        &serde_json::to_vec(&serde_json::json!({
            "issuer":"https://issuer.example/realm", "audience":"trellis-api", "requiredScopes":["trellis.access"],
            "allowedClients":["producer"], "profile":"keycloak", "introspectionEndpoint":"https://issuer.example/introspect",
            "introspectionClientId":"introspection", "introspectionClientSecretFile":"secret", "grantsFile":"grants.json",
            "identities":[{"issuer":"https://issuer.example/realm","subject":"producer","clientId":"producer","principal":"producer"}],
            "actionScopes":{"read":"trellis.read","append":"trellis.append","administer":"trellis.administer"}
        }))
        .unwrap(),
    );
    private(
        &directory.path().join("secret"),
        b"private-test-only-secret",
    );
    private(&directory.path().join("grants.json"), br#"{"grants":[]}"#);
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/vectors/_keys/issuer-001.cose_key"
    );
    let output = cli()
        .arg("bootstrap")
        .env("TRELLIS_OIDC_CONFIG_FILE", &profile)
        .env("TRELLIS_SIGNING_KEY_COSE_PATH", key)
        .env("TRELLIS_PROFILE", "development")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("trellis bootstrap ok for cell cell-a"),
        "{stdout}"
    );
}
