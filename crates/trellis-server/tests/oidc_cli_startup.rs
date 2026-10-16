//! Exercises the actual CLI's fail-closed authentication selection.
// Rust guideline compliant 2026-02-21

use std::process::Command;

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trellis-server"));
    command.env_clear().env("TRELLIS_STORAGE", "memory");
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
    let tenant = json!({"tenant":"tenant-a","workspace":"workspace-a","environment":"environment-a","cell":"cell-a"});
    private(&profile, &serde_json::to_vec(&json!({
        "issuer":"https://issuer.example/realm", "audience":"trellis-api", "requiredScopes":["trellis.access"],
        "allowedClients":["producer"], "profile":"keycloak", "introspectionEndpoint":"https://issuer.example/introspect",
        "introspectionClientId":"introspection", "introspectionClientSecretFile":"secret", "grantsFile":"grants.json",
        "tenantScope":tenant, "identities":[{"issuer":"https://issuer.example/realm","subject":"producer","clientId":"producer","principal":"producer"}],
        "actionScopes":{"read":"trellis.read","append":"trellis.append","administer":"trellis.administer"}
    })).unwrap());
    private(
        &directory.path().join("secret"),
        b"private-test-only-secret",
    );
    private(
        &directory.path().join("grants.json"),
        &serde_json::to_vec(&json!({"tenantScope":tenant,"grants":[]})).unwrap(),
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
