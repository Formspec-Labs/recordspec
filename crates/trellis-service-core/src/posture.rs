//! Startup posture for a Trellis server: what a production profile refuses.
//!
//! The rules live in `stack-common-posture`; this module reads the profile (production unless
//! `TRELLIS_PROFILE=development`) and feeds the rules this server's settings. The development profile
//! accepts fixture keys and in-memory storage so tests and local runs keep working.

use stack_common_error::StackError;
use stack_common_posture::{Profile, Refusals};

use crate::ServerSigningKey;

/// Key ids (hex of the 16-byte `kid` derived from the public key) of every key the parser accepts
/// under `fixtures/vectors/_keys/` (the recipient keys parse as signing keys too, so they are
/// listed). The private halves are public, so no export they
/// sign proves anything. `every_fixture_signing_key_is_listed` keeps this list complete.
const FIXTURE_SIGNING_KEY_KIDS: &[&str] = &[
    "af9dff525391faa75c8e8da4808b1743", // issuer-001 (the key compose mounts for development)
    "3d05ee9ced8f29b60ef84b17d4712e24", // issuer-002
    "55bb0204b910f5f881fd79b2637ee7eb", // attestation-authority-cm-b-001
    "dc34f22009fea53dfcff9b83750c23f4", // recipient-004-ledger-service
    "e1e0168ef446e127dd4237559a5ce851", // ephemeral-004-recipient-001
    "187d7d88b4366300a6571bb5447acca5", // ephemeral-041-recipient-001
    "b6d2352f6a28c81ad62e4e455405e31d", // ephemeral-042-recipient-001
];

/// Reads `TRELLIS_PROFILE` (production unless it says `development`).
pub(crate) fn profile_from_env() -> Result<Profile, StackError> {
    Profile::from_setting(
        "TRELLIS_PROFILE",
        std::env::var("TRELLIS_PROFILE").ok().as_deref(),
    )
    .map_err(StackError::bad_request)
}

/// Reads the signing key. Production takes it only from an owner-only file (like WOS's grant keys),
/// since committed fixture keys are world-readable; development reads any file.
pub(crate) fn read_signing_key(profile: Profile, path: &str) -> Result<Vec<u8>, StackError> {
    let read = if profile.is_production() {
        stack_common_private_file::read_private_file(
            std::path::Path::new(path),
            SIGNING_KEY_MAX_BYTES,
            stack_common_private_file::PrivateAccess::OwnerOnly,
        )
        .map_err(|error| error.to_string())
    } else {
        std::fs::read(path).map_err(|error| error.to_string())
    };
    read.map_err(|error| {
        StackError::bad_request(format!(
            "failed to read TRELLIS_SIGNING_KEY_COSE_PATH: {error}"
        ))
    })
}

const SIGNING_KEY_MAX_BYTES: u64 = 4096;

/// Refuses a production start on in-memory storage or a publicly known signing key.
pub(crate) fn check(
    profile: Profile,
    storage_is_memory: bool,
    signing_key: &ServerSigningKey,
) -> Result<(), StackError> {
    if !profile.is_production() {
        return Ok(());
    }
    let mut refusals = Refusals::new();
    refusals.durable_storage("TRELLIS_STORAGE=memory", storage_is_memory);
    refusals.not_a_known_key(
        "TRELLIS_SIGNING_KEY_COSE_PATH",
        &signing_key.kid_hex(),
        FIXTURE_SIGNING_KEY_KIDS,
    );
    refusals
        .finish("trellis production config")
        .map_err(|refused| StackError::bad_request(refused.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrellisTimestamp;

    const KEYS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/vectors/_keys");

    fn fixture_signing_keys() -> Vec<(String, ServerSigningKey)> {
        std::fs::read_dir(KEYS)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "cose_key"))
            .filter_map(|path| {
                let bytes = std::fs::read(&path).unwrap();
                let key = ServerSigningKey::from_cose_key_bytes(
                    bytes,
                    TrellisTimestamp::new(0, 0).unwrap(),
                )
                .ok()?;
                Some((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    key,
                ))
            })
            .collect()
    }

    #[test]
    fn every_fixture_signing_key_is_listed() {
        let keys = fixture_signing_keys();
        assert!(
            keys.len() >= 2,
            "expected the fixture issuer keys, found {}",
            keys.len()
        );
        let missing: Vec<String> = keys
            .iter()
            .filter(|(_, key)| !FIXTURE_SIGNING_KEY_KIDS.contains(&key.kid_hex().as_str()))
            .map(|(name, key)| format!("{name} (kid {})", key.kid_hex()))
            .collect();
        assert!(
            missing.is_empty(),
            "add to FIXTURE_SIGNING_KEY_KIDS: {}",
            missing.join(", ")
        );
    }

    #[test]
    fn production_refuses_the_fixture_signing_key() {
        for (name, key) in fixture_signing_keys() {
            let error = check(Profile::Production, false, &key)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("publicly known fixture key"),
                "{name}: {error}"
            );
            check(Profile::Development, true, &key)
                .unwrap_or_else(|e| panic!("{name}: dev must accept: {e}"));
        }
    }

    #[test]
    #[cfg(unix)]
    fn production_reads_the_signing_key_only_from_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key.cose_key");
        std::fs::write(&path, b"key bytes").unwrap();
        let path = path.to_str().unwrap();
        for (mode, accepted) in [(0o644, false), (0o640, false), (0o600, true), (0o400, true)] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_signing_key(Profile::Production, path).is_ok(),
                accepted,
                "{mode:o}"
            );
            assert!(
                read_signing_key(Profile::Development, path).is_ok(),
                "development reads {mode:o}"
            );
        }
    }

    #[test]
    fn production_refuses_in_memory_storage() {
        let (_, key) = fixture_signing_keys().remove(0);
        let error = check(Profile::Production, true, &key)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("TRELLIS_STORAGE=memory selects in-memory"),
            "{error}"
        );
    }
}
