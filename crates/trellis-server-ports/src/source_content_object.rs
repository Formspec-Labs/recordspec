//! The single derivation of the object key under which a prepared Source-content batch lives.
//!
//! WOS writes the object and Trellis reads it. Both derive the key from the `TenantScope`
//! of the request and the batch's `preparationKey`; the key is never carried on the wire,
//! so a request cannot name another tenant's object (ADR 0163 5.1).

use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;

const KEY_ROOT: &str = "wos-source-content";

/// Object key `wos-source-content/<tenant>/<workspace>/<environment>/<cell>/<preparationKey>`.
///
/// Pass it to [`crate::S3CompatibleArtifactStore::artifact_ref_for_key`], which adds the
/// store's configured prefix. Tenant fields are limited to `[A-Za-z0-9._-]` and the
/// preparation key to `sha256:<64 lowercase hex>`, so the store's segment sanitising is
/// injective and no field can add, drop or alias a path segment.
///
/// # Errors
/// Refuses any field outside those forms.
pub fn source_content_object_key(
    tenant: &TenantScope,
    preparation_key: &str,
) -> Result<String, StackError> {
    for field in [
        &tenant.tenant,
        &tenant.workspace,
        &tenant.environment,
        &tenant.cell,
    ] {
        let plain = !field.is_empty()
            && field.len() <= 128
            && field != "."
            && field != ".."
            && field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !plain {
            return Err(StackError::bad_request(
                "Source content object tenant scope is not a plain path segment",
            ));
        }
    }
    let hex = preparation_key.strip_prefix("sha256:");
    if !hex.is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return Err(StackError::bad_request(
            "Source content preparation key is not a sha256 digest",
        ));
    }
    Ok(format!(
        "{KEY_ROOT}/{}/{}/{}/{}/{}",
        tenant.tenant,
        tenant.workspace,
        tenant.environment,
        tenant.cell,
        preparation_key.replace(':', "_"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantScope {
        TenantScope {
            tenant: "tenant-a".into(),
            workspace: "workspace-a".into(),
            environment: "prod".into(),
            cell: "cell-a".into(),
        }
    }
    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    #[test]
    fn key_has_the_adr_shape_and_changes_with_every_field() {
        let key = source_content_object_key(&tenant(), &digest('a')).unwrap();
        assert_eq!(
            key,
            format!(
                "wos-source-content/tenant-a/workspace-a/prod/cell-a/sha256_{}",
                "a".repeat(64)
            )
        );
        let mut seen = std::collections::BTreeSet::from([key]);
        for edit in 0..4 {
            let mut other = tenant();
            match edit {
                0 => other.tenant = "tenant-b".into(),
                1 => other.workspace = "workspace-b".into(),
                2 => other.environment = "test".into(),
                _ => other.cell = "cell-b".into(),
            }
            assert!(seen.insert(source_content_object_key(&other, &digest('a')).unwrap()));
        }
        assert!(seen.insert(source_content_object_key(&tenant(), &digest('b')).unwrap()));
    }

    #[test]
    fn fields_that_could_leave_the_tenant_prefix_are_refused() {
        for bad in ["", "..", ".", "a/b", "a b", "a:b", "../x", "t\u{e9}"] {
            let mut t = tenant();
            t.cell = bad.into();
            assert!(
                source_content_object_key(&t, &digest('a')).is_err(),
                "{bad}"
            );
        }
        for bad in [
            "",
            "sha256:",
            "sha256:../../other",
            "sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "other/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(source_content_object_key(&tenant(), bad).is_err(), "{bad}");
        }
    }
}
