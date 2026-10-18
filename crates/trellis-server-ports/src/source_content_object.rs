//! The single derivation of the object name under which a prepared Source-content batch lives.
//!
//! WOS writes the object and Trellis reads it, each through its own `ScopedObjects` for the
//! request's scope, so the full key is `{scope key}/wos-source-content/{preparationKey}`. Both
//! derive the name from the batch's `preparationKey`; the key is never carried on the wire, and
//! the scope prefix comes from the admitted scope, so a request cannot name another tenant's
//! object (ADR 0163 5.1, ADR 0168 §1.4).

use stack_common_error::StackError;

const NAME_ROOT: &str = "wos-source-content";

/// Object name `wos-source-content/sha256_<64 lowercase hex>`, under the scope's key.
///
/// Pass it to `ScopedObjects::key` (or `write_once`), which puts it under the scope's key. The
/// preparation key is limited to `sha256:<64 lowercase hex>`, so the name is one canonical path
/// that cannot add, drop or alias a segment.
///
/// # Errors
/// Refuses a preparation key outside that form.
pub fn source_content_object_name(preparation_key: &str) -> Result<String, StackError> {
    let hex = preparation_key.strip_prefix("sha256:");
    if !hex.is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return Err(StackError::bad_request(
            "Source content preparation key is not a sha256 digest",
        ));
    }
    Ok(format!("{NAME_ROOT}/{}", preparation_key.replace(':', "_")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    #[test]
    fn name_has_the_adr_shape_and_changes_with_the_preparation_key() {
        let name = source_content_object_name(&digest('a')).unwrap();
        assert_eq!(
            name,
            format!("wos-source-content/sha256_{}", "a".repeat(64))
        );
        assert_ne!(name, source_content_object_name(&digest('b')).unwrap());
    }

    #[test]
    fn preparation_keys_that_could_leave_the_name_are_refused() {
        for bad in [
            "",
            "sha256:",
            "sha256:../../other",
            "sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "other/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(source_content_object_name(bad).is_err(), "{bad}");
        }
    }
}
