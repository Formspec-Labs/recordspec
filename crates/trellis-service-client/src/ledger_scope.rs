// Rust guideline compliant 2026-02-21
//! The ledger scope: the one definition of `<scope key hex>.<ledger id>` (ADR 0168 §1.6), shared
//! by the client that sends it, the server that admits it and the store that keys rows by it.

use std::fmt::{self, Display, Formatter};

use stack_common_error::StackError;
use stack_common_scope::{Scope, ScopeKey};

/// A ledger's scope as every event and checkpoint signs it: `<scope key hex>.<ledger id>`.
///
/// The ledger id is the bare id a producer chose (`{tenant}_case_{uuid}` for WOS); the scope key
/// already carries the tenant. The whole string is ASCII and one path segment with no `/` or `:`,
/// and the key is 64 hex digits, so the first `.` splits it (ADR 0168 §1.6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerScope {
    text: String,
    key: ScopeKey,
}

/// Longest ledger id a ledger scope may carry, in bytes.
const MAX_LEDGER_ID: usize = 256;

impl LedgerScope {
    /// Names ledger `ledger_id` under `scope`.
    ///
    /// # Errors
    /// A bad request when the id is empty, too long, or not printable ASCII without `/` or `:`.
    pub fn of(scope: &Scope, ledger_id: &str) -> Result<Self, StackError> {
        Self::under(*scope.key(), ledger_id)
    }

    /// Names ledger `ledger_id` under the scope whose key is `key`, for configuration read before
    /// any [`Scope`] is issued (a startup profile names served scopes by their key). Holding one
    /// grants nothing: the server admits a request's ledger only under the request's own scope.
    ///
    /// # Errors
    /// As [`LedgerScope::of`].
    pub fn under(key: ScopeKey, ledger_id: &str) -> Result<Self, StackError> {
        validate_ledger_id(ledger_id)?;
        Ok(Self {
            text: format!("{key}.{ledger_id}"),
            key,
        })
    }

    /// Reads the ledger scope a request names, which must lie under the request's `scope`.
    ///
    /// # Errors
    /// A bad request for a malformed name; not found for a well-formed name under another scope,
    /// which a server answers as it answers a ledger it does not hold.
    pub fn within(scope: &Scope, raw: &str) -> Result<Self, StackError> {
        if raw.trim().is_empty() {
            return Err(StackError::bad_request("scope is required"));
        }
        if raw.contains('/') {
            return Err(StackError::bad_request("scope must be one path segment"));
        }
        if !raw.is_ascii() {
            return Err(StackError::bad_request("scope must be ASCII"));
        }
        let ledger_id = raw
            .split_once('.')
            .filter(|(key, _)| *key == scope.key().to_string())
            .map(|(_, id)| id)
            .ok_or_else(|| StackError::not_found("no such ledger in this scope"))?;
        Self::of(scope, ledger_id)
    }

    /// The scope key the ledger lives under.
    #[must_use]
    pub const fn key(&self) -> &ScopeKey {
        &self.key
    }

    /// The ledger scope as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The ledger scope bytes, as events, checkpoints and rows carry them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The ledger id after the scope key.
    #[must_use]
    pub fn ledger_id(&self) -> &str {
        // The text is `<64 hex>.<id>`, built by `of`.
        &self.text[65..]
    }

    /// Whether the ledger lives under `scope`.
    #[must_use]
    pub fn belongs_to(&self, scope: &Scope) -> bool {
        &self.key == scope.key()
    }
}

impl Display for LedgerScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Checks a ledger id's grammar: 1 to 256 printable ASCII characters without `/` or `:`, and
/// not `.` or `..`, which object-store paths refuse as a segment.
///
/// # Errors
/// A bad request naming the grammar.
pub fn validate_ledger_id(ledger_id: &str) -> Result<(), StackError> {
    if ledger_id.is_empty()
        || ledger_id == "."
        || ledger_id == ".."
        || ledger_id.len() > MAX_LEDGER_ID
        || !ledger_id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':')
    {
        return Err(StackError::bad_request(
            "a ledger id is 1 to 256 printable ASCII characters without `/` or `:`, not `.` or `..`",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> Scope {
        Scope::fixture("acme", "benefits", Some("prod"))
    }

    fn b() -> Scope {
        Scope::fixture("globex", "benefits", Some("prod"))
    }

    #[test]
    fn a_ledger_scope_is_the_scope_key_then_the_ledger_id() {
        let ledger = LedgerScope::of(&a(), "acme_case_1").unwrap();
        assert_eq!(ledger.as_str(), format!("{}.acme_case_1", a().key()));
        assert_eq!(ledger.ledger_id(), "acme_case_1");
        assert!(ledger.belongs_to(&a()) && !ledger.belongs_to(&b()));
        assert_eq!(LedgerScope::within(&a(), ledger.as_str()).unwrap(), ledger);
    }

    #[test]
    fn another_scopes_ledger_is_not_found_and_a_malformed_one_is_refused() {
        let theirs = LedgerScope::of(&b(), "globex_case_1").unwrap();
        for foreign in [theirs.as_str(), "case_123", "acme_case_1.x"] {
            let refused = LedgerScope::within(&a(), foreign).unwrap_err();
            assert_eq!(refused.status().as_u16(), 404, "{foreign}");
        }
        let ours = a().key().to_string();
        for malformed in [
            String::new(),
            format!("{ours}."),
            format!("{ours}.a/b"),
            format!("{ours}.urn:wos:case"),
            format!("{ours}.caf\u{e9}"),
            format!("{ours}.{}", "x".repeat(257)),
            // Object-store paths refuse these as a segment (a Source batch key's ledger id).
            format!("{ours}.."),
            format!("{ours}..."),
        ] {
            let refused = LedgerScope::within(&a(), &malformed).unwrap_err();
            assert_eq!(refused.status().as_u16(), 400, "{malformed}");
        }
    }
}
