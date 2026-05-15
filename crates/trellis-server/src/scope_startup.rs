//! Scope-authorizer startup flags (TWREF-022 / TWREF-086).
//!
//! Keeps [`TrellisScopeAuthorizerStartupInputs`] out of the HTTP composition root so
//! `lib.rs` stays smaller without changing behavior.

use std::env;

/// Environment-derived inputs for TWREF-022 scope-authorizer startup policy.
///
/// Construct in tests with literals; use [`Self::from_env`] only from `state_from_env`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrellisScopeAuthorizerStartupInputs {
    /// Set when `TRELLIS_STORAGE=memory`.
    pub storage_is_memory: bool,
    /// Set when `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`.
    pub permissive_scope_auth: bool,
}

impl TrellisScopeAuthorizerStartupInputs {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            storage_is_memory: matches!(env::var("TRELLIS_STORAGE").as_deref(), Ok("memory")),
            permissive_scope_auth: matches!(
                env::var("TRELLIS_PERMISSIVE_SCOPE_AUTH").as_deref(),
                Ok("1")
            ),
        }
    }

    /// Durable storage without explicit allow-all bypass — matches production-like HTTP tightening.
    #[must_use]
    pub fn production_like_scope_posture(&self) -> bool {
        !self.storage_is_memory && !self.permissive_scope_auth
    }
}

#[cfg(test)]
mod tests {
    use super::TrellisScopeAuthorizerStartupInputs;

    #[test]
    fn given_durable_non_permissive_when_inputs_then_production_like_true() {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: false,
        };
        assert!(inputs.production_like_scope_posture());
    }

    #[test]
    fn given_memory_storage_when_inputs_then_production_like_false() {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: true,
            permissive_scope_auth: false,
        };
        assert!(!inputs.production_like_scope_posture());
    }

    #[test]
    fn given_permissive_auth_when_inputs_then_production_like_false() {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: true,
        };
        assert!(!inputs.production_like_scope_posture());
    }
}
