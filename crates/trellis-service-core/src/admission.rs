// Rust guideline compliant 2026-02-21
//! Explicit programmatic scope-authorizer fixtures.
//!
//! Normal startup installs current deployment grants from `oidc_startup`.
//! The allow-all adapter supports explicit in-memory host composition; router
//! validation refuses it with external authentication or production posture.
//! The JWT scope adapter exists only for isolated unit-test fixtures.

use async_trait::async_trait;
#[cfg(test)]
use axum::http::StatusCode;
use stack_common_auth::VerifiedAccessIdentity;
#[cfg(test)]
use stack_common_error::ErrorCode;
use stack_common_error::StackError;
use stack_common_scope::ScopeKey;
use trellis_server_ports::{AuthorizedScope, ScopeAuthorization, ScopeAuthorizer};

#[derive(Debug, Clone, Copy)]
pub(crate) struct AllowAllScopeAuthorizer;

#[async_trait]
impl ScopeAuthorizer for AllowAllScopeAuthorizer {
    type Error = StackError;

    /// Every scope the deployment serves: development composition admits any selected scope.
    fn bound_scopes(
        &self,
        _identity: Option<&VerifiedAccessIdentity>,
    ) -> Result<Option<Vec<ScopeKey>>, Self::Error> {
        Ok(None)
    }

    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, Self::Error> {
        Ok(legacy_permit(request))
    }
}

/// Checks fixture JWT scopes against the requested scope.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScopedAllowlistScopeAuthorizer;

#[cfg(test)]
#[async_trait]
impl ScopeAuthorizer for ScopedAllowlistScopeAuthorizer {
    type Error = StackError;

    fn bound_scopes(
        &self,
        _identity: Option<&VerifiedAccessIdentity>,
    ) -> Result<Option<Vec<ScopeKey>>, Self::Error> {
        Ok(None)
    }

    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, Self::Error> {
        let Some(scopes) = request.jwt_scopes else {
            return Err(StackError::new(
                ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                StatusCode::UNAUTHORIZED,
                "bearer token required for Trellis scope authorization",
            )
            .with_detail(
                "Set Authorization: Bearer with a JWT whose `scopes` claim lists the target scope (TWREF-022).",
            ));
        };
        // Fixture tokens list ledger ids; the ledger scope puts them under the admitted scope.
        let scope_str = request.scope.ledger_id();
        if scopes.iter().any(|allowed| allowed.as_str() == scope_str) {
            Ok(legacy_permit(request))
        } else {
            Err(StackError::new(
                ErrorCode::new("INFRA-4030").expect("static error code is valid"),
                StatusCode::FORBIDDEN,
                "scope not authorized for this bearer token",
            )
            .with_detail(format!(
                "JWT `scopes` did not include `{scope_str}` (TWREF-022)."
            )))
        }
    }
}

// Explicit fixtures return the requested scope; normal startup resolves current grants.
fn legacy_permit(request: &ScopeAuthorization<'_>) -> AuthorizedScope {
    AuthorizedScope {
        principal: request.actor.to_string(),
        scope: request.scope.clone(),
        action: request.action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_common_scope::Scope;
    use trellis_server_ports::{LedgerScope, ScopeAction};

    fn ledger() -> LedgerScope {
        LedgerScope::of(&Scope::fixture("test", "test", Some("test")), "case_123").unwrap()
    }

    /// Given a scope listed in JWT scopes, when scoped authorizer runs, then authorization succeeds.
    #[tokio::test]
    async fn given_scope_in_jwt_scopes_when_scoped_authorizer_runs_then_ok() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let scopes = vec!["case_123".to_string()];
        auth.authorize(&ScopeAuthorization {
            actor: "sub",
            identity: None,
            append_body: None,
            scope: &ledger(),
            action: ScopeAction::Append,
            jwt_scopes: Some(scopes.as_slice()),
        })
        .await
        .expect("scope allowlisted");
    }

    /// Given JWT scopes omitting the request scope, when scoped authorizer runs, then it returns forbidden.
    #[tokio::test]
    async fn given_missing_scope_in_jwt_when_scoped_authorizer_runs_then_forbidden() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let scopes = vec!["other".to_string()];
        let err = auth
            .authorize(&ScopeAuthorization {
                actor: "sub",
                identity: None,
                append_body: None,
                scope: &ledger(),
                action: ScopeAction::Append,
                jwt_scopes: Some(scopes.as_slice()),
            })
            .await
            .expect_err("scope must not match");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    /// Given no JWT scopes slice (anonymous / missing claims), when scoped authorizer runs, then unauthorized.
    #[tokio::test]
    async fn given_no_jwt_scopes_when_scoped_authorizer_runs_then_unauthorized() {
        let auth = ScopedAllowlistScopeAuthorizer;
        let err = auth
            .authorize(&ScopeAuthorization {
                actor: "sub",
                identity: None,
                append_body: None,
                scope: &ledger(),
                action: ScopeAction::Append,
                jwt_scopes: None,
            })
            .await
            .expect_err("bearer scopes required");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }
}
