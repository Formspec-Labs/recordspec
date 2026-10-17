//! Current identity and exact permissions before HTTP replay lookup.

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{FromRequest, FromRequestParts, Path, Request},
    response::{IntoResponse, Response},
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::routes::{Authenticate, Authenticated, Authority, Declared, Requirement};
use stack_common_http::tenant::TenantScope;
use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization};
use trellis_service_client::SubstrateAppendBody;

use crate::source_diagnostics::{self as diag, Outcome, Stage};
use crate::state::{AuthenticatedRequest, TrellisServerState};

/// Parsed append admitted by the current authorization boundary.
#[derive(Clone)]
pub(crate) struct AuthorizedAppend(
    pub(crate) SubstrateAppendBody,
    pub(crate) Option<std::sync::Arc<crate::source_content::AdmittedSourceContent>>,
);

/// What a Trellis route requires of its caller: the scope names the bearer must hold and which
/// admission runs before the handler. The deployment's `actionScopes` profile may rename the
/// scopes; these are the names D1 and the shipped profile use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// A bearer that may read the ledger scope.
    Read,
    /// A bearer that may append events; the body is admitted and the replay partition chosen
    /// before replay lookup.
    AppendEvent,
    /// A bearer that may append and read, as the completion seal does.
    SealCompletion,
    /// A bearer that may append accepted attachments; the body is admitted before replay.
    AcceptedAttachment,
}

impl Authority for Admission {
    fn names(&self) -> Vec<String> {
        let names: &[&str] = match self {
            Self::Read => &["trellis.read"],
            Self::AppendEvent | Self::AcceptedAttachment => &["trellis.append"],
            Self::SealCompletion => &["trellis.append", "trellis.read"],
        };
        names.iter().map(|name| (*name).to_owned()).collect()
    }
}

#[async_trait::async_trait]
impl Authenticate<Admission> for TrellisServerState {
    async fn authenticate(
        &self,
        declared: &Declared<Admission>,
        request: &mut Request,
    ) -> Result<Authenticated, Response> {
        match declared.access.requirement() {
            Requirement::Scope(Admission::AppendEvent) => {
                let (scope, tenant) = scope_and_tenant(self, request).await?;
                let partition = admit_append(self, &scope, &tenant, request).await?;
                Ok(Authenticated {
                    principal: Some(partition),
                })
            }
            Requirement::Scope(Admission::AcceptedAttachment) => {
                let (scope, tenant) = scope_and_tenant(self, request).await?;
                let partition = crate::external_transport::admit(self, scope, &tenant, request)
                    .await
                    .map_err(IntoResponse::into_response)?;
                Ok(Authenticated {
                    principal: Some(partition),
                })
            }
            Requirement::Scope(Admission::Read | Admission::SealCompletion) => {
                // The handler authorizes against the ledger scope; the bearer is refused here first.
                self.bearer_identity(request.headers())
                    .await
                    .map_err(IntoResponse::into_response)?;
                Ok(Authenticated::default())
            }
            _ => Err(StackError::internal("Trellis routes declare an admission").into_response()),
        }
    }
}

/// The ledger scope in the matched path and the tenant scope in the headers.
async fn scope_and_tenant(
    state: &TrellisServerState,
    request: &mut Request,
) -> Result<(String, TenantScope), Response> {
    let (mut parts, body) = std::mem::replace(request, Request::new(Body::empty())).into_parts();
    let extracted = async {
        let Path(scope) = Path::<String>::from_request_parts(&mut parts, &())
            .await
            .map_err(IntoResponse::into_response)?;
        let tenant = TenantScope::from_request_parts(&mut parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok((scope, tenant))
    }
    .await;
    *request = Request::from_parts(parts, body);
    extracted
}

async fn admit_append(
    state: &TrellisServerState,
    scope: &str,
    tenant_scope: &TenantScope,
    request: &mut Request,
) -> Result<String, Response> {
    let started = std::time::Instant::now();
    let identity = state
        .bearer_identity(request.headers())
        .await
        .map_err(IntoResponse::into_response)?;
    // The claim rides in the body, so the diagnostic flag is known only once it is parsed.
    let mut selected = false;
    diag::mark(selected, Stage::BodyAdmission, Outcome::Enter);
    crate::http::validate_scope(scope).map_err(|error| {
        diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
        error.into_response()
    })?;
    // Match Axum's existing default JSON limit; replay still hashes original bytes.
    let raw_body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = to_bytes(raw_body, 2 * 1024 * 1024).await.map_err(|_| {
        diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
        (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "append body exceeds JSON limit",
        )
            .into_response()
    })?;
    let mut parse_request = Request::new(Body::from(bytes.clone()));
    *parse_request.headers_mut() = request.headers().clone();
    let Json(body) = Json::<SubstrateAppendBody>::from_request(parse_request, state)
        .await
        .map_err(|error| {
            diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
            error.into_response()
        })?;
    selected = body.source_content.is_some();
    body.validate().map_err(|error| {
        diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
        error.into_response()
    })?;
    crate::http::validate_client_attestation_shape(&body).map_err(|error| {
        diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
        error.into_response()
    })?;
    crate::http::validate_idempotency_header(request.headers(), &body.idempotency_key).map_err(
        |error| {
            diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
            error.into_response()
        },
    )?;
    crate::http::validate_compute_context(&body).map_err(|error| {
        diag::mark(selected, Stage::BodyAdmission, Outcome::Refused);
        error.into_response()
    })?;
    diag::mark(selected, Stage::BodyAdmission, Outcome::ReturnedOk);
    diag::mark(selected, Stage::CurrentGrant, Outcome::Enter);
    let permit = diag::observed(
        selected,
        Stage::CurrentGrant,
        authorize_action(
            state,
            &identity,
            tenant_scope,
            scope,
            ScopeAction::Append,
            Some(&body),
        )
        .await,
    )
    .map_err(IntoResponse::into_response)?;
    // Source admission runs before the HTTP replay decision (ADR 0163 5.4), so every
    // refusal below is current and never recorded. No credential enters replay state.
    let admitted = match (&body.source_content, &state.source_content) {
        (None, None) => None,
        (None, Some(composition)) => {
            // A closeout can only be the last event, so the last event decides.
            let last = state
                .repository
                .last_event(scope.as_bytes())
                .await
                .map_err(IntoResponse::into_response)?;
            if matches!(
                composition
                    .final_prefix_guard
                    .classify_append(scope.as_bytes(), &body, last.as_ref())
                    .map_err(IntoResponse::into_response)?,
                crate::SourceContentPrefixClass::FinalCloseout { .. }
            ) {
                return Err(StackError::unavailable(
                    "final closeout requires committed Source content",
                )
                .into_response());
            }
            None
        }
        (Some(_), None) => {
            return Err(
                StackError::unavailable("Source content composition is absent").into_response(),
            );
        }
        (Some(_), Some(composition)) => {
            diag::mark(selected, Stage::ContentRead, Outcome::Enter);
            let admitted = diag::observed(
                selected,
                Stage::ContentRead,
                composition
                    .admit_claim(
                        state.native_closeout.as_ref(),
                        tenant_scope,
                        &permit.principal,
                        &body,
                        started,
                    )
                    .await,
            )
            .map_err(IntoResponse::into_response)?;
            // The object read is the slow step; authority may have changed during it.
            diag::mark(selected, Stage::RefreshedGrant, Outcome::Enter);
            let current = diag::observed(
                selected,
                Stage::RefreshedGrant,
                state.bearer_identity(request.headers()).await,
            )
            .map_err(IntoResponse::into_response)?;
            let refreshed = diag::observed(
                selected,
                Stage::RefreshedGrant,
                authorize_action(
                    state,
                    &current,
                    tenant_scope,
                    scope,
                    ScopeAction::Append,
                    Some(&body),
                )
                .await,
            )
            .map_err(IntoResponse::into_response)?;
            if refreshed != permit {
                diag::mark(selected, Stage::RefreshedGrant, Outcome::Refused);
                return Err(StackError::conflict(
                    "Source append permission changed during content read",
                )
                .into_response());
            }
            Some(std::sync::Arc::new(admitted))
        }
    };
    // JSON encodes the tuple without delimiter ambiguity. The claim is in the body the
    // replay fingerprint already covers; the route tag keeps Source appends in their own cache.
    let route = if admitted.is_some() {
        "source-content-only"
    } else {
        "append"
    };
    let partition = serde_json::to_string(&(permit.principal, &permit.tenant_scope, scope, route))
        .map_err(|_| StackError::internal("replay partition encoding failed").into_response())?;
    request
        .extensions_mut()
        .insert(AuthorizedAppend(body, admitted));
    *request.body_mut() = Body::from(bytes);
    diag::mark(selected, Stage::ReplayAdmission, Outcome::Enter);
    Ok(partition)
}

pub(crate) async fn authorize_action(
    state: &TrellisServerState,
    identity: &AuthenticatedRequest,
    tenant_scope: &TenantScope,
    scope: &str,
    action: ScopeAction,
    append_body: Option<&SubstrateAppendBody>,
) -> Result<AuthorizedScope, StackError> {
    let fallback = append_body.map_or("anonymous", |body| body.actor.subject.as_str());
    let permit = state
        .authorizer
        .authorize(&ScopeAuthorization {
            actor: identity.actor(fallback),
            scope: scope.as_bytes(),
            action,
            tenant_scope,
            identity: identity.external_identity(),
            append_body,
            jwt_scopes: identity.legacy_scopes(),
        })
        .await?;
    if permit.principal.trim().is_empty()
        || permit.tenant_scope != *tenant_scope
        || permit.scope != scope.as_bytes()
        || permit.action != action
    {
        return Err(StackError::new(
            ErrorCode::new("INFRA-4030").expect("static error code is valid"),
            axum::http::StatusCode::FORBIDDEN,
            "authorizer did not admit the exact requested operation",
        ));
    }
    Ok(permit)
}
