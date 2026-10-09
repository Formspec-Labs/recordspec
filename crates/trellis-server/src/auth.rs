//! Current identity and exact permissions before HTTP replay lookup.

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{FromRequest, Path, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::{idempotency::TrustedReplayPartition, tenant::TenantScope};
use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization};
use trellis_service_client::SubstrateAppendBody;

use crate::state::{AuthenticatedRequest, TrellisServerState};

/// Parsed append admitted by the current authorization boundary.
#[derive(Clone)]
pub(crate) struct AuthorizedAppend(pub(crate) SubstrateAppendBody);

pub(crate) async fn authorize_append(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    mut request: Request,
    next: Next,
) -> Response {
    match admit_append(&state, &scope, &tenant_scope, &mut request).await {
        Ok(()) => next.run(request).await,
        Err(response) => response,
    }
}

async fn admit_append(
    state: &TrellisServerState,
    scope: &str,
    tenant_scope: &TenantScope,
    request: &mut Request,
) -> Result<(), Response> {
    let identity = state
        .authenticate(request.headers())
        .await
        .map_err(IntoResponse::into_response)?;
    crate::http::validate_scope(scope).map_err(IntoResponse::into_response)?;
    // Match Axum's existing default JSON limit; replay still hashes original bytes.
    let raw_body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = to_bytes(raw_body, 2 * 1024 * 1024).await.map_err(|_| {
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
        .map_err(IntoResponse::into_response)?;
    body.validate().map_err(IntoResponse::into_response)?;
    crate::http::validate_client_attestation_shape(&body).map_err(IntoResponse::into_response)?;
    crate::http::validate_idempotency_header(request.headers(), &body.idempotency_key)
        .map_err(IntoResponse::into_response)?;
    crate::http::validate_compute_context(&body).map_err(IntoResponse::into_response)?;
    let permit = authorize_action(
        state,
        &identity,
        tenant_scope,
        scope,
        ScopeAction::Append,
        Some(&body),
    )
    .await
    .map_err(IntoResponse::into_response)?;
    // JSON encodes the tuple without delimiter ambiguity. No bearer token is retained.
    let partition =
        serde_json::to_string(&(permit.principal, &permit.tenant_scope, scope, "append")).map_err(
            |_| StackError::internal("replay partition encoding failed").into_response(),
        )?;
    request
        .extensions_mut()
        .insert(TrustedReplayPartition::new(partition));
    request.extensions_mut().insert(AuthorizedAppend(body));
    *request.body_mut() = Body::from(bytes);
    Ok(())
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

/// Requires publication authority for the same admitted reader and resource.
pub(crate) async fn authorize_publication(
    state: &TrellisServerState,
    identity: &AuthenticatedRequest,
    read_permit: &AuthorizedScope,
) -> Result<(), StackError> {
    let scope = std::str::from_utf8(&read_permit.scope)
        .map_err(|_| StackError::internal("admitted read scope is not UTF-8"))?;
    let administer = authorize_action(
        state,
        identity,
        &read_permit.tenant_scope,
        scope,
        ScopeAction::Administer,
        None,
    )
    .await?;
    if administer.principal != read_permit.principal {
        return Err(StackError::new(
            ErrorCode::new("INFRA-4030").expect("static error code is valid"),
            axum::http::StatusCode::FORBIDDEN,
            "publication requires the same authorized internal principal",
        ));
    }
    Ok(())
}
