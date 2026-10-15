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

use crate::source_diagnostics::{self as diag, Outcome, Stage};
use crate::state::{AuthenticatedRequest, TrellisServerState};

/// Parsed append admitted by the current authorization boundary.
#[derive(Clone)]
pub(crate) struct AuthorizedAppend(
    pub(crate) SubstrateAppendBody,
    pub(crate) Option<crate::SourceContentSelection>,
);

pub(crate) async fn authorize_append(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    mut request: Request,
    next: Next,
) -> Response {
    let selected = request
        .headers()
        .contains_key(crate::source_content::PREPARATION_KEY_HEADER);
    diag::mark(selected, Stage::AuthMiddleware, Outcome::Enter);
    match diag::observed(
        selected,
        Stage::AuthMiddleware,
        admit_append(&state, &scope, &tenant_scope, &mut request).await,
    ) {
        Ok(()) => {
            diag::mark(selected, Stage::ReplayAdmission, Outcome::Enter);
            let response = next.run(request).await;
            diag::mark(
                selected,
                Stage::ReplayAdmission,
                if response.status().is_success() {
                    Outcome::ReturnedOk
                } else {
                    Outcome::Refused
                },
            );
            response
        }
        Err(response) => response,
    }
}

async fn admit_append(
    state: &TrellisServerState,
    scope: &str,
    tenant_scope: &TenantScope,
    request: &mut Request,
) -> Result<(), Response> {
    let selected = request
        .headers()
        .contains_key(crate::source_content::PREPARATION_KEY_HEADER);
    diag::mark(selected, Stage::Authentication, Outcome::Enter);
    let identity = diag::observed(
        selected,
        Stage::Authentication,
        state.authenticate(request.headers()).await,
    )
    .map_err(IntoResponse::into_response)?;
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
    // Qualify current borrowed human + selected machine authority before HTTP replay.
    // The locator conveys no authority; no credential enters request replay state.
    let source_selection = match crate::source_content::preparation_key(request.headers())
        .map_err(IntoResponse::into_response)?
    {
        None => {
            if let Some(composition) = &state.source_content {
                let prefix = state
                    .repository
                    .list_scope(scope.as_bytes())
                    .await
                    .map_err(IntoResponse::into_response)?;
                if matches!(
                    composition
                        .final_prefix_guard
                        .classify_append(scope.as_bytes(), &body, &prefix)
                        .map_err(IntoResponse::into_response)?,
                    crate::SourceContentPrefixClass::FinalCloseout { .. }
                ) {
                    return Err(StackError::unavailable(
                        "final closeout requires committed Source content",
                    )
                    .into_response());
                }
            }
            None
        }
        Some(key) => {
            let composition = state.source_content.as_ref().ok_or_else(|| {
                StackError::unavailable("Source content composition is absent").into_response()
            })?;
            let caller = crate::CompletionCallerContext::from_headers(request.headers())
                .map_err(IntoResponse::into_response)?;
            if caller.person_authorization().is_none() {
                return Err(
                    StackError::unavailable("qualified Source content caller is absent")
                        .into_response(),
                );
            }
            let mut prefix = state
                .repository
                .list_scope(scope.as_bytes())
                .await
                .map_err(IntoResponse::into_response)?;
            // A same-key replay of an already committed closeout selects against the
            // history that preceded it, exactly as the original append did.
            if let Some(index) = prefix
                .iter()
                .position(|event| event.idempotency_key() == Some(body.idempotency_key.as_bytes()))
            {
                prefix.truncate(index);
            }
            diag::mark(selected, Stage::Selection, Outcome::Enter);
            let selection = diag::observed(
                selected,
                Stage::Selection,
                composition
                    .selection_resolver
                    .select(&crate::SourceContentSelectionRequest {
                        preparation_key: key,
                        scope,
                        prefix: &prefix,
                        append_body: &body,
                        caller: &caller,
                        tenant: tenant_scope,
                    })
                    .await,
            )
            .map_err(IntoResponse::into_response)?;
            if selection.preparation_key != key {
                diag::mark(selected, Stage::SelectedNative, Outcome::Refused);
                return Err(
                    StackError::conflict("Source preparation locator changed").into_response()
                );
            }
            diag::mark(selected, Stage::SelectedNative, Outcome::Enter);
            diag::observed(
                selected,
                Stage::SelectedNative,
                crate::validate_source_content_append_closeout(
                    &body.event_type,
                    &body.payload,
                    &selection.identity,
                ),
            )
            .map_err(IntoResponse::into_response)?;
            Some(selection)
        }
    };
    if source_selection.is_some() {
        diag::mark(selected, Stage::RefreshedGrant, Outcome::Enter);
        let current = diag::observed(
            selected,
            Stage::RefreshedGrant,
            state.authenticate(request.headers()).await,
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
                "Source append permission changed during owner selection",
            )
            .into_response());
        }
    }
    // JSON encodes the tuple without delimiter ambiguity. No bearer token is retained.
    let partition = match &source_selection {
        None => serde_json::to_string(&(permit.principal, &permit.tenant_scope, scope, "append")),
        Some(selection) => serde_json::to_string(&(
            permit.principal,
            &permit.tenant_scope,
            scope,
            "source-content-only",
            selection,
        )),
    }
    .map_err(|_| StackError::internal("replay partition encoding failed").into_response())?;
    request
        .extensions_mut()
        .insert(TrustedReplayPartition::new(partition));
    request
        .extensions_mut()
        .insert(AuthorizedAppend(body, source_selection));
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
