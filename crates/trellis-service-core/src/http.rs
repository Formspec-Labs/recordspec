// Rust guideline compliant 2026-02-21
//! Axum router and HTTP handlers (TWREF-086 `http` split).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{Router, get};
use axum::{Extension, Json};
use stack_common_error::{ProblemJson, StackError};
use stack_common_http::idempotency::IDEMPOTENCY_KEY_HEADER;
use stack_common_http::routes::{Access, Documents, Routes};
use stack_common_http::tenant::TenantScope;
use stack_common_ops::HealthRouter;
use trellis_server_ports::ComputeSensitivity;
use trellis_server_ports::ScopeAction;
use trellis_service_client::endpoints::{
    ACCEPTED_ATTACHMENT, APPEND_EVENT, BundlePath, EVENT_TYPE_REGISTRY, EventTypeRegistryView,
    HEAD_BUNDLE, PINNED_BUNDLE, RECONCILE_EVENT, SEAL_COMPLETION, SIGNING_KEY_REGISTRY, ScopePath,
};
use trellis_service_client::{SubstrateAppendBody, SubstrateAppendResult};

use crate::append;
use crate::auth::Admission;
use crate::event_type_registry_view;
use crate::openapi::base_document;
use crate::state::{TrellisHealthProbe, TrellisServerState};

/// Every Trellis route, declared once; the router and the document derive from this set.
fn routes(state: TrellisServerState) -> Routes<TrellisServerState, Admission, TrellisServerState> {
    Routes::new(base_document(), state.clone())
        .endpoint(
            APPEND_EVENT,
            utoipa_axum::routes!(append_event),
            Access::scope(Admission::AppendEvent),
        )
        .endpoint(
            RECONCILE_EVENT,
            utoipa_axum::routes!(reconcile_event),
            Access::scope(Admission::Read),
        )
        .endpoint(
            SEAL_COMPLETION,
            utoipa_axum::routes!(seal_completion),
            Access::scope(Admission::SealCompletion),
        )
        .endpoint(
            ACCEPTED_ATTACHMENT,
            utoipa_axum::routes!(crate::external_transport::append),
            Access::scope(Admission::AcceptedAttachment),
        )
        .endpoint(
            HEAD_BUNDLE,
            utoipa_axum::routes!(head_bundle),
            Access::scope(Admission::Read),
        )
        .endpoint(
            PINNED_BUNDLE,
            utoipa_axum::routes!(pinned_bundle),
            Access::scope(Admission::Read),
        )
        .endpoint(
            SIGNING_KEY_REGISTRY,
            utoipa_axum::routes!(signing_key_registry),
            Access::scope(Admission::Read),
        )
        .endpoint(
            EVENT_TYPE_REGISTRY,
            utoipa_axum::routes!(event_type_registry),
            Access::scope(Admission::Read),
        )
        .merge_health(HealthRouter::new().with_probe(TrellisHealthProbe::new(state)))
}

/// The OpenAPI documents of the declared routes.
///
/// # Errors
/// Returns an error when a handler's annotation disagrees with its endpoint.
pub fn documents(state: TrellisServerState) -> Result<Documents, StackError> {
    routes(state)
        .build()
        .map(|built| built.documents)
        .map_err(|error| StackError::internal(error.to_string()))
}

/// Builds the Trellis Axum router.
///
/// # Errors
/// Returns an error when shared HTTP middleware cannot be constructed or a route declaration
/// disagrees with its handler.
pub fn router(state: TrellisServerState) -> Result<Router, StackError> {
    state.ensure_serving_posture_twref022()?;
    let http_layer = stack_common_http::MiddlewareBuilder::new()
        .with_request_id()
        .with_tracing()
        .with_catch_panic()
        .build()
        .map_err(|error| StackError::internal(format!("http middleware: {error}")))?;
    let built = routes(state.clone())
        .build()
        .map_err(|error| StackError::internal(error.to_string()))?;
    let document = Bytes::from(
        serde_json::to_vec(&built.documents.public)
            .map_err(|error| StackError::internal(format!("OpenAPI serialization: {error}")))?,
    );
    Ok(built
        .router
        .route(
            "/openapi.json",
            get(move || {
                let document = document.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], document) }
            }),
        )
        .with_state(state)
        .layer(http_layer))
}

/// Looks up append identity with current read authority and no publication effects.
#[utoipa::path(post, path = RECONCILE_EVENT.path(),
    responses((status=200,description="Read-point disposition; lookup never appends or publishes",body=trellis_service_client::AppendReconciliation),(status=400,description="Invalid lookup identity"),(status=401,description="Current authentication refused"),(status=403,description="Current scope read permission refused")),tag="events",operation_id="reconcileEvent")]
pub(crate) async fn reconcile_event(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    tenant: TenantScope,
    headers: HeaderMap,
    Json(request): Json<trellis_service_client::AppendReconciliationRequest>,
) -> Result<Json<trellis_service_client::AppendReconciliation>, StackError> {
    let (_, before) = read_authorized(&state, &scope, &tenant, &headers).await?;
    request.validate()?;
    let result = crate::reconciliation::reconcile(&state, &scope, &request).await;
    let (_, after) = read_authorized(&state, &scope, &tenant, &headers).await?;
    if before != after {
        return Err(StackError::unavailable(
            "reconciliation read authority changed",
        ));
    }
    Ok(Json(result))
}

#[utoipa::path(post, path = SEAL_COMPLETION.path(),
    responses((status=201,description="Certificate and archive retained",body=SubstrateAppendResult),(status=400,description="Closed trigger or selection refused, including a status or impact outside the vocabulary"),(status=401,description="Current authentication refused"),(status=403,description="Current permission refused, or the caller is not the configured publisher"),(status=409,description="Snapshot, signing-evidence, different-principal or replay conflict"),(status=503,description="Composition not selected or dependency unavailable")),tag="events")]
pub(crate) async fn seal_completion(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    tenant: TenantScope,
    headers: HeaderMap,
    Json(request): Json<trellis_service_client::CompletionRequest>,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), StackError> {
    // Authenticate before revealing configuration availability.
    state.bearer_identity(&headers).await?;
    let (signer, _) = state
        .completion
        .as_ref()
        .ok_or_else(|| StackError::unavailable("completion composition is not selected"))?;
    let result =
        crate::seal_completion(&state, &headers, &tenant, &scope, &request, signer.as_ref())
            .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

#[utoipa::path(
    post,
    path = APPEND_EVENT.path(),
    request_body = trellis_service_client::SubstrateAppendBody,
    responses(
        (status = 201, description = "Event and its checkpoint committed.", body = SubstrateAppendResult),
        (status = 400, description = "Invalid append request.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "Service token rejected.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 403, description = "Scope action forbidden.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Idempotency key or sequence conflict.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Substrate dependency unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "events",
    operation_id = "appendEvent",
)]
pub(crate) async fn append_event(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    Extension(crate::auth::AuthorizedAppend(body, admitted)): Extension<
        crate::auth::AuthorizedAppend,
    >,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), StackError> {
    let command = append::AppendCommand {
        scope: scope.clone(),
        event_type: body.event_type.clone(),
        idempotency_key: body.idempotency_key.clone(),
        payload: body.payload.clone(),
        client_attestation: body.client_attestation.clone(),
    };
    let outcome = match admitted {
        None => state.append_runner.run_append(&state, command).await?,
        Some(admitted) => {
            use crate::source_diagnostics::{self as diag, Outcome, Stage};
            diag::mark(true, Stage::Handler, Outcome::Enter);
            let source = crate::source_content::SourceContentAppendContext {
                admitted: &admitted,
                body: &body,
            };
            diag::observed(
                true,
                Stage::Handler,
                state
                    .append_coordinator()
                    .append_selected_source_content(command, &source)
                    .await,
            )?
        }
    };
    Ok((StatusCode::CREATED, Json(outcome.result)))
}

#[utoipa::path(
    get,
    path = HEAD_BUNDLE.path(),
    responses(
        (status = 200, description = "The Core section 18 export at the head checkpoint, assembled on request under Read.", content_type = "application/zip"),
        (status = 403, description = "Current Read refused.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "Scope has no events.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Stored rows or a retained Source batch contradict themselves.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Ledger or artifact store unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "bundles",
    operation_id = "getHeadBundle",
)]
pub(crate) async fn head_bundle(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    let (_, read_permit) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let head = state
        .repository
        .head_checkpoint(scope.as_bytes())
        .await?
        .ok_or_else(|| StackError::not_found("scope has no events"))?;
    let bytes = crate::export::assemble(&state, scope.as_bytes(), &head).await?;
    let (_, after) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    if after != read_permit {
        return Err(StackError::unavailable("bundle read authority changed"));
    }
    Ok(bytes_response("application/zip", bytes))
}

#[utoipa::path(
    get,
    path = PINNED_BUNDLE.path(),
    responses(
        (status = 200, description = "The Core section 18 export at the pinned checkpoint, assembled on request under Read.", content_type = "application/zip"),
        (status = 400, description = "Invalid checkpoint digest.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No checkpoint with that digest in the scope.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Stored rows or a retained Source batch contradict themselves.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Ledger or artifact store unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "bundles",
    operation_id = "getBundleByCheckpointDigest",
)]
pub(crate) async fn pinned_bundle(
    State(state): State<TrellisServerState>,
    Path(BundlePath {
        scope,
        checkpoint_digest,
    }): Path<BundlePath>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    let (_, read_permit) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let digest = parse_checkpoint_digest(&checkpoint_digest)?;
    let checkpoint = state
        .repository
        .checkpoint_by_digest(scope.as_bytes(), &digest)
        .await?
        .ok_or_else(|| StackError::not_found("checkpoint bundle not found"))?;
    let bytes = crate::export::assemble(&state, scope.as_bytes(), &checkpoint).await?;
    let (_, after) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    if after != read_permit {
        return Err(StackError::unavailable("bundle read authority changed"));
    }
    Ok(bytes_response("application/zip", bytes))
}

#[utoipa::path(
    get,
    path = SIGNING_KEY_REGISTRY.path(),
    responses(
        (status = 200, description = "CBOR signing-key registry snapshot.", content_type = "application/cbor"),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getSigningKeyRegistry",
)]
pub(crate) async fn signing_key_registry(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let bytes = state.signing_key.public_key_registry_cbor()?;
    Ok(bytes_response("application/cbor", bytes))
}

#[utoipa::path(
    get,
    path = EVENT_TYPE_REGISTRY.path(),
    responses(
        (status = 200, description = "Event-type registry projection.", body = EventTypeRegistryView),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getEventTypeRegistry",
)]
pub(crate) async fn event_type_registry(
    State(state): State<TrellisServerState>,
    Path(ScopePath { scope }): Path<ScopePath>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Json<EventTypeRegistryView>, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    Ok(Json(event_type_registry_view(
        state.event_type_catalog.as_ref(),
    )))
}

async fn read_authorized(
    state: &TrellisServerState,
    scope: &str,
    tenant_scope: &TenantScope,
    headers: &HeaderMap,
) -> Result<
    (
        crate::state::AuthenticatedRequest,
        trellis_server_ports::AuthorizedScope,
    ),
    StackError,
> {
    validate_scope(scope)?;
    let identity = state.bearer_identity(headers).await?;
    let permit = crate::auth::authorize_action(
        state,
        &identity,
        tenant_scope,
        scope,
        ScopeAction::Read,
        None,
    )
    .await?;
    Ok((identity, permit))
}

fn bytes_response(content_type: &'static str, bytes: Vec<u8>) -> Response {
    use axum::http::HeaderValue;
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

pub(crate) fn validate_idempotency_header(
    headers: &HeaderMap,
    body_key: &str,
) -> Result<(), StackError> {
    let header_key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| StackError::bad_request("idempotency key required"))?;
    if header_key != body_key {
        return Err(StackError::bad_request(
            "idempotency header must match request idempotencyKey",
        ));
    }
    Ok(())
}

pub(crate) fn validate_compute_context(body: &SubstrateAppendBody) -> Result<(), StackError> {
    if body.compute_context.sensitivity != ComputeSensitivity::PublicMetadata {
        return Err(StackError::bad_request(
            "this Trellis server path only admits publicMetadata payloads",
        ));
    }
    Ok(())
}

/// Validates the structural shape of a `clientAttestation` when present.
///
/// The semantic accept/reject decision is metadata-driven and lives inside
/// the append coordinator: it consults `AdmittedEvent.direct_submit` after
/// admission classifies the event family. This handler-side check only
/// catches malformed shapes that admission would never see (empty `kid`,
/// empty `cose_sign1`).
pub(crate) fn validate_client_attestation_shape(
    body: &SubstrateAppendBody,
) -> Result<(), StackError> {
    if let Some(attestation) = &body.client_attestation {
        if attestation.kid.trim().is_empty() {
            return Err(StackError::bad_request(
                "clientAttestation.kid must not be empty",
            ));
        }
        if attestation.cose_sign1.trim().is_empty() {
            return Err(StackError::bad_request(
                "clientAttestation.cose_sign1 must not be empty",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_scope(scope: &str) -> Result<(), StackError> {
    if scope.trim().is_empty() {
        return Err(StackError::bad_request("scope is required"));
    }
    if scope.contains('/') {
        return Err(StackError::bad_request("scope must be one path segment"));
    }
    if !scope.is_ascii() {
        return Err(StackError::bad_request("scope must be ASCII"));
    }
    Ok(())
}

fn parse_checkpoint_digest(value: &str) -> Result<[u8; 32], StackError> {
    let hex_digits = value.strip_prefix("sha256:").unwrap_or(value);
    validate_digest_hex(hex_digits)?;
    let mut digest = [0u8; 32];
    hex::decode_to_slice(hex_digits, &mut digest)
        .map_err(|_| StackError::bad_request("checkpoint digest must be sha256:<64 hex chars>"))?;
    Ok(digest)
}

fn validate_digest_hex(value: &str) -> Result<(), StackError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StackError::bad_request(
            "checkpoint digest must be sha256:<64 hex chars>",
        ));
    }
    Ok(())
}
