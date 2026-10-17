// Rust guideline compliant 2026-02-21
//! Axum router and HTTP handlers (TWREF-086 `http` split).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{Router, get, post};
use axum::{Extension, Json};
use stack_common_error::{ProblemJson, StackError};
use stack_common_http::idempotency::{IDEMPOTENCY_KEY_HEADER, idempotency_middleware};
use stack_common_http::tenant::TenantScope;
use stack_common_ops::HealthRouter;
use trellis_server_ports::ScopeAction;
use trellis_service_client::{ComputeSensitivity, SubstrateAppendBody, SubstrateAppendResult};

use crate::append;
use crate::event_type_registry_view;
use crate::openapi::EventTypeRegistryView;
use crate::state::{TrellisHealthProbe, TrellisServerState};

/// Seal body limit. The worst case the request validator admits is about 0.84 MiB (measured
/// by `completion_route_body_limit_admits_the_worst_case_selection_and_no_more`): 141 text
/// fields of 1024 bytes that JSON escapes to at most six bytes each, plus about 20 KiB of
/// hashes and keys as JSON number arrays.
const SEAL_BODY_LIMIT: usize = 1024 * 1024;

/// Builds the Trellis Axum router.
///
/// # Errors
/// Returns an error when shared HTTP middleware cannot be constructed.
pub fn router(state: TrellisServerState) -> Result<Router, StackError> {
    state.ensure_serving_posture_twref022()?;
    let http_layer = stack_common_http::MiddlewareBuilder::new()
        .with_request_id()
        .with_tracing()
        .with_catch_panic()
        .build()
        .map_err(|error| StackError::internal(format!("http middleware: {error}")))?;

    let append = post(append_event)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            idempotency_middleware::<TrellisServerState>,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::authorize_append,
        ));

    let accepted_attachments = post(crate::external_transport::append)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            idempotency_middleware::<TrellisServerState>,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::external_transport::authorize,
        ));
    Ok(Router::new()
        .route("/openapi.json", get(crate::openapi::openapi_json))
        .route("/v1/scopes/{scope}/events", append)
        .route(
            "/v1/scopes/{scope}/events/reconcile",
            post(reconcile_event).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/v1/scopes/{scope}/completion",
            post(seal_completion).layer(axum::extract::DefaultBodyLimit::max(SEAL_BODY_LIMIT)),
        )
        .route(
            "/v1/scopes/{scope}/accepted-attachments",
            accepted_attachments,
        )
        .route("/v1/scopes/{scope}/bundles/head", get(head_bundle))
        .route(
            "/v1/scopes/{scope}/bundles/{checkpoint_digest}",
            get(pinned_bundle),
        )
        .route(
            "/v1/scopes/{scope}/registries/signing-keys",
            get(signing_key_registry),
        )
        .route(
            "/v1/scopes/{scope}/registries/event-types",
            get(event_type_registry),
        )
        .merge(
            HealthRouter::new()
                .with_probe(TrellisHealthProbe::new(state.clone()))
                .into_router_for_state(),
        )
        .with_state(state)
        .layer(http_layer))
}

/// Looks up append identity with current read authority and no publication effects.
#[utoipa::path(post, path="/v1/scopes/{scope}/events/reconcile",
    params(("scope"=String,Path,description="Authorized ledger scope")),
    request_body=trellis_service_client::AppendReconciliationRequest,
    responses((status=200,description="Read-point disposition; lookup never appends or publishes",body=trellis_service_client::AppendReconciliation),(status=400,description="Invalid lookup identity"),(status=401,description="Current authentication refused"),(status=403,description="Current scope read permission refused")),tag="events",operation_id="reconcileEvent")]
pub(crate) async fn reconcile_event(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
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

#[utoipa::path(post, path="/v1/scopes/{scope}/completion",
    params(("scope"=String,Path,description="Authorized ledger scope"), ("idempotency-key"=String,Header,description="Must match closed request")),
    request_body=trellis_service_client::CompletionRequest,
    responses((status=201,description="Certificate and archive retained",body=SubstrateAppendResult),(status=400,description="Closed trigger or selection refused, including a status or impact outside the vocabulary"),(status=401,description="Current authentication refused"),(status=403,description="Current permission refused, or the caller is not the configured publisher"),(status=409,description="Snapshot, signing-evidence, different-principal or replay conflict"),(status=503,description="Composition not selected or dependency unavailable")),tag="events")]
pub(crate) async fn seal_completion(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant: TenantScope,
    headers: HeaderMap,
    Json(request): Json<trellis_service_client::CompletionRequest>,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), StackError> {
    // Authenticate before revealing configuration availability.
    state.authenticate(&headers).await?;
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
    path = "/v1/scopes/{scope}/events",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("idempotency-key" = String, Header, description = "HTTP replay key; must match body idempotencyKey.")
    ),
    request_body = SubstrateAppendBody,
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
    Path(scope): Path<String>,
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
    path = "/v1/scopes/{scope}/bundles/head",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
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
    Path(scope): Path<String>,
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
    path = "/v1/scopes/{scope}/bundles/{checkpointDigest}",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("checkpointDigest" = String, Path, description = "Checkpoint digest in `sha256:<64 hex>` form.")
    ),
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
    Path((scope, checkpoint_digest)): Path<(String, String)>,
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
    path = "/v1/scopes/{scope}/registries/signing-keys",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "CBOR signing-key registry snapshot.", content_type = "application/cbor"),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getSigningKeyRegistry",
)]
pub(crate) async fn signing_key_registry(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let bytes = state.signing_key.public_key_registry_cbor()?;
    Ok(bytes_response("application/cbor", bytes))
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/registries/event-types",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "Event-type registry projection.", body = EventTypeRegistryView),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getEventTypeRegistry",
)]
pub(crate) async fn event_type_registry(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
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
    let identity = state.authenticate(headers).await?;
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
