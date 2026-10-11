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
use crate::openapi::EventTypeRegistryView;
use crate::state::{TrellisHealthProbe, TrellisServerState};
use crate::{event_type_registry_view, publish_bundle, signing_key_registry_cbor};

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

#[utoipa::path(
    post,
    path = "/v1/scopes/{scope}/events",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("idempotency-key" = String, Header, description = "HTTP replay key; must match body idempotencyKey.")
    ),
    request_body = SubstrateAppendBody,
    responses(
        (status = 201, description = "Event appended and proof bundle published.", body = SubstrateAppendResult),
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
    Extension(crate::auth::AuthorizedAppend(body)): Extension<crate::auth::AuthorizedAppend>,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), StackError> {
    let command = append::AppendCommand {
        scope: scope.clone(),
        event_type: body.event_type.clone(),
        idempotency_key: body.idempotency_key.clone(),
        payload: body.payload.clone(),
        compute_context: append::port_compute_context(&body),
        client_attestation: body.client_attestation.clone(),
    };
    let outcome = state.append_runner.run_append(&state, command).await?;
    Ok((StatusCode::CREATED, Json(outcome.result)))
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/bundles/head",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "Current Trellis export bundle.", content_type = "application/zip"),
        (status = 404, description = "Scope has no bundle.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Bundle artifact or seal identity conflict.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Bundle store unavailable.", body = ProblemJson, content_type = "application/problem+json")
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
    let (identity, read_permit) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    crate::auth::authorize_publication(&state, &identity, &read_permit).await?;
    let bundle = {
        let _scope_guard = state.scope_locks.lock(scope.as_bytes()).await;
        let events = state.repository.list_scope(scope.as_bytes()).await?;
        publish_bundle(
            &state,
            scope.as_bytes(),
            &events,
            true,
            &append::default_public_compute_context(),
        )
        .await?
    };
    bundle_response(&state, &bundle).await
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/bundles/{checkpointDigest}",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("checkpointDigest" = String, Path, description = "Checkpoint digest in `sha256:<64 hex>` form.")
    ),
    responses(
        (status = 200, description = "Pinned Trellis export bundle.", content_type = "application/zip"),
        (status = 400, description = "Invalid checkpoint digest.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "Pinned checkpoint bundle not found.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Bundle artifact or seal identity conflict.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Bundle store unavailable.", body = ProblemJson, content_type = "application/problem+json")
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
    let (identity, read_permit) = read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let digest = normalize_checkpoint_digest(&checkpoint_digest)?;
    let record = {
        let _scope_guard = state.scope_locks.lock(scope.as_bytes()).await;
        let record = state
            .bundles
            .get_by_digest(scope.as_bytes(), &digest)
            .await?;
        if let Some(record) = record {
            record
        } else {
            crate::auth::authorize_publication(&state, &identity, &read_permit).await?;
            let events = state.repository.list_scope(scope.as_bytes()).await?;
            let head = publish_bundle(
                &state,
                scope.as_bytes(),
                &events,
                true,
                &append::default_public_compute_context(),
            )
            .await?;
            if head.checkpoint_digest == digest {
                head
            } else {
                return Err(StackError::not_found("checkpoint bundle not found"));
            }
        }
    };
    bundle_response(&state, &record).await
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
    let bytes = signing_key_registry_cbor(&state.signing_key.export_key())?;
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

async fn bundle_response(
    state: &TrellisServerState,
    bundle: &crate::artifacts::BundleRecord,
) -> Result<Response, StackError> {
    let bytes = state
        .artifact_store
        .get(&bundle.artifact_ref)
        .await?
        .ok_or_else(|| StackError::not_found("bundle artifact bytes not found"))?;
    Ok(bytes_response("application/zip", bytes))
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

fn normalize_checkpoint_digest(value: &str) -> Result<String, StackError> {
    if let Some(hex) = value.strip_prefix("sha256:") {
        validate_digest_hex(hex)?;
        Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
    } else {
        validate_digest_hex(value)?;
        Ok(format!("sha256:{}", value.to_ascii_lowercase()))
    }
}

fn validate_digest_hex(value: &str) -> Result<(), StackError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StackError::bad_request(
            "checkpoint digest must be sha256:<64 hex chars>",
        ));
    }
    Ok(())
}
