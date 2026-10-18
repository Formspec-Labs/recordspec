//! Current identity, the admitted scope and exact permissions, before HTTP replay lookup.
//!
//! [`TrellisHost`] is the router's `Authenticate`: it verifies the bearer, asks the authorizer
//! which scopes the identity is bound to, selects one (`x-stack-scope-key` when there are
//! several) and admits the request through the deployment, which hands back the request's
//! [`TrellisScoped`] handle (ADR 0168 §1.1–§1.2). The host holds the deployment; the router
//! state does not, so a handler reaches data only through the handle its gate admitted.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{FromRequest, FromRequestParts, RawPathParams, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::idempotency::{
    HttpIdempotencyState, IdempotencyCall, IdempotencyDecision, IdempotencyDriverError,
    IdempotencyFailure, IdempotencyOperation,
};
use stack_common_http::problem_response;
use stack_common_http::routes::{Authenticate, Authenticated, Authority, Declared, Requirement};
use stack_common_idempotency::{
    HttpReplayStore, ReplayOutcome, ScopedHttpReplayStore, ScopedReplayOutcome, StoredResponse,
};
use stack_common_scope::{Deployment, SCOPE_KEY_HEADER, ScopeBound, ScopeKey, VerifiedBinding};
use trellis_server_ports::{AuthorizedScope, LedgerScope, ScopeAction, ScopeAuthorization};
use trellis_service_client::SubstrateAppendBody;

use crate::source_diagnostics::{self as diag, Outcome, Stage};
use crate::state::{
    AuthenticatedRequest, NativeReplayScope, TrellisServerState, native_replay_call,
};
use crate::store::{TrellisScoped, TrellisStore};

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

/// The router's host: the server state for verification and the deployment that admits scopes.
#[derive(Clone)]
pub(crate) struct TrellisHost {
    pub(crate) state: TrellisServerState,
    deployment: Arc<Deployment<TrellisStore>>,
    /// Every served scope's key, the binding an authorizer that names none admits to.
    served: Arc<[ScopeKey]>,
}

impl TrellisHost {
    pub(crate) fn new(
        state: TrellisServerState,
        deployment: Arc<Deployment<TrellisStore>>,
    ) -> Self {
        let served = deployment
            .scopes()
            .iter()
            .map(|scope| *scope.key())
            .collect();
        Self {
            state,
            deployment,
            served,
        }
    }

    /// Admits the verified identity to one of its bound scopes.
    ///
    /// The authorizer names the scopes the identity is bound to (every served scope only in
    /// development composition); the `x-stack-scope-key` header selects one when there are
    /// several. A refused selection answers 404, as a scope the caller does not hold.
    fn admit(
        &self,
        identity: &AuthenticatedRequest,
        request: &Request,
    ) -> Result<TrellisScoped, StackError> {
        let named = self
            .state
            .authorizer
            .bound_scopes(identity.external_identity())?;
        let bound: &[ScopeKey] = named.as_deref().unwrap_or(&self.served);
        let selector = match request.headers().get(SCOPE_KEY_HEADER) {
            None => None,
            Some(value) => Some(
                value
                    .to_str()
                    .map_err(|_| StackError::not_found("the scope selector is malformed"))?,
            ),
        };
        let binding = VerifiedBinding::select(bound, selector)
            .map_err(|refused| StackError::not_found(refused.to_string()))?;
        self.deployment
            .admit(&binding)
            .map_err(|refused| StackError::not_found(refused.to_string()))
    }
}

#[async_trait]
impl Authenticate<Admission> for TrellisHost {
    type Scoped = TrellisScoped;

    async fn authenticate(
        &self,
        declared: &Declared<Admission>,
        request: &mut Request,
    ) -> Result<Authenticated<TrellisScoped>, Response> {
        let identity = self
            .state
            .bearer_identity(request.headers())
            .await
            .map_err(IntoResponse::into_response)?;
        let scoped = self
            .admit(&identity, request)
            .map_err(IntoResponse::into_response)?;
        let principal = match declared.access.requirement() {
            Requirement::Scope(Admission::AppendEvent) => {
                let scope = ledger_in_path(&scoped, request).await?;
                admit_append(&self.state, &scoped, &identity, &scope, request).await?
            }
            Requirement::Scope(Admission::AcceptedAttachment) => {
                let scope = ledger_in_path(&scoped, request).await?;
                crate::external_transport::admit(&self.state, &identity, scope, request)
                    .await
                    .map_err(IntoResponse::into_response)?
            }
            // A foreign ledger answers 404 here, before the body is read; the handler authorizes
            // the action against the ledger scope.
            Requirement::Scope(Admission::Read | Admission::SealCompletion) => {
                ledger_in_path(&scoped, request).await?;
                return Ok(Authenticated::without_principal(scoped));
            }
            _ => {
                return Err(
                    StackError::internal("Trellis routes declare an admission").into_response()
                );
            }
        };
        Ok(Authenticated::principal(principal, scoped))
    }

    fn public(&self, _declared: &Declared<Admission>) -> Result<TrellisScoped, Response> {
        Err(StackError::unavailable("Trellis serves no public scope").into_response())
    }
}

/// The matched path's `{scope}`, which must be a ledger under the admitted scope (404 if not).
///
/// Every Trellis route is under `/v1/scopes/{scope}`, so the gate refuses another scope's ledger
/// before any handler, extractor or body parser runs.
async fn ledger_in_path(
    scoped: &TrellisScoped,
    request: &mut Request,
) -> Result<LedgerScope, Response> {
    let (mut parts, body) = std::mem::replace(request, Request::new(Body::empty())).into_parts();
    let extracted = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .map_err(IntoResponse::into_response)
        .and_then(|params| {
            params
                .iter()
                .find(|(name, _)| *name == "scope")
                .map(|(_, value)| value.to_owned())
                .ok_or_else(|| {
                    StackError::internal("a Trellis route has no {scope} segment").into_response()
                })
        });
    *request = Request::from_parts(parts, body);
    LedgerScope::within(scoped.scope(), &extracted?).map_err(IntoResponse::into_response)
}

async fn admit_append(
    state: &TrellisServerState,
    scoped: &TrellisScoped,
    identity: &AuthenticatedRequest,
    scope: &LedgerScope,
    request: &mut Request,
) -> Result<String, Response> {
    let started = std::time::Instant::now();
    // The claim rides in the body, so the diagnostic flag is known only once it is parsed.
    let mut selected = false;
    diag::mark(selected, Stage::BodyAdmission, Outcome::Enter);
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
        authorize_action(state, identity, scope, ScopeAction::Append, Some(&body)).await,
    )
    .map_err(IntoResponse::into_response)?;
    // Source admission runs before the HTTP replay decision (ADR 0163 5.4), so every
    // refusal below is current and never recorded. No credential enters replay state.
    let admitted = match (&body.source_content, &state.source_content) {
        (None, None) => None,
        (None, Some(composition)) => {
            // A closeout can only be the last event, so the last event decides.
            let last = scoped
                .ledgers()
                .last_event(scope)
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
                        scoped,
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
                authorize_action(state, &current, scope, ScopeAction::Append, Some(&body)).await,
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
    // JSON encodes the tuple without delimiter ambiguity; the gate prefixes the scope key. The
    // claim is in the body the replay fingerprint already covers; the route tag keeps Source
    // appends in their own cache.
    let route = if admitted.is_some() {
        "source-content-only"
    } else {
        "append"
    };
    let partition = serde_json::to_string(&(permit.principal, scope.as_str(), route))
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
    scope: &LedgerScope,
    action: ScopeAction,
    append_body: Option<&SubstrateAppendBody>,
) -> Result<AuthorizedScope, StackError> {
    let fallback = append_body.map_or("anonymous", |body| body.actor.subject.as_str());
    let permit = state
        .authorizer
        .authorize(&ScopeAuthorization {
            actor: identity.actor(fallback),
            scope,
            action,
            identity: identity.external_identity(),
            append_body,
            jwt_scopes: identity.legacy_scopes(),
        })
        .await?;
    if permit.principal.trim().is_empty() || permit.scope != *scope || permit.action != action {
        return Err(StackError::new(
            ErrorCode::new("INFRA-4030").expect("static error code is valid"),
            axum::http::StatusCode::FORBIDDEN,
            "authorizer did not admit the exact requested operation",
        ));
    }
    Ok(permit)
}

/// HTTP replay: the gate partitions every admitted request by `(scope key, principal)`.
///
/// Accepted attachments keep their response-replaying store row (`native_replay_call`); every
/// other idempotent route replays through the stored-response check.
#[async_trait]
impl HttpIdempotencyState for TrellisHost {
    type Error = StackError;

    async fn reserve_http_idempotency(
        &self,
        call: &IdempotencyCall,
    ) -> Result<IdempotencyDecision, IdempotencyDriverError<Self::Error>> {
        let store = &self.state.replay_store;
        if native_replay_call(call) {
            return match store
                .check_or_record(
                    &NativeReplayScope(replay_scope(call)),
                    "",
                    &call.request.key,
                    &call.request.request_hash,
                )
                .await
            {
                Ok(ScopedReplayOutcome::Recorded) => Ok(IdempotencyDecision::Fresh),
                Ok(ScopedReplayOutcome::Replayed { response }) => {
                    Ok(IdempotencyDecision::Replay(response))
                }
                Err(error) if error.status() == StatusCode::CONFLICT => {
                    Ok(IdempotencyDecision::Conflict)
                }
                Err(error) => Err(IdempotencyDriverError::store(error)),
            };
        }
        match store
            .check(
                &replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
            )
            .await
            .map_err(IdempotencyDriverError::store)?
        {
            ReplayOutcome::Fresh => Ok(IdempotencyDecision::Fresh),
            ReplayOutcome::Replay(response) => Ok(IdempotencyDecision::Replay(response)),
            ReplayOutcome::Conflict => Ok(IdempotencyDecision::Conflict),
        }
    }

    async fn record_http_idempotency_response(
        &self,
        call: &IdempotencyCall,
        response: StoredResponse,
    ) -> Result<(), IdempotencyDriverError<Self::Error>> {
        let store = &self.state.replay_store;
        if native_replay_call(call) {
            return store
                .record_response(
                    &NativeReplayScope(replay_scope(call)),
                    "",
                    &call.request.key,
                    &call.request.request_hash,
                    response,
                )
                .await
                .map_err(IdempotencyDriverError::store);
        }
        store
            .record(
                &replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
                response,
            )
            .await
            .map_err(IdempotencyDriverError::store)
    }

    fn idempotency_failure_response(&self, failure: IdempotencyFailure) -> Response {
        let error = match failure {
            IdempotencyFailure::MissingKey => StackError::bad_request("idempotency key required"),
            IdempotencyFailure::RequestBodyCaptureFailed => {
                StackError::bad_request("request body capture failed")
            }
            IdempotencyFailure::Conflict => {
                StackError::conflict("idempotency key reused with a different body")
            }
            IdempotencyFailure::ResponseBodyCaptureFailed => {
                StackError::internal("response body capture failed")
            }
        };
        problem_response(error)
    }

    fn idempotency_store_error_response(
        &self,
        _operation: IdempotencyOperation,
        error: Self::Error,
    ) -> Response {
        problem_response(error)
    }
}

/// The replay partition the gate minted, length-prefixed so arbitrary principal or route text
/// cannot collide. Every Trellis route is admitted to a scope, so a request without one is
/// refused by the gate before replay; the empty partition is never shared with an admitted one.
fn replay_scope(call: &IdempotencyCall) -> String {
    let partition = call.replay_partition.as_deref().unwrap_or_default();
    format!("{}:{}{}", partition.len(), partition, call.request.scope)
}
