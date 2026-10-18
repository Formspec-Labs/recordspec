// Rust guideline compliant 2026-02-21
//! Every Trellis route as an [`Endpoint`] (ADR 0165 §1.1, §1.2).
//!
//! `trellis-service-core` mounts each of these with `Routes::endpoint`, which fails the router
//! build when the handler's annotation disagrees; [`TrellisServiceClient`](crate::TrellisServiceClient)
//! builds its requests from the same constants. Method, path, the four wire types, the body
//! limit and the `Idempotency-Key` requirement are stated here once.

use serde::{Deserialize, Serialize};
use stack_common_http::routes::{Absent, Cbor, Endpoint, Zip};
use stack_common_typeid::STACK_ID_EXTENSION;
use utoipa::openapi::extensions::ExtensionsBuilder;
use utoipa::openapi::schema::{Object, ObjectBuilder, Type};
use utoipa::{IntoParams, ToSchema};

use crate::{
    AcceptedAttachmentAppendBody, AppendReconciliation, AppendReconciliationRequest,
    CompletionRequest, SubstrateAppendBody, SubstrateAppendResult,
};

/// The id family the ledger scope parameter is documented under (`x-stack-id`): the cross-scope
/// harness fills a parameter of a family with another scope's id of it (ADR 0168 §1.8), so every
/// ledger route is probed with A's ledger and must answer 404 or 401.
pub const LEDGER_SCOPE_FAMILY: &str = "trellis-ledger";

/// A ledger scope in a path, `<scope key>.<ledger id>` (ADR 0168 §1.6), as `LedgerScope::within`
/// parses it; documented as an id of [`LEDGER_SCOPE_FAMILY`]. Fields name it as their
/// `value_type`, as `Id<F>` aliases are named, so the parameter stays required.
pub struct LedgerScopeParam;

impl utoipa::PartialSchema for LedgerScopeParam {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        ledger_scope_schema().into()
    }
}

impl ToSchema for LedgerScopeParam {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("LedgerScope")
    }
}

fn ledger_scope_schema() -> Object {
    ObjectBuilder::new()
        .schema_type(Type::String)
        .description(Some(
            "Ledger scope: the scope key (64 lowercase hex), `.`, and a ledger id of 1-256 \
             printable ASCII characters other than `/` and `:`, not `.` or `..`.",
        ))
        .pattern(Some(r"^[0-9a-f]{64}\.(?!\.?$)[!-.0-9;-~]{1,256}$"))
        .extensions(Some(
            ExtensionsBuilder::new()
                .add(STACK_ID_EXTENSION, LEDGER_SCOPE_FAMILY)
                .build(),
        ))
        .build()
}

/// Path of every ledger-scoped route.
#[derive(Clone, Debug, Serialize, Deserialize, IntoParams, ToSchema)]
pub struct ScopePath {
    /// Trellis ledger scope.
    #[param(value_type = LedgerScopeParam)]
    #[schema(value_type = LedgerScopeParam)]
    pub scope: String,
}

/// Path of the pinned-bundle route.
#[derive(Clone, Debug, Serialize, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BundlePath {
    /// Trellis ledger scope.
    #[param(value_type = LedgerScopeParam)]
    #[schema(value_type = LedgerScopeParam)]
    pub scope: String,
    /// Checkpoint digest in `sha256:<64 hex>` form.
    pub checkpoint_digest: String,
}

/// One event type in the registry projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventTypeRegistryEntry {
    /// The event type literal.
    pub event_type: String,
    /// Reference to the schema that governs its payload.
    pub schema_ref: String,
}

/// The event-type registry projection, `GET .../registries/event-types`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventTypeRegistryView {
    /// Registry version.
    pub registry_version: String,
    /// Registered event types.
    pub event_types: Vec<EventTypeRegistryEntry>,
}

/// Seal body limit. The worst case the request validator admits is about 0.84 MiB (measured
/// by `completion_route_body_limit_admits_the_worst_case_selection_and_no_more`): 141 text
/// fields of 1024 bytes that JSON escapes to at most six bytes each, plus about 20 KiB of
/// hashes and keys as JSON number arrays.
const SEAL_BODY_LIMIT: usize = 1024 * 1024;

/// Append one event.
pub const APPEND_EVENT: Endpoint<ScopePath, Absent, SubstrateAppendBody, SubstrateAppendResult> =
    Endpoint::post("/v1/scopes/{scope}/events").idempotent();

/// Look up append identity without appending.
pub const RECONCILE_EVENT: Endpoint<
    ScopePath,
    Absent,
    AppendReconciliationRequest,
    AppendReconciliation,
> = Endpoint::post("/v1/scopes/{scope}/events/reconcile").limit(4096);

/// Seal a completion certificate.
pub const SEAL_COMPLETION: Endpoint<ScopePath, Absent, CompletionRequest, SubstrateAppendResult> =
    Endpoint::post("/v1/scopes/{scope}/completion")
        .keyed()
        .limit(SEAL_BODY_LIMIT);

/// Append an accepted attachment under the server's selected protection.
pub const ACCEPTED_ATTACHMENT: Endpoint<
    ScopePath,
    Absent,
    AcceptedAttachmentAppendBody,
    SubstrateAppendResult,
> = Endpoint::post("/v1/scopes/{scope}/accepted-attachments").idempotent();

/// The export at the head checkpoint.
pub const HEAD_BUNDLE: Endpoint<ScopePath, Absent, Absent, Zip> =
    Endpoint::get("/v1/scopes/{scope}/bundles/head");

/// The export at a pinned checkpoint.
pub const PINNED_BUNDLE: Endpoint<BundlePath, Absent, Absent, Zip> =
    Endpoint::get("/v1/scopes/{scope}/bundles/{checkpointDigest}");

/// The signing-key registry snapshot.
pub const SIGNING_KEY_REGISTRY: Endpoint<ScopePath, Absent, Absent, Cbor> =
    Endpoint::get("/v1/scopes/{scope}/registries/signing-keys");

/// The event-type registry projection.
pub const EVENT_TYPE_REGISTRY: Endpoint<ScopePath, Absent, Absent, EventTypeRegistryView> =
    Endpoint::get("/v1/scopes/{scope}/registries/event-types");
