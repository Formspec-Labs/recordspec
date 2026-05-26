// Rust guideline compliant 2026-02-21
#![allow(clippy::result_large_err)]
// `StackError` carries operational context callers rely on; boxing it would change every fallible
// signature in this crate. Follow-up: convert `StackError` to a `Box<...>` newtype workspace-wide.
//! Formspec aggregate ingress admission for Trellis.
//!
//! Validates Formspec aggregate append payload shapes and emits neutral
//! [`AdmittedEvent`] metadata. Direct-client submission is rejected until ADR
//! 0103 / TWREF-0103 lands; this adapter always returns
//! [`DirectSubmitPolicy::ServiceOnly`].
//!
//! Generic Trellis service modules must not depend on this crate; only the
//! Trellis composition root wires it in.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde_json::{Map, Value};
use stack_common_error::StackError;
use stack_common_hash::{canonical_json_hash, sha256_prefixed};
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, BudgetReviewRecord, DirectSubmitPolicy, EventAdmissionPolicy,
    EventFamilyId, EventTypeSpec, SchemaRef,
};
use trellis_types::ArtifactType;

/// Logical event family for Formspec aggregate append events.
pub const FORMSPEC_EVENT_FAMILY: &str = "formspec.response";

/// Canonical Formspec aggregate append literal admitted by this adapter.
pub const FORMSPEC_RESPONSE_SUBMITTED: &str = "substrate.append.response_submitted";

/// Logical event family for Response Actions session operation-batch appends.
pub const FORMSPEC_RESPONSE_ACTION_EVENT_FAMILY: &str = "formspec.response_action";

/// Canonical Formspec Response Actions session operation-batch append literal.
pub const FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH: &str =
    "substrate.append.response_action_session_op_batch";
const FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH_AGGREGATE_TYPE: &str =
    "formspec.response_action_session_op_batch";

/// Returns the schema reference used by [`AdmittedEvent`] entries this adapter emits.
#[must_use]
pub fn formspec_schema_ref(event_type: &str) -> String {
    format!("formspec-events://{event_type}")
}

/// Builds the event-type specifications a Trellis composition root may register
/// against [`trellis_server_ports::EventTypeRegistry`] at startup.
///
/// Each entry carries the full neutral metadata (`event_family`,
/// `artifact_type`, `direct_submit`) so the registry remains the catalog's
/// source of truth. `artifact_type` is the substrate structural-role contract.
#[must_use]
pub fn formspec_event_type_specs() -> Vec<EventTypeSpec> {
    vec![
        formspec_event_type_spec(
            FORMSPEC_RESPONSE_SUBMITTED,
            FORMSPEC_EVENT_FAMILY,
            "trellis-admission-formspec::FORMSPEC_RESPONSE_SUBMITTED",
        ),
        formspec_event_type_spec(
            FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            FORMSPEC_RESPONSE_ACTION_EVENT_FAMILY,
            "trellis-admission-formspec::FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH",
        ),
    ]
}

/// Formspec aggregate admission for intake proof append events.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormspecAppendAdmissionPolicy;

impl FormspecAppendAdmissionPolicy {
    /// Constructs the adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn admitted_event_for(event_type: &str) -> Result<AdmittedEvent, StackError> {
        let Some(family_id) = formspec_event_family(event_type) else {
            return Err(StackError::bad_request(format!(
                "event type `{event_type}` is not a Formspec append literal"
            )));
        };
        let family = EventFamilyId::new(family_id)
            .map_err(|error| StackError::internal(format!("formspec family invariant: {error}")))?;
        let schema_ref = SchemaRef::new(formspec_schema_ref(event_type)).map_err(|error| {
            StackError::internal(format!("formspec schema ref invariant: {error}"))
        })?;
        Ok(AdmittedEvent {
            event_type: event_type.to_string(),
            event_family: family,
            schema_ref,
            artifact_type: ArtifactType::Event,
            direct_submit: DirectSubmitPolicy::ServiceOnly,
        })
    }
}

#[async_trait]
impl EventAdmissionPolicy for FormspecAppendAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        if formspec_event_family(event.event_type).is_none() {
            return Err(StackError::bad_request(format!(
                "event type `{}` is not a Formspec append literal",
                event.event_type
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(event.payload).map_err(|error| {
            StackError::bad_request(format!("payload is not valid JSON: {error}"))
        })?;
        let map = value.as_object().ok_or_else(|| {
            StackError::bad_request("Formspec append payload must be a JSON object")
        })?;
        for key in ["aggregateType", "aggregateId", "payload"] {
            if !map.contains_key(key) {
                return Err(StackError::bad_request(format!(
                    "Formspec append payload is missing `{key}`"
                )));
            }
        }
        if event.event_type == FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH {
            validate_response_action_session_op_batch_payload(map)?;
        }
        Self::admitted_event_for(event.event_type)
    }
}

fn validate_response_action_session_op_batch_payload(
    map: &Map<String, Value>,
) -> Result<(), StackError> {
    let aggregate_type = string_field(map, "aggregateType", "aggregateType")?;
    if aggregate_type != FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH_AGGREGATE_TYPE {
        return Err(StackError::bad_request(format!(
            "Response Actions append aggregateType must be `{FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH_AGGREGATE_TYPE}`"
        )));
    }
    let aggregate_id = string_field(map, "aggregateId", "aggregateId")?;
    let payload = object_field(map, "payload", "payload")?;
    let ledger_scope = string_field(payload, "payload.ledgerScope", "ledgerScope")?;
    if aggregate_id != ledger_scope {
        return Err(StackError::bad_request(
            "Response Actions append aggregateId must match payload.ledgerScope",
        ));
    }
    let branch_id = string_field(payload, "payload.branchId", "branchId")?;
    let op_batch_hash = string_field(payload, "payload.opBatchHash", "opBatchHash")?;
    validate_sha256_prefixed_hex("payload.opBatchHash", op_batch_hash)?;
    let idempotency_key = string_field(
        payload,
        "payload.ledgerPortIdempotencyKey",
        "ledgerPortIdempotencyKey",
    )?;
    validate_sha256_prefixed_hex("payload.ledgerPortIdempotencyKey", idempotency_key)?;
    let mode = string_field(payload, "payload.mode", "mode")?;
    if mode != "require-anchored" {
        return Err(StackError::bad_request(
            "Response Actions append payload.mode must be `require-anchored`",
        ));
    }
    let op_batch_value = payload
        .get("opBatch")
        .ok_or_else(|| StackError::bad_request("payload.opBatch must be a JSON object"))?;
    let op_batch = op_batch_value
        .as_object()
        .ok_or_else(|| StackError::bad_request("payload.opBatch must be a JSON object"))?;
    if !matches!(op_batch.get("semanticOps"), Some(Value::Array(_))) {
        return Err(StackError::bad_request(
            "Response Actions append payload.opBatch.semanticOps must be an array",
        ));
    }
    let computed_hash = canonical_json_hash(op_batch_value).map_err(|error| {
        StackError::bad_request(format!("payload.opBatch canonical hash failed: {error}"))
    })?;
    if computed_hash != op_batch_hash {
        return Err(StackError::bad_request(
            "Response Actions append payload.opBatchHash must equal the canonical JSON SHA-256 hash of payload.opBatch",
        ));
    }
    let expected_idempotency_key =
        studio_ledger_idempotency_key(ledger_scope, branch_id, op_batch_hash);
    if expected_idempotency_key != idempotency_key {
        return Err(StackError::bad_request(
            "Response Actions append payload.ledgerPortIdempotencyKey must equal StudioCore ledger idempotency for ledgerScope, branchId, and opBatchHash",
        ));
    }
    Ok(())
}

fn validate_sha256_prefixed_hex(field: &str, value: &str) -> Result<(), StackError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(StackError::bad_request(format!(
            "{field} must use sha256:<64-hex> format"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StackError::bad_request(format!(
            "{field} must use sha256:<64-hex> format"
        )));
    }
    Ok(())
}

fn studio_ledger_idempotency_key(
    ledger_scope: &str,
    branch_id: &str,
    op_batch_hash: &str,
) -> String {
    sha256_prefixed(
        studio_ledger_idempotency_material(ledger_scope, branch_id, op_batch_hash).as_bytes(),
    )
}

fn studio_ledger_idempotency_material(
    ledger_scope: &str,
    branch_id: &str,
    op_batch_hash: &str,
) -> String {
    [ledger_scope, branch_id, op_batch_hash]
        .map(|part| format!("{}:{part}", part.encode_utf16().count()))
        .join("|")
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field_path: &str,
    key: &str,
) -> Result<&'a Map<String, Value>, StackError> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| StackError::bad_request(format!("{field_path} must be a JSON object")))
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field_path: &str,
    key: &str,
) -> Result<&'a str, StackError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| StackError::bad_request(format!("{field_path} must be a string")))?;
    if value.is_empty() || value.trim() != value {
        return Err(StackError::bad_request(format!(
            "{field_path} must be a non-empty string without leading or trailing whitespace"
        )));
    }
    Ok(value)
}

fn formspec_event_family(event_type: &str) -> Option<&'static str> {
    match event_type {
        FORMSPEC_RESPONSE_SUBMITTED => Some(FORMSPEC_EVENT_FAMILY),
        FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH => Some(FORMSPEC_RESPONSE_ACTION_EVENT_FAMILY),
        _ => None,
    }
}

fn formspec_event_type_spec(
    event_type: &'static str,
    event_family: &'static str,
    reviewer: &'static str,
) -> EventTypeSpec {
    EventTypeSpec {
        event_type: event_type.to_string(),
        event_family: EventFamilyId::new(event_family)
            .expect("formspec family slug is non-empty by construction"),
        schema_ref: SchemaRef::new(formspec_schema_ref(event_type))
            .expect("formspec schema refs are URI-like by construction"),
        artifact_type: ArtifactType::Event,
        direct_submit: DirectSubmitPolicy::ServiceOnly,
        budget_review: BudgetReviewRecord {
            reviewer: reviewer.to_string(),
            plaintext_fields: vec!["eventType".to_string()],
            considered: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_server_ports::{EventTypeRegistry, ReviewGateEventTypeRegistry};

    #[tokio::test]
    async fn given_well_formed_payload_when_admits_then_returns_formspec_metadata() {
        let payload = serde_json::json!({
            "aggregateType": "formspec.response",
            "aggregateId": "resp-001",
            "payload": { "status": "submitted" }
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: payload_bytes.as_slice(),
        };
        let admitted = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect("well-formed payload admits");
        assert_eq!(admitted.event_type, FORMSPEC_RESPONSE_SUBMITTED);
        assert_eq!(admitted.event_family.as_str(), FORMSPEC_EVENT_FAMILY);
        assert_eq!(admitted.artifact_type, ArtifactType::Event);
        assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
        assert!(
            admitted
                .schema_ref
                .as_str()
                .starts_with("formspec-events://")
        );
    }

    #[tokio::test]
    async fn given_response_action_session_batch_when_admits_then_returns_action_metadata() {
        let payload = response_action_append_payload();
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            payload: payload_bytes.as_slice(),
        };
        let admitted = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect("well-formed Response Actions batch admits");
        assert_eq!(
            admitted.event_type,
            FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH
        );
        assert_eq!(
            admitted.event_family.as_str(),
            FORMSPEC_RESPONSE_ACTION_EVENT_FAMILY
        );
        assert_eq!(admitted.artifact_type, ArtifactType::Event);
        assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
    }

    #[tokio::test]
    async fn given_response_action_batch_missing_ledger_fields_when_admits_then_rejects() {
        let payload = serde_json::json!({
            "aggregateType": "formspec.response_action_session_op_batch",
            "aggregateId": "session-001",
            "payload": { "semanticOps": [] }
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            payload: payload_bytes.as_slice(),
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("malformed Response Actions batch must reject");
        assert!(
            err.to_string().contains("ledgerScope"),
            "error should name the missing Response Actions field: {err}"
        );
    }

    #[tokio::test]
    async fn given_response_action_batch_wrong_hash_when_admits_then_rejects() {
        let mut payload = response_action_append_payload();
        payload["payload"]["opBatchHash"] =
            serde_json::Value::String(format!("sha256:{}", "c".repeat(64)));
        payload["payload"]["ledgerPortIdempotencyKey"] =
            serde_json::Value::String(studio_ledger_idempotency_key(
                payload["payload"]["ledgerScope"]
                    .as_str()
                    .expect("ledgerScope"),
                payload["payload"]["branchId"].as_str().expect("branchId"),
                payload["payload"]["opBatchHash"]
                    .as_str()
                    .expect("opBatchHash"),
            ));
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            payload: payload_bytes.as_slice(),
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("mismatched Response Actions hash must reject");
        assert!(
            err.to_string().contains("opBatchHash"),
            "error should name the hash mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn given_response_action_batch_wrong_idempotency_when_admits_then_rejects() {
        let mut payload = response_action_append_payload();
        payload["payload"]["ledgerPortIdempotencyKey"] =
            serde_json::Value::String(format!("sha256:{}", "d".repeat(64)));
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            payload: payload_bytes.as_slice(),
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("mismatched Response Actions idempotency must reject");
        assert!(
            err.to_string().contains("ledgerPortIdempotencyKey"),
            "error should name the idempotency mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn given_wrong_literal_when_admits_then_rejects_before_payload_parse() {
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: "wos.kernel.case_created",
            payload: b"{}",
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("non-Formspec literal must reject");
        assert!(
            err.to_string().contains("not a Formspec append literal"),
            "error should name literal failure: {err}"
        );
    }

    #[tokio::test]
    async fn given_payload_missing_aggregate_type_when_admits_then_rejects() {
        let payload = serde_json::json!({
            "aggregateId": "resp-missing",
            "payload": { "status": "submitted" }
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: payload_bytes.as_slice(),
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("missing aggregateType must reject");
        assert!(
            err.to_string().contains("aggregateType"),
            "error should name the missing key: {err}"
        );
    }

    #[tokio::test]
    async fn given_malformed_payload_when_admits_then_rejects() {
        let event = AdmissionEvent {
            scope: b"formspec.managed-single-cell",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload: b"not-json",
        };
        let err = FormspecAppendAdmissionPolicy::new()
            .admit(&event)
            .await
            .expect_err("non-JSON must reject");
        assert!(
            err.to_string().contains("not valid JSON"),
            "error should name parse failure: {err}"
        );
    }

    #[test]
    fn given_formspec_event_type_specs_when_registered_then_review_gate_accepts_all() {
        let specs = formspec_event_type_specs();
        assert_eq!(specs.len(), 2);
        let mut registry = ReviewGateEventTypeRegistry::default();
        for spec in specs {
            registry
                .register(spec)
                .expect("formspec admission spec satisfies budget review");
        }
    }

    fn response_action_append_payload() -> serde_json::Value {
        let ledger_scope = "urn:formspec:session:response-action-ledger";
        let branch_id = "branch-main";
        let op_batch = serde_json::json!({
            "semanticOps": []
        });
        let op_batch_hash = canonical_json_hash(&op_batch).expect("opBatch hash");
        let idempotency_key =
            studio_ledger_idempotency_key(ledger_scope, branch_id, &op_batch_hash);
        serde_json::json!({
            "aggregateType": "formspec.response_action_session_op_batch",
            "aggregateId": ledger_scope,
            "payload": {
                "ledgerScope": ledger_scope,
                "branchId": branch_id,
                "opBatch": op_batch,
                "opBatchHash": op_batch_hash,
                "ledgerPortIdempotencyKey": idempotency_key,
                "mode": "require-anchored"
            }
        })
    }
}
