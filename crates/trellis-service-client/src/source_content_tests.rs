//! Neutral transport checks; opaque prefix bindings do not qualify native proof.
// Rust guideline compliant 2026-02-21
use super::source_content::*;
use crate::{AppendActor, ComputeContext, SubstrateAppendBody};
use stack_common_http::tenant::TenantScope;

pub(crate) fn request() -> SourceContentOnlySelectionRequest {
    let tenant = TenantScope {
        tenant: "tenant".into(),
        workspace: "workspace".into(),
        environment: "test".into(),
        cell: "cell".into(),
    };
    let body = SubstrateAppendBody {
        event_type: "wos.provenance.recorded".into(),
        idempotency_key: "neutral-closeout".into(),
        actor: AppendActor::service("native-producer"),
        payload: serde_json::json!({"record":{"id":"neutral"}}),
        compute_context: ComputeContext::no_delegated_compute("native-producer"),
        client_attestation: None,
    };
    let event = trellis_types::StoredEvent::new(
        b"distinct-ledger-scope".to_vec(),
        0,
        vec![1, 2, 3],
        vec![4, 5, 6],
    );
    SourceContentOnlySelectionRequest::from_prefix(
        &tenant,
        "distinct-ledger-scope",
        "sha256:neutral",
        &body,
        &[event],
    )
    .unwrap()
}
pub(crate) fn selection() -> SourceContentSelection {
    SourceContentSelection {
        preparation_key: "sha256:neutral".into(),
        identity: SourceContentIdentityV1 {
            case_ledger_id: "distinct-owning-case".into(),
            process_id: "owning-process".into(),
            native_prefix_digest: [1; 32],
            reserved_closeout_record_id: "owning-record".into(),
            reserved_native_closeout_record_sha256: [2; 32],
            provider_selection_hash: [3; 32],
            native_policy_hash: [4; 32],
            recipient_policy_hash: [5; 32],
            recipient_set_sha256: [9; 32],
            workflow_url: "urn:neutral:workflow".into(),
            workflow_version: "1".into(),
            tenant_id: "tenant".into(),
            workspace_id: "workspace".into(),
            environment_id: "test".into(),
            cell_id: "cell".into(),
            source_id: "neutral-source".into(),
            service_binding_id: "neutral-binding".into(),
        },
        native_prefix_event_hashes: vec![[6; 32]],
        photo_event_hashes: vec![],
        intake_catalog_sha256: [7; 32],
        task_catalog_sha256: [8; 32],
        record_pins: vec![],
    }
}
#[test]
fn source_only_request_is_closed_and_has_no_formal_trigger_or_credentials() {
    let request = request();
    let encoded = request.to_json_bytes().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 6);
    assert!(value.get("appendBody").is_some());
    assert!(value.get("trigger").is_none());
    assert!(value.get("personAuthorization").is_none());
    assert!(value.get("trustedPins").is_none());
    let mut changed = value.clone();
    changed["trustedPins"] = serde_json::json!({});
    assert!(serde_json::from_value::<SourceContentOnlySelectionRequest>(changed).is_err());
    let mut too_many = request.clone();
    too_many.prefix = std::iter::repeat_with(|| request.prefix[0].clone())
        .take(257)
        .collect();
    assert!(too_many.to_json_bytes().is_err());
}
#[test]
fn source_only_reply_binds_namespace_separately_from_owning_case_and_refuses_changed_prefix() {
    let request = request();
    let digest = trellis_types::completion_selection::completion_selection_prefix_digest(
        request.ledger_scope.as_bytes(),
        &request.prefix_events().unwrap(),
    )
    .unwrap();
    let mut reply = SourceContentOnlySelectionResponse {
        version: 1,
        tenant: request.tenant.clone(),
        ledger_scope: request.ledger_scope.clone(),
        preparation_key: request.preparation_key.clone(),
        prefix_digest: digest,
        selected: selection(),
    };
    assert_ne!(reply.selected.identity.case_ledger_id, reply.ledger_scope);
    assert!(reply.validate_for_request(&request).is_ok());
    reply.prefix_digest[0] ^= 1;
    assert!(reply.validate_for_request(&request).is_err());
}

#[test]
fn source_content_recipient_set_digest_is_required_and_distinguishes_same_policy_key_rotation() {
    let original = selection();
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let mut value = serde_json::to_value(&original.identity).unwrap();
    assert_eq!(
        value["recipientSetSha256"],
        serde_json::json!(vec![9u8; 32])
    );
    value.as_object_mut().unwrap().remove("recipientSetSha256");
    assert!(serde_json::from_value::<SourceContentIdentityV1>(value).is_err());
    let mut rotated = original.clone();
    // Neutral opaque owner digests stand for different actual key sets. The
    // owning WOS test qualifies its canonical sorted-key digest algorithm.
    rotated.identity.recipient_set_sha256 = [10; 32];
    assert_eq!(
        original.identity.recipient_policy_hash,
        rotated.identity.recipient_policy_hash
    );
    assert_ne!(original.identity, rotated.identity);
    assert_ne!(original_bytes, serde_json::to_vec(&rotated).unwrap());
}
