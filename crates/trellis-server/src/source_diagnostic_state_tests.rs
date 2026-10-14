// Generic persistence controls, not Source qualification or proof/crypto fixture replay.
// Rust guideline compliant 2026-02-21
use super::*;
fn synthetic_command(key: &str) -> append::AppendCommand {
    let body: SubstrateAppendBody = serde_json::from_slice(&append_body(key)).unwrap();
    append::AppendCommand {
        scope: "synthetic-diagnostic-scope".into(),
        event_type: body.event_type,
        idempotency_key: body.idempotency_key,
        payload: body.payload,
        compute_context: append::default_public_compute_context(),
        client_attestation: None,
    }
}
#[tokio::test]
async fn source_diagnostics_prewrite_policy_refusal_leaves_repository_empty() {
    let state = test_state();
    let mut command = synthetic_command("synthetic-policy-refusal");
    command.event_type = "synthetic.unregistered".into();
    let error = state
        .append_coordinator()
        .append(command)
        .await
        .unwrap_err();
    assert!(error.status().is_client_error());
    assert!(
        state
            .repository
            .list_scope(b"synthetic-diagnostic-scope")
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn source_diagnostics_write_ok_zip_failure_preserves_event_and_original_error() {
    let state = test_state().with_artifact_store(Arc::new(ConflictOnImmutableArtifactStore));
    let error = state
        .append_coordinator()
        .append(synthetic_command("synthetic-publish-refusal"))
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "artifact key already exists with different bytes"
    );
    assert_eq!(
        state
            .repository
            .list_scope(b"synthetic-diagnostic-scope")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        state
            .bundles
            .get_by_seal(b"synthetic-diagnostic-scope", 1)
            .await
            .unwrap()
            .is_none()
    );
}
