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
async fn source_diagnostics_commit_failure_leaves_nothing_and_is_retryable() {
    let state = TrellisServerState::new(
        Arc::new(crate::repository_probes::FaultyRepository {
            inner: Arc::new(InMemoryEventRepository::new()),
            fault: Arc::new(crate::repository_probes::Fault::FirstCommits(AtomicUsize::new(1))),
        }),
        test_signing_key(),
        crate::test_adapters::adapters(),
    );
    let error = state
        .append_coordinator()
        .append(synthetic_command("synthetic-commit-refusal"))
        .await
        .unwrap_err();
    assert!(error.status().is_server_error());
    assert!(
        state
            .repository
            .head_checkpoint(b"synthetic-diagnostic-scope")
            .await
            .unwrap()
            .is_none(),
        "the failed commit wrote neither event nor checkpoint"
    );
    state
        .append_coordinator()
        .append(synthetic_command("synthetic-commit-refusal"))
        .await
        .unwrap();
}
