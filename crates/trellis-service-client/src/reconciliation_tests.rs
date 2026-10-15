// Rust guideline compliant 2026-02-21
use super::*;

#[test]
fn reconciliation_builder_shares_canonical_payload_identity_and_key_byte_bound() {
    let mut body: SubstrateAppendBody = serde_json::from_value(serde_json::json!({
        "eventType":"neutral.event", "idempotencyKey":"neutral-key",
        "actor":{"kind":"service", "subject":"neutral-service"},
        "payload":{"z":1,"a":{"b":true}},
        "computeContext":{"declarationId":"neutral-compute","actor":"neutral-service","sensitivity":"publicMetadata"}
    })).unwrap();
    let first = AppendReconciliationRequest::from_append_body(&body).unwrap();
    body.payload = serde_json::json!({"a":{"b":true},"z":1});
    assert_eq!(
        first,
        AppendReconciliationRequest::from_append_body(&body).unwrap()
    );
    body.idempotency_key = "é".repeat(33);
    assert!(AppendReconciliationRequest::from_append_body(&body).is_err());
}

#[tokio::test]
async fn reconciliation_client_uses_dedicated_encoded_route_and_current_tenant() {
    let endpoint = test_server(|request| {
        assert!(request.starts_with("POST /v1/scopes/case%3Aneutral/events/reconcile "));
        assert!(request.to_lowercase().contains("x-wos-tenant-id: tenant-a"));
        assert!(!request.to_lowercase().contains("idempotency-key:"));
        let body: serde_json::Value = serde_json::from_str(request_body(&request)).unwrap();
        assert_eq!(body["idempotencyKey"], "neutral-key");
        response(
            "application/json",
            "{\"status\":\"absent\",\"eventCount\":0,\"lastEventHash\":null}",
        )
    });
    let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(
        endpoint,
        HeaderConfig::wos(),
    ))
    .unwrap();
    let lookup = AppendReconciliationRequest {
        event_type: "neutral.event".into(),
        idempotency_key: "neutral-key".into(),
        content_hash: [0; 32],
    };
    assert_eq!(
        client
            .reconcile_event("case:neutral", &tenant_scope(), &lookup)
            .await
            .unwrap(),
        AppendReconciliation::Absent {
            event_count: 0,
            last_event_hash: None
        }
    );
}

#[tokio::test]
async fn reconciliation_client_refuses_malformed_or_unverified_receipts() {
    for body in [
        "{\"status\":\"unknown\",\"reason\":\"invented\"}",
        "{\"status\":\"absent\",\"eventCount\":0,\"lastEventHash\":null,\"unexpected\":1}",
        "{\"status\":\"committed\",\"receipt\":{\"eventId\":\"event\",\"sequence\":0,\"canonicalEventHash\":\"hash\",\"checkpointRef\":\"trellis://case_123/checkpoints/hash\",\"bundleRef\":\"memory://bundle\",\"verificationReceipt\":{\"verified\":false,\"artifactType\":\"event\",\"eventType\":\"neutral.event\"}}}",
    ] {
        let endpoint = test_server(move |_| response("application/json", body));
        let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(
            endpoint,
            HeaderConfig::wos(),
        ))
        .unwrap();
        let lookup = AppendReconciliationRequest {
            event_type: "neutral.event".into(),
            idempotency_key: "neutral-key".into(),
            content_hash: [0; 32],
        };
        assert!(
            client
                .reconcile_event("case_123", &tenant_scope(), &lookup)
                .await
                .is_err()
        );
    }
}
