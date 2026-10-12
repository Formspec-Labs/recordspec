// Checks current-token acquisition at every public HTTP operation.
// Rust guideline compliant 2026-02-21

use super::*;
use stack_common_auth::client_credentials::{ServiceAccessToken, TokenAcquisitionError};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Tokens {
    calls: AtomicUsize,
    fail_after: usize,
}

#[async_trait]
impl ClientCredentialsTokenProvider for Tokens {
    async fn access_token(&self) -> Result<ServiceAccessToken, TokenAcquisitionError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call > self.fail_after {
            return Err(TokenAcquisitionError::unavailable());
        }
        ServiceAccessToken::new(format!("public-test-token-{call}"), i64::MAX)
    }
}

fn tokens(fail_after: usize) -> Arc<Tokens> {
    Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        fail_after,
    })
}

fn selection_request() -> completion_selection::CompletionSelectionRequest {
    completion_selection::CompletionSelectionRequest::from_prefix(
        &tenant_scope(),
        "case_123",
        &CompletionRequest {
            idempotency_key: "selection".into(),
            certificate_id: "urn:test:certificate".into(),
            expected_head: [7; 32],
            signing_events: vec![[8; 32]],
        },
        &[trellis_types::StoredEvent::new(
            b"case_123".to_vec(),
            0,
            b"protected-canonical".to_vec(),
            b"protected-signed".to_vec(),
        )],
    )
    .unwrap()
}

fn selection_reply(
    request: &completion_selection::CompletionSelectionRequest,
) -> serde_json::Value {
    serde_json::json!({ "version":1,"tenant":request.tenant,"ledgerScope":request.ledger_scope,
        "trigger":request.trigger,"prefixDigest":request.prefix_digest,"caseLedgerId":"case_derived",
        "selected":{"selectionRevision":vec![9u8;32],"caseRef":"case_derived","workflowRef":"process_done",
            "workflowStatus":"completed","completedAt":[100,123],"impactLevel":null,
            "signerLabels":[{"signingEvent":vec![8u8;32],"displayName":"Protected Person"}],
            "requiredAttestors":[{"authority":"urn:test:authority","authorityClass":"new","publicKey":vec![10u8;32]}]}})
}

#[tokio::test]
async fn selection_forwards_separate_credentials_and_exact_bound_prefix() {
    let body = selection_request();
    let expected = body.clone();
    let endpoint = test_server(move |request| {
        assert!(request.starts_with("POST /api/v1/completion/selections "));
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(!headers.contains("x-wos-workspace-id:"));
        assert!(!headers.contains("x-wos-environment-id:"));
        assert!(headers.contains("authorization: Bearer public-test-token-1\r\n"));
        assert!(
            headers.contains("x-stack-completion-caller-authorization: Bearer public-person-token")
        );
        assert!(!body.contains("public-person-token"));
        let actual: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(actual, serde_json::to_value(&expected).unwrap());
        response("application/json", &selection_reply(&expected).to_string())
    });
    let provider = tokens(usize::MAX);
    let reply = client(endpoint, provider.clone())
        .completion_selection(&body, "Bearer public-person-token")
        .await
        .unwrap();
    assert_eq!(reply.case_ledger_id, "case_derived");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert!(!format!("{body:?} {reply:?}").contains("Protected Person"));
    assert!(!format!("{body:?}").contains("protected-canonical"));
}

#[test]
fn selection_refuses_changed_echoes_unknown_authority_and_unbounded_bytes() {
    let request = selection_request();
    let baseline = selection_reply(&request);
    for (path, altered) in [
        ("/version", serde_json::json!(2)),
        ("/tenant/cell", serde_json::json!("other")),
        ("/ledgerScope", serde_json::json!("other")),
        ("/trigger/certificateId", serde_json::json!("other")),
        (
            "/prefixDigest/0",
            serde_json::json!(request.prefix_digest[0] ^ 1),
        ),
        ("/caseLedgerId", serde_json::json!("other")),
        ("/selected/completedAt/1", serde_json::json!(1000000000)),
        (
            "/selected/requiredAttestors/0/authorityClass",
            serde_json::json!("invented"),
        ),
    ] {
        let mut reply = baseline.clone();
        *reply.pointer_mut(path).unwrap() = altered;
        let reply: completion_selection::CompletionSelectionResponse =
            serde_json::from_value(reply).unwrap();
        assert!(reply.validate_for_request(&request).is_err(), "{path}");
    }
    let mut unknown = baseline;
    unknown["callerPrincipal"] = serde_json::json!("asserted");
    assert!(
        serde_json::from_value::<completion_selection::CompletionSelectionResponse>(unknown)
            .is_err()
    );
    let mut changed = request.clone();
    changed.prefix_digest[0] ^= 1;
    assert!(changed.to_json_bytes().is_err());
    changed = request;
    changed.prefix[0].signed_event =
        vec![0; trellis_types::completion_selection::MAX_COMPLETION_PREFIX_BYTES];
    assert!(changed.to_json_bytes().is_err());
}

#[tokio::test]
async fn selection_failure_redacts_echoes_and_provider_failure_sends_no_request() {
    let provider = tokens(0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let error = client(endpoint, provider.clone())
        .completion_selection(&selection_request(), "Bearer public-person-token")
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("public-person-token"));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let endpoint = test_server(|_| {
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 19\r\n\r\npublic-person-token".into()
    });
    let error = client(endpoint, tokens(usize::MAX))
        .completion_selection(&selection_request(), "Bearer public-person-token")
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("public-person-token"));
}

#[tokio::test]
async fn selection_refuses_redirect_and_oversized_streamed_reply() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let location = format!("http://{}/", target.local_addr().unwrap());
    let endpoint = test_server(move |_| {
        format!("HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n")
    });
    assert!(client(endpoint, tokens(usize::MAX))
        .completion_selection(&selection_request(), "Bearer public-person-token")
        .await
        .is_err());
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let endpoint = test_server(|_| {
        let body = "x".repeat(completion_selection::MAX_SELECTION_RESPONSE_BYTES + 1);
        format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
    });
    assert!(client(endpoint, tokens(usize::MAX))
        .completion_selection(&selection_request(), "Bearer public-person-token")
        .await
        .is_err());
}

#[test]
fn selection_preserves_indexed_labels_and_bounds_tenant_before_cloning() {
    let mut request = selection_request();
    request.trigger.signing_events.push([11; 32]);
    let mut reply = selection_reply(&request);
    reply["selected"]["signerLabels"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
        "signingEvent":vec![11u8;32],"displayName":"Second Person"}));
    let valid: completion_selection::CompletionSelectionResponse =
        serde_json::from_value(reply.clone()).unwrap();
    valid.validate_for_request(&request).unwrap();
    reply["selected"]["signerLabels"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let changed: completion_selection::CompletionSelectionResponse =
        serde_json::from_value(reply).unwrap();
    assert!(changed.validate_for_request(&request).is_err());
    request.tenant.tenant = "x".repeat(1025);
    assert!(request.to_json_bytes().is_err());
}

#[tokio::test]
async fn selection_deadline_includes_stalled_current_provider() {
    struct Stalled;
    #[async_trait]
    impl ClientCredentialsTokenProvider for Stalled {
        async fn access_token(&self) -> Result<ServiceAccessToken, TokenAcquisitionError> {
            std::future::pending().await
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(
        endpoint,
        HeaderConfig::wos(),
    ))
    .unwrap()
    .with_token_provider(Arc::new(Stalled))
    .unwrap();
    let error = client
        .completion_selection(&selection_request(), "Bearer public-person-token")
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("public-person-token"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn client(endpoint: String, provider: Arc<Tokens>) -> TrellisServiceClient {
    TrellisServiceClient::new(TrellisServiceClientConfig::new(
        endpoint,
        HeaderConfig::wos(),
    ))
    .unwrap()
    .with_token_provider(provider)
    .unwrap()
}

fn append() -> SubstrateAppendRequest {
    SubstrateAppendRequest::new_json(
        "case_123",
        tenant_scope(),
        "example.event",
        "test-idempotency-key",
        AppendActor::service("producer"),
        serde_json::json!({}),
        ComputeContext::no_delegated_compute("producer"),
    )
    .unwrap()
}

#[tokio::test]
async fn all_seven_operations_acquire_changed_current_tokens_once_each() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let paths = [
            "POST /v1/scopes/case_123/events ",
            "GET /v1/scopes/case_123/bundles/head ",
            "GET /v1/scopes/case_123/bundles/checkpoint-1 ",
            "GET /v1/scopes/case_123/registries/signing-keys ",
            "GET /v1/scopes/case_123/registries/event-types ",
            "POST /v1/scopes/case_123/accepted-attachments ",
            "POST /v1/scopes/case_123/completion ",
        ];
        for (index, path) in paths.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .map(|value| value.parse().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with(path), "{request}");
            assert!(request.contains("x-wos-workspace-id:"));
            assert!(request.contains("x-wos-environment-id:"));
            assert!(request.contains(&format!(
                "authorization: Bearer public-test-token-{}\r\n",
                index + 1
            )));
            let body = match index {
                0 => {
                    r#"{"eventId":"evt_1","sequence":1,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/cp_1","bundleRef":"s3://bucket/bundle.zip","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"example.event"}}"#
                }
                4 => r#"{"eventTypes":[]}"#,
                5 => {
                    r#"{"eventId":"evt_2","sequence":2,"canonicalEventHash":"sha256:def","checkpointRef":"trellis://case_123/checkpoints/cp_2","bundleRef":"s3://bucket/attachment.zip","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"substrate.append.accepted_attachment_binding"}}"#
                }
                6 => {
                    r#"{"eventId":"evt_3","sequence":3,"canonicalEventHash":"sha256:cdef","checkpointRef":"trellis://case_123/checkpoints/cp_3","bundleRef":"s3://bucket/completion.zip","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"trellis.certificate-of-completion.v2"}}"#
                }
                _ => "test-bytes",
            };
            // Close each connection so the fixture reads one complete request per socket.
            let wire =
                response("application/json", body).replacen("\r\n", "\r\nconnection: close\r\n", 1);
            stream.write_all(wire.as_bytes()).unwrap();
        }
    });
    let provider = tokens(usize::MAX);
    let client = client(endpoint, provider.clone());
    client.append_event(append()).await.unwrap();
    assert_eq!(
        client
            .head_bundle("case_123", &tenant_scope())
            .await
            .unwrap(),
        b"test-bytes"
    );
    client
        .bundle("case_123", "checkpoint-1", &tenant_scope())
        .await
        .unwrap();
    client
        .signing_key_registry("case_123", &tenant_scope())
        .await
        .unwrap();
    assert_eq!(
        client
            .event_type_registry("case_123", &tenant_scope())
            .await
            .unwrap(),
        serde_json::json!({"eventTypes":[]})
    );
    client
        .append_accepted_attachment("case_123", &tenant_scope(), &attachment_body())
        .await
        .unwrap();
    client
        .seal_completion(
            "case_123",
            &tenant_scope(),
            &CompletionRequest {
                idempotency_key: "manual-completion".into(),
                certificate_id: "urn:test:completion".into(),
                expected_head: [7; 32],
                signing_events: vec![[7; 32]],
            },
        )
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), 7);
    server.join().unwrap();
}

#[tokio::test]
async fn failed_provider_and_invalid_input_send_zero_http_and_never_reuse_prior_token() {
    let provider = tokens(1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..count]);
        assert!(request.contains("authorization: Bearer public-test-token-1\r\n"));
        let wire =
            response("application/zip", "first").replacen("\r\n", "\r\nconnection: close\r\n", 1);
        stream.write_all(wire.as_bytes()).unwrap();
        listener
    });
    let failing = client(endpoint, provider.clone());
    failing
        .head_bundle("case_123", &tenant_scope())
        .await
        .unwrap();
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(failing.head_bundle("", &tenant_scope()).await.is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert!(failing
        .head_bundle("case_123", &tenant_scope())
        .await
        .is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    let mut invalid = attachment_body();
    invalid.original_bytes.clear();
    assert!(failing
        .append_accepted_attachment("case_123", &tenant_scope(), &invalid)
        .await
        .is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert!(failing
        .append_accepted_attachment("case_123", &tenant_scope(), &attachment_body())
        .await
        .is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn provider_rejects_every_static_bearer_and_debug_redacts_credentials() {
    for bearer in ["", " ", "private-static-bearer"] {
        let config = TrellisServiceClientConfig::new("http://127.0.0.1:1", HeaderConfig::wos())
            .with_service_bearer_token(bearer);
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("[REDACTED]"));
        let client = TrellisServiceClient::new(config).unwrap();
        assert!(!format!("{client:?}").contains("private-static-bearer"));
        assert!(client.with_token_provider(tokens(usize::MAX)).is_err());
    }
    let provider = tokens(usize::MAX);
    let client = client("http://127.0.0.1:1".into(), provider.clone());
    assert!(format!("{client:?}").contains("[configured]"));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirects_fail_without_forwarding_credentials_or_acquiring_again() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let target_url = format!("http://{}/redirected", target.local_addr().unwrap());
    let endpoint = test_server(move |request| {
        assert!(request.contains("authorization: Bearer public-test-token-1\r\n"));
        format!("HTTP/1.1 302 Found\r\nlocation: {target_url}\r\ncontent-length: 0\r\n\r\n")
    });
    let provider = tokens(usize::MAX);
    assert!(client(endpoint, provider.clone())
        .head_bundle("case_123", &tenant_scope())
        .await
        .is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn completion_request_rejects_asserted_authority_unknown_fields_and_repeated_hashes() {
    let mut request = CompletionRequest {
        idempotency_key: "manual-completion".into(),
        certificate_id: "urn:test:certificate".into(),
        expected_head: [7; 32],
        signing_events: vec![[7; 32]],
    };
    request.validate().unwrap();
    let mut body = serde_json::to_value(&request).unwrap();
    body["completed"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CompletionRequest>(body).is_err());
    request.signing_events.push([7; 32]);
    assert!(request.validate().is_err());
}

#[tokio::test]
async fn completion_person_header_stays_separate_from_current_machine_token_and_body() {
    let endpoint = test_server(|request| {
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains("authorization: Bearer public-test-token-1\r\n"));
        assert!(
            headers.contains("x-stack-completion-caller-authorization: Bearer public-person-token")
        );
        assert!(!body.contains("public-person-token"));
        response(
            "application/json",
            r#"{"eventId":"evt_3","sequence":3,"canonicalEventHash":"sha256:cdef","checkpointRef":"trellis://case_123/checkpoints/cp_3","bundleRef":"s3://bucket/completion.zip","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"trellis.certificate-of-completion.v2"}}"#,
        )
    });
    let provider = tokens(usize::MAX);
    client(endpoint, provider.clone())
        .seal_completion_with_caller_authorization(
            "case_123",
            &tenant_scope(),
            &CompletionRequest {
                idempotency_key: "manual-completion".into(),
                certificate_id: "urn:test:certificate".into(),
                expected_head: [7; 32],
                signing_events: vec![[7; 32]],
            },
            "Bearer public-person-token",
        )
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completion_person_errors_redact_echoes_and_invalid_headers_acquire_no_token() {
    let provider = tokens(usize::MAX);
    let endpoint = test_server(|_| {
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 19\r\n\r\npublic-person-token".into()
    });
    let client = client(endpoint, provider.clone());
    let body = CompletionRequest {
        idempotency_key: "manual-completion".into(),
        certificate_id: "urn:test:certificate".into(),
        expected_head: [7; 32],
        signing_events: vec![[7; 32]],
    };
    for invalid in [
        "",
        "Bearer ",
        "Basic private",
        "Bearer has space",
        "Bearer bad\r\nvalue",
    ] {
        assert!(client
            .seal_completion_with_caller_authorization("case_123", &tenant_scope(), &body, invalid)
            .await
            .is_err());
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let error = client
        .seal_completion_with_caller_authorization(
            "case_123",
            &tenant_scope(),
            &body,
            "Bearer public-person-token",
        )
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("public-person-token"));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}
