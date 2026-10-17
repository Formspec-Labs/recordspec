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
                    r#"{"eventId":"evt_1","sequence":1,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/cp_1"}"#
                }
                4 => r#"{"eventTypes":[]}"#,
                5 => {
                    r#"{"eventId":"evt_2","sequence":2,"canonicalEventHash":"sha256:def","checkpointRef":"trellis://case_123/checkpoints/cp_2"}"#
                }
                6 => {
                    r#"{"eventId":"evt_3","sequence":3,"canonicalEventHash":"sha256:cdef","checkpointRef":"trellis://case_123/checkpoints/cp_3"}"#
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
            &crate::completion::tests::request(),
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
    let mut request = crate::completion::tests::request();
    request.validate().unwrap();
    let mut body = serde_json::to_value(&request).unwrap();
    body["completed"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CompletionRequest>(body).is_err());
    request.signing_events.push([2; 32]);
    assert!(request.validate().is_err());
}

#[tokio::test]
async fn completion_seal_sends_the_selection_in_the_body_under_the_machine_token_only() {
    let expected = serde_json::to_value(crate::completion::tests::request()).unwrap();
    let endpoint = test_server(move |request| {
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains("authorization: Bearer public-test-token-1\r\n"));
        assert!(!headers.to_lowercase().contains("caller-authorization"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(body).unwrap(), expected);
        response(
            "application/json",
            r#"{"eventId":"evt_3","sequence":3,"canonicalEventHash":"sha256:cdef","checkpointRef":"trellis://case_123/checkpoints/cp_3"}"#,
        )
    });
    let provider = tokens(usize::MAX);
    client(endpoint, provider.clone())
        .seal_completion(
            "case_123",
            &tenant_scope(),
            &crate::completion::tests::request(),
        )
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completion_seal_with_an_invalid_selection_sends_nothing_and_acquires_no_token() {
    let provider = tokens(usize::MAX);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = client(format!("http://{}", listener.local_addr().unwrap()), provider.clone());
    let mut body = crate::completion::tests::request();
    body.selection.signer_labels.pop();
    assert!(client
        .seal_completion("case_123", &tenant_scope(), &body)
        .await
        .is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
