// Scaled synthetic callback budgets; no Source proof, case, crypto or database effects.
// Rust guideline compliant 2026-02-21
use super::*;
use crate::source_content::{
    DEFAULT_SOURCE_CONTENT_APPEND_TIMEOUT, DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT,
    SourceContentOnlySelectionResponse,
};

fn configured(endpoint: String, timeout: Duration) -> TrellisServiceClient {
    TrellisServiceClient::new(
        TrellisServiceClientConfig::new(endpoint, HeaderConfig::wos()).with_timeout(timeout),
    )
    .unwrap()
    .with_token_provider(tokens(usize::MAX))
    .unwrap()
}
#[test]
fn source_budget_named_defaults_preserve_inner_transport_outer_order() {
    assert_eq!(
        TrellisServiceClientConfig::new("http://127.0.0.1:1", HeaderConfig::wos()).timeout,
        Duration::from_secs(5)
    );
    assert!(Duration::from_secs(5) < DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT);
    assert!(DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT < DEFAULT_SOURCE_CONTENT_APPEND_TIMEOUT);
    assert_eq!(
        DEFAULT_SOURCE_CONTENT_APPEND_TIMEOUT,
        DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT * 2 + Duration::from_secs(10)
    );
}
struct SlowToken;
#[async_trait]
impl ClientCredentialsTokenProvider for SlowToken {
    async fn access_token(&self) -> Result<ServiceAccessToken, TokenAcquisitionError> {
        tokio::time::sleep(Duration::from_millis(400)).await;
        ServiceAccessToken::new("synthetic-token".to_owned(), i64::MAX)
    }
}
#[tokio::test]
async fn source_budget_configuration_bounds_entire_post_and_get_token_waits() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = TrellisServiceClient::new(
        TrellisServiceClientConfig::new(
            format!("http://{}", listener.local_addr().unwrap()),
            HeaderConfig::wos(),
        )
        .with_timeout(Duration::from_millis(40)),
    )
    .unwrap()
    .with_token_provider(Arc::new(SlowToken))
    .unwrap();
    let started = std::time::Instant::now();
    assert!(
        client
            .source_content_selection(
                &crate::source_content_tests::request(),
                "Bearer synthetic-person"
            )
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
    let started = std::time::Instant::now();
    assert!(
        client
            .prepared_source_content_bytes(
                &tenant_scope(),
                "synthetic-case",
                "synthetic-preparation",
                "Bearer synthetic-person"
            )
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

async fn nested_transport(callback_delay: Duration, expect_write: bool) {
    let inner = Duration::from_millis(150);
    let transport = Duration::from_millis(300);
    let outer = Duration::from_millis(900);
    assert!(inner < transport && transport < outer);
    let selection_request = crate::source_content_tests::request();
    let reply = SourceContentOnlySelectionResponse {
        version: 1,
        tenant: selection_request.tenant.clone(),
        ledger_scope: selection_request.ledger_scope.clone(),
        preparation_key: selection_request.preparation_key.clone(),
        prefix_digest: trellis_types::completion_selection::completion_selection_prefix_digest(
            selection_request.ledger_scope.as_bytes(),
            &selection_request.prefix_events().unwrap(),
        )
        .unwrap(),
        selected: crate::source_content_tests::selection(),
    };
    let reply = serde_json::to_string(&reply).unwrap();
    let callback = TcpListener::bind("127.0.0.1:0").unwrap();
    let callback_origin = format!("http://{}", callback.local_addr().unwrap());
    let callbacks = Arc::new(AtomicUsize::new(0));
    let calls = callbacks.clone();
    let callback_thread = thread::spawn(move || {
        for index in 0..if expect_write { 2 } else { 1 } {
            let (mut stream, _) = callback.accept().unwrap();
            let mut buffer = [0; 8192];
            let size = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..size]);
            if index == 0 {
                assert!(
                    request
                        .starts_with("POST /api/v1/internal/completion-source-content-selection ")
                );
            } else {
                assert!(request.starts_with("GET /api/v1/internal/completion-export-content/"));
            }
            calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(callback_delay);
            let wire = if index == 0 {
                response("application/json", &reply)
            } else {
                response("application/json", "synthetic committed bytes")
            };
            // A cancelled inner handler may close the socket before this reply.
            let _ = stream.write_all(wire.as_bytes());
        }
    });
    let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let write_gate = wrote.clone();
    let endpoint = test_server(move |_| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let completed = runtime.block_on(async {
            let callback = configured(callback_origin, transport);
            tokio::time::timeout(inner, async {
                let selected = callback
                    .source_content_selection(&selection_request, "Bearer synthetic-person")
                    .await?;
                callback
                    .prepared_source_content_bytes(
                        &tenant_scope(),
                        &selected.selected.identity.case_ledger_id,
                        &selected.preparation_key,
                        "Bearer synthetic-person",
                    )
                    .await?;
                // Typed surrogate for the pre-write boundary, not a repository
                // or Source verification. Production tests/owner capture remain separate.
                write_gate.store(true, Ordering::SeqCst);
                Ok::<(), StackError>(())
            })
            .await
        });
        match completed {
            Ok(Ok(())) => response(
                "application/json",
                r#"{"eventId":"synthetic-event","sequence":0,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/synthetic","bundleRef":"memory://synthetic","verificationReceipt":{"verified":true,"artifactType":"event","eventType":"example.event"}}"#,
            ),
            _ => {
                let body = r#"{"error_code":"INFRA-5030"}"#;
                format!(
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
            }
        }
    });
    let result = configured(endpoint, outer)
        .append_source_content_event(append(), "synthetic-preparation", "Bearer synthetic-person")
        .await;
    if expect_write {
        assert!(result.is_ok());
    } else {
        assert!(result.unwrap_err().title().contains("HTTP 503"));
    }
    assert_eq!(wrote.load(Ordering::SeqCst), expect_write);
    callback_thread.join().unwrap();
    assert_eq!(
        callbacks.load(Ordering::SeqCst),
        if expect_write { 2 } else { 1 }
    );
}
#[tokio::test]
async fn source_budget_two_callbacks_before_inner_limit_keep_append_receipt_valid() {
    nested_transport(Duration::from_millis(5), true).await;
}
#[tokio::test]
async fn source_budget_callback_exceeding_inner_limit_refuses_before_surrogate_write() {
    nested_transport(Duration::from_millis(250), false).await;
}

#[tokio::test]
async fn source_budget_whole_append_bounds_token_wait_before_any_http_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = TrellisServiceClient::new(
        TrellisServiceClientConfig::new(
            format!("http://{}", listener.local_addr().unwrap()),
            HeaderConfig::wos(),
        )
        .with_timeout(Duration::from_millis(40)),
    )
    .unwrap()
    .with_token_provider(Arc::new(SlowToken))
    .unwrap();
    let started = std::time::Instant::now();
    let error = client
        .append_source_content_event(append(), "synthetic-preparation", "Bearer synthetic-person")
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "trellis Source-content append transport failed"
    );
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
