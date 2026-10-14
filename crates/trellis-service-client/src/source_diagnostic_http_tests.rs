// Synthetic transport failure controls; no Source proof or existing attempt is replayed.
// Rust guideline compliant 2026-02-21
use super::*;
#[tokio::test]
async fn source_diagnostics_connect_and_request_failures_preserve_errors_and_counts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let provider = tokens(usize::MAX);
    let error = client(format!("http://{address}"), provider.clone())
        .append_source_content_event(append(), "synthetic-locator", "Bearer synthetic-person")
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "trellis Source-content append transport failed"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let provider = tokens(0);
    let error = client(
        format!("http://{}", listener.local_addr().unwrap()),
        provider.clone(),
    )
    .append_source_content_event(append(), "synthetic-locator", "Bearer synthetic-person")
    .await
    .unwrap_err();
    assert_eq!(error.title(), "Trellis service token acquisition failed");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[tokio::test]
async fn source_diagnostics_non2xx_and_invalid2xx_consume_one_response_and_preserve_errors() {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let endpoint = test_server(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        let body = r#"{"error_code":"INFRA-4030","title":"PRIVATE_SENTINEL"}"#;
        format!(
            "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    });
    let error = client(endpoint, tokens(usize::MAX))
        .append_source_content_event(append(), "synthetic-locator", "Bearer synthetic-person")
        .await
        .unwrap_err();
    // Existing returned previews are deliberately preserved. Closed diagnostic
    // output privacy is tested at its writer, without capturing global stderr.
    assert!(error.title().contains("HTTP 403"));
    assert!(error.title().contains("PRIVATE_SENTINEL"));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let endpoint = test_server(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        response("application/json", "not JSON")
    });
    let error = client(endpoint, tokens(usize::MAX))
        .append_source_content_event(append(), "synthetic-locator", "Bearer synthetic-person")
        .await
        .unwrap_err();
    assert!(
        error
            .title()
            .starts_with("trellis append response is invalid:")
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn source_diagnostics_receipt_validation_returns_the_existing_refusal() {
    let body = r#"{"eventId":"synthetic-event","sequence":0,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/synthetic","bundleRef":"memory://synthetic","verificationReceipt":{"verified":false,"artifactType":"event","eventType":"example.event"}}"#;
    let expected = serde_json::from_str::<SubstrateAppendResult>(body)
        .unwrap()
        .validate_for_event_append("case_123", "example.event")
        .unwrap_err();
    let endpoint = test_server(move |_| response("application/json", body));
    let error = client(endpoint, tokens(usize::MAX))
        .append_source_content_event(append(), "synthetic-locator", "Bearer synthetic-person")
        .await
        .unwrap_err();
    assert_eq!(error.title(), expected.title());
}
