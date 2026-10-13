// HTTP controls for the committed-content read port; no Source qualification claim.
// Rust guideline compliant 2026-02-21
use super::*;

#[tokio::test]
async fn source_content_get_forwards_current_separate_headers_and_encodes_locators() {
    let endpoint =
        test_server(|request| {
            assert!(request.starts_with(
                "GET /api/v1/internal/completion-export-content/case%2Fopaque/sha256%3Akey "
            ));
            assert!(request.contains("authorization: Bearer public-test-token-1\r\n"));
            assert!(request.contains(
                "x-stack-completion-caller-authorization: Bearer public-person-token\r\n"
            ));
            assert!(request.contains("x-wos-tenant-id: tenant-a\r\n"));
            assert!(!request.contains("x-wos-workspace-id:"));
            assert!(!request.contains("x-wos-environment-id:"));
            assert!(request_body(&request).is_empty());
            response("application/json", "committed-neutral-bytes")
        });
    let provider = tokens(usize::MAX);
    let bytes = client(endpoint, provider.clone())
        .prepared_source_content_bytes(
            &tenant_scope(),
            "case/opaque",
            "sha256:key",
            "Bearer public-person-token",
        )
        .await
        .unwrap();
    assert_eq!(bytes, b"committed-neutral-bytes");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn source_content_get_refuses_status_redirect_and_declared_overflow() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let redirect = format!("http://{}/must-not-read", target.local_addr().unwrap());
    for wire in [
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n".to_string(),
        format!("HTTP/1.1 302 Found\r\nlocation: {redirect}\r\ncontent-length: 0\r\n\r\n"),
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
            crate::source_content::MAX_PREPARED_SOURCE_CONTENT_BYTES + 1
        ),
    ] {
        let endpoint = test_server(move |_| wire);
        assert!(
            client(endpoint, tokens(usize::MAX))
                .prepared_source_content_bytes(
                    &tenant_scope(),
                    "case",
                    "key",
                    "Bearer public-person-token"
                )
                .await
                .is_err()
        );
    }
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn source_content_get_refuses_streaming_overflow_without_content_length() {
    let endpoint = test_server(|_| {
        let body = "x".repeat(crate::source_content::MAX_PREPARED_SOURCE_CONTENT_BYTES + 1);
        format!("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}")
    });
    assert!(
        client(endpoint, tokens(usize::MAX))
            .prepared_source_content_bytes(
                &tenant_scope(),
                "case",
                "key",
                "Bearer public-person-token"
            )
            .await
            .is_err()
    );
}
