//! Provider HTTP refusals retain status without retaining provider content.
// Rust guideline compliant 2026-02-21
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

fn reply(status: u16, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 16384];
        stream.read(&mut request).unwrap();
        let response = format!(
            "HTTP/1.1 {status} controlled\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });
    endpoint
}

#[tokio::test]
async fn provider_http_status_survives_completion_and_bundle_without_private_content() {
    for status in [400, 401, 403, 404, 409, 413, 418, 422, 423, 429, 500, 503] {
        for bundle in [false, true] {
            let body = r#"{"error_code":"INFRA-4030","title":"TOKEN_SENTINEL","detail":"PRIVATE_BODY_SENTINEL","context":{"secret":"CONTEXT_SENTINEL"}}"#.to_owned();
            let client =
                TrellisServiceClient::new(TrellisServiceClientConfig::new(reply(status, body)))
                    .unwrap();
            let ledger = crate::test_ledger("case_123");
            let error = if bundle {
                client
                    .bundle_bounded(&ledger, "checkpoint", 100)
                    .await
                    .unwrap_err()
            } else {
                client
                    .seal_completion(&ledger, &crate::completion::tests::request())
                    .await
                    .unwrap_err()
            };
            assert_eq!(
                error.status().as_u16(),
                status,
                "bundle={bundle}: {error:?}"
            );
            let public = serde_json::to_string(&error.clone().into_problem()).unwrap();
            let debug = format!("{error:?}");
            assert!(error.title().len() < 150);
            assert!(
                error.title().contains("INFRA-4030"),
                "closed provider reason survives"
            );
            for text in [&public, &debug] {
                assert!(
                    !text.contains("SENTINEL"),
                    "private provider fields escaped"
                );
            }
        }
    }
}

#[tokio::test]
async fn provider_malformed_and_oversized_errors_keep_status_and_only_safe_generic_reason() {
    for body in [
        "<html>PRIVATE_SENTINEL</html>".to_owned(),
        "PRIVATE_SENTINEL".repeat(2048),
        r#"{"error_code":"PRIVATE_SENTINEL","title":"PRIVATE_SENTINEL"}"#.to_owned(),
    ] {
        let client =
            TrellisServiceClient::new(TrellisServiceClientConfig::new(reply(403, body))).unwrap();
        let error = client
            .seal_completion(
                &crate::test_ledger("case_123"),
                &crate::completion::tests::request(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status().as_u16(), 403);
        assert!(error.title().contains("other"));
        assert!(!format!("{error:?}").contains("SENTINEL"));
    }
}

#[tokio::test]
async fn provider_chunked_refusal_stops_after_the_diagnostic_bound_without_waiting_for_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 16384];
        stream.read(&mut request).unwrap();
        let body = "x".repeat(16 * 1024);
        write!(
            stream,
            "HTTP/1.1 403 controlled\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n",
            body.len()
        )
        .unwrap();
        let _ = finished.recv_timeout(Duration::from_secs(3));
        let _ = stream.write_all(b"0\r\n\r\n");
    });
    let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        client.seal_completion(
            &crate::test_ledger("case_123"),
            &crate::completion::tests::request(),
        ),
    )
    .await;
    done.send(()).unwrap();
    server.join().unwrap();
    let error = result
        .expect("known status does not await an unbounded refusal body")
        .unwrap_err();
    assert_eq!(error.status().as_u16(), 403);
    assert!(error.title().len() < 150);
}

#[tokio::test]
async fn provider_transport_failure_remains_retryable_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
    let error = client
        .seal_completion(
            &crate::test_ledger("case_123"),
            &crate::completion::tests::request(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.status().as_u16(), 503);
}

#[tokio::test]
async fn provider_response_timeout_remains_retryable_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    // Holding an unaccepted loopback listener prevents a response until the deadline.
    let client = TrellisServiceClient::new(
        TrellisServiceClientConfig::new(endpoint).with_timeout(Duration::from_millis(30)),
    )
    .unwrap();
    let error = client
        .seal_completion(
            &crate::test_ledger("case_123"),
            &crate::completion::tests::request(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.status().as_u16(), 503);
    drop(listener);
}
