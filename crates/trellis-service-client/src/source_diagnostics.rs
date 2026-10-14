//! Opt-in closed-label Source append diagnostics; credentials and error text never enter output.
// Rust guideline compliant 2026-02-21
#[cfg(any(feature = "test-diagnostics", test))]
use std::io::Write;

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Input,
    Request,
    Send,
    Response,
    Decode,
    Receipt,
}
impl Stage {
    #[cfg(any(feature = "test-diagnostics", test))]
    fn label(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Request => "request",
            Self::Send => "send",
            Self::Response => "response",
            Self::Decode => "decode",
            Self::Receipt => "receipt",
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Enter,
    ReturnedOk,
    Refused,
}
impl Outcome {
    #[cfg(any(feature = "test-diagnostics", test))]
    fn label(self) -> &'static str {
        match self {
            Self::Enter => "enter",
            Self::ReturnedOk => "returned_ok",
            Self::Refused => "refused",
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
#[cfg(any(feature = "test-diagnostics", test))]
enum SendClass {
    Timeout,
    Connect,
    Decode,
    Other,
}
#[cfg(any(feature = "test-diagnostics", test))]
fn send_class(timeout: bool, connect: bool, decode: bool) -> SendClass {
    if timeout {
        SendClass::Timeout
    } else if connect {
        SendClass::Connect
    } else if decode {
        SendClass::Decode
    } else {
        SendClass::Other
    }
}
#[cfg(any(feature = "test-diagnostics", test))]
impl SendClass {
    #[cfg(any(feature = "test-diagnostics", test))]
    fn label(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Decode => "decode",
            Self::Other => "other",
        }
    }
}
#[cfg(any(feature = "test-diagnostics", test))]
fn public_code(preview: &str) -> &'static str {
    // Only the already bounded existing error preview is parsed. No additional
    // response read or unbounded diagnostic parse is introduced.
    let Ok(value) = serde_json::from_str::<serde_json::Value>(preview) else {
        return "other";
    };
    match value.get("error_code").and_then(serde_json::Value::as_str) {
        Some("INFRA-4000") => "INFRA-4000",
        Some("INFRA-4010") => "INFRA-4010",
        Some("INFRA-4030") => "INFRA-4030",
        Some("INFRA-4040") => "INFRA-4040",
        Some("INFRA-4090") => "INFRA-4090",
        Some("INFRA-5000") => "INFRA-5000",
        Some("INFRA-5030") => "INFRA-5030",
        _ => "other",
    }
}
#[cfg(any(feature = "test-diagnostics", test))]
fn write_mark(writer: &mut impl Write, stage: Stage, outcome: Outcome) {
    let _ = writeln!(
        writer,
        "trellis_source_client stage={} outcome={}",
        stage.label(),
        outcome.label()
    );
}
pub(crate) fn mark(selected: bool, stage: Stage, outcome: Outcome) {
    #[cfg(feature = "test-diagnostics")]
    if selected {
        write_mark(&mut std::io::stderr().lock(), stage, outcome);
    }
    #[cfg(not(feature = "test-diagnostics"))]
    let _ = (selected, stage, outcome);
}
pub(crate) fn observed<T, E>(selected: bool, stage: Stage, result: Result<T, E>) -> Result<T, E> {
    mark(
        selected,
        stage,
        if result.is_ok() {
            Outcome::ReturnedOk
        } else {
            Outcome::Refused
        },
    );
    result
}
pub(crate) fn send_error(selected: bool, error: &reqwest::Error) {
    #[cfg(feature = "test-diagnostics")]
    if selected {
        let class = send_class(error.is_timeout(), error.is_connect(), error.is_decode());
        let _ = writeln!(
            std::io::stderr().lock(),
            "trellis_source_client stage=send outcome=refused class={}",
            class.label()
        );
    }
    #[cfg(not(feature = "test-diagnostics"))]
    let _ = (selected, error);
}
pub(crate) fn send_timeout(selected: bool) {
    #[cfg(feature = "test-diagnostics")]
    if selected {
        let _ = writeln!(
            std::io::stderr().lock(),
            "trellis_source_client stage=send outcome=refused class={}",
            SendClass::Timeout.label()
        );
    }
    #[cfg(not(feature = "test-diagnostics"))]
    let _ = selected;
}

#[cfg(any(feature = "test-diagnostics", test))]
fn write_http(writer: &mut impl Write, status: u16, preview: &str) {
    let _ = writeln!(
        writer,
        "trellis_source_client stage=response outcome=refused http_status={} public_code={}",
        status,
        public_code(preview)
    );
}
pub(crate) fn http_refusal(selected: bool, status: u16, preview: &str) {
    #[cfg(feature = "test-diagnostics")]
    if selected {
        write_http(&mut std::io::stderr().lock(), status, preview);
    }
    #[cfg(not(feature = "test-diagnostics"))]
    let _ = (selected, status, preview);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_diagnostics_error_precedence_is_closed() {
        assert_eq!(send_class(true, true, true), SendClass::Timeout);
        assert_eq!(send_class(false, true, true), SendClass::Connect);
        assert_eq!(send_class(false, false, true), SendClass::Decode);
        assert_eq!(send_class(false, false, false), SendClass::Other);
    }
    #[test]
    fn source_diagnostics_unknown_codes_and_sentinel_text_never_enter_output() {
        let mut output = Vec::new();
        write_http(
            &mut output,
            503,
            r#"{"error_code":"PRIVATE_SENTINEL","title":"TOKEN_SENTINEL","detail":"HEADER_SENTINEL"}"#,
        );
        write_mark(&mut output, Stage::Receipt, Outcome::Refused);
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("public_code=other"));
        assert!(!text.contains("SENTINEL"));
        assert_eq!(public_code(r#"{"error_code":"INFRA-4000"}"#), "INFRA-4000");
    }
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    #[test]
    fn source_diagnostics_broken_output_preserves_original_result() {
        write_mark(&mut Broken, Stage::Send, Outcome::Enter);
        write_http(&mut Broken, 503, "private sentinel");
        assert_eq!(
            observed(false, Stage::Send, Err::<(), _>("original failure")),
            Err("original failure")
        );
    }
}
