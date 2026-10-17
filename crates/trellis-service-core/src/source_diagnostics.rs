//! Feature-gated fixed Source closeout stage labels; no request or error data is emitted.
// Rust guideline compliant 2026-02-21
#[cfg(any(feature = "source-diagnostics", test))]
use std::io::Write;
#[derive(Clone, Copy)]
pub(crate) enum Stage {
    BodyAdmission,
    CurrentGrant,
    SelectedNative,
    RefreshedGrant,
    ReplayAdmission,
    Handler,
    Coordinator,
    Policy,
    Prefix,
    Replay,
    Core,
    FinalGuard,
    ContentRead,
    Evidence,
    RepositoryWrite,
    ZipPublish,
    Receipt,
}
impl Stage {
    #[cfg(any(feature = "source-diagnostics", test))]
    fn label(self) -> &'static str {
        match self {
            Self::BodyAdmission => "body_admission",
            Self::CurrentGrant => "current_grant",
            Self::SelectedNative => "selected_native",
            Self::RefreshedGrant => "refreshed_grant",
            Self::ReplayAdmission => "replay_admission",
            Self::Handler => "handler",
            Self::Coordinator => "coordinator",
            Self::Policy => "policy",
            Self::Prefix => "prefix",
            Self::Replay => "replay",
            Self::Core => "core",
            Self::FinalGuard => "final_guard",
            Self::ContentRead => "content_read",
            Self::Evidence => "evidence",
            Self::RepositoryWrite => "repository_write",
            Self::ZipPublish => "zip_publish",
            Self::Receipt => "receipt",
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Enter,
    ReturnedOk,
    Refused,
    Uncertain,
}
impl Outcome {
    #[cfg(any(feature = "source-diagnostics", test))]
    fn label(self) -> &'static str {
        match self {
            Self::Enter => "enter",
            Self::ReturnedOk => "returned_ok",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
}
#[cfg(any(feature = "source-diagnostics", test))]
fn write_mark(writer: &mut impl Write, stage: Stage, outcome: Outcome) {
    let _ = writeln!(
        writer,
        "trellis_source_server stage={} outcome={}",
        stage.label(),
        outcome.label()
    );
}
pub(crate) fn mark(selected: bool, stage: Stage, outcome: Outcome) {
    #[cfg(feature = "source-diagnostics")]
    if selected {
        write_mark(&mut std::io::stderr().lock(), stage, outcome);
    }
    #[cfg(not(feature = "source-diagnostics"))]
    let _ = (selected, stage, outcome);
}
pub(crate) fn observed<T, E>(selected: bool, stage: Stage, result: Result<T, E>) -> Result<T, E> {
    let outcome = if result.is_ok() {
        Outcome::ReturnedOk
    } else if matches!(stage, Stage::RepositoryWrite) {
        Outcome::Uncertain
    } else {
        Outcome::Refused
    };
    mark(selected, stage, outcome);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn source_diagnostics_write_failure_is_uncertain_and_output_failure_preserves_result() {
        write_mark(&mut Broken, Stage::RepositoryWrite, Outcome::Uncertain);
        let original = Err::<(), _>("PRIVATE_SENTINEL");
        assert_eq!(
            observed(false, Stage::RepositoryWrite, original),
            Err("PRIVATE_SENTINEL")
        );
        let mut output = Vec::new();
        write_mark(&mut output, Stage::RepositoryWrite, Outcome::Uncertain);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "trellis_source_server stage=repository_write outcome=uncertain\n"
        );
    }
}
