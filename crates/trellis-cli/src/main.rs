// Rust guideline compliant 2026-02-21
//! Trellis smoke checks, manual completion and exact certificate extraction.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use integrity_verify::trellis::{Severity, verify_single_event};
use trellis_cddl::parse_ed25519_cose_key;
use trellis_core::{AuthoredEvent, SigningKeyMaterial, append_event};
use trellis_store_memory::MemoryStore;

#[derive(Clone, Copy)]
struct FixtureCase {
    label: &'static str,
    vector_dir: &'static str,
    key_file: &'static str,
}

const FIXTURE_001: FixtureCase = FixtureCase {
    label: "001",
    vector_dir: "001-minimal-inline-payload",
    key_file: "issuer-001.cose_key",
};

const FIXTURE_002: FixtureCase = FixtureCase {
    label: "002",
    vector_dir: "002-rotation-signing-key",
    key_file: "issuer-002.cose_key",
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(message) = run(args.as_slice()) {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn usage_top_level() -> String {
    "usage: trellis-cli <seal-completion|certificate|append-001|append-002|verify-001|verify-002|verify-export <bundle.zip> [--certificate-authorities <registry.json>]>\n\
     \n\
     Fixture commands mirror a small smoke subset of the Trellis append corpus.\n\
     `verify-export` verifies a Trellis/WOS export ZIP through trellis-verify-wos.\n\
     Run the full committed vector set via the `trellis-conformance` binary."
        .to_string()
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(usage_top_level)?;
    dispatch_command(args, command)
}

fn dispatch_command(args: &[String], command: &str) -> Result<(), String> {
    match command {
        "append-001" => append_fixture_command(&FIXTURE_001),
        "append-002" => append_fixture_command(&FIXTURE_002),
        "verify-001" => verify_fixture_command(&FIXTURE_001),
        "verify-002" => verify_fixture_command(&FIXTURE_002),
        "verify-export" => verify_export_command(args),
        "seal-completion" => seal_completion_command(args),
        "certificate" => certificate_command(args),
        _ => Err(format!("unknown command `{command}`")),
    }
}

fn append_fixture_command(fixture: &FixtureCase) -> Result<(), String> {
    let (authored_event, signing_key) = fixture_inputs(fixture)?;
    let mut store = MemoryStore::new();
    let artifacts = append_event(
        &mut store,
        &SigningKeyMaterial::new(signing_key),
        &AuthoredEvent::new(authored_event),
    )
    .map_err(|error| error.to_string())?;

    println!(
        "append/{} canonical={} signed={} append_head={}",
        fixture.label,
        artifacts.canonical_event.len(),
        artifacts.signed_event.len(),
        artifacts.append_head.len()
    );
    Ok(())
}

fn verify_fixture_command(fixture: &FixtureCase) -> Result<(), String> {
    let key_bytes = fs::read(key_path(fixture.key_file))
        .map_err(|error| format!("failed to read key fixture: {error}"))?;
    let parsed_key = parse_ed25519_cose_key(&key_bytes).map_err(|error| error.to_string())?;
    let signed_event = fs::read(fixture_root(fixture.vector_dir).join("expected-event.cbor"))
        .map_err(|error| format!("failed to read event fixture: {error}"))?;

    let report = verify_single_event(parsed_key.public_key, &signed_event)
        .map_err(|error| error.to_string())?;
    println!(
        "structure_verified={} integrity_verified={} readability_verified={}",
        report.structure_verified, report.integrity_verified, report.readability_verified
    );
    Ok(())
}

fn verify_export_command(args: &[String]) -> Result<(), String> {
    let path = args
        .get(2)
        .ok_or_else(|| "usage: trellis-cli verify-export <bundle.zip>".to_string())?;
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read export bundle `{path}`: {error}"))?;
    let report = match args.get(3).map(String::as_str) {
        None => trellis_verify_wos::verify_export_zip(&bytes),
        Some("--certificate-authorities") if args.len() == 5 => {
            let registry_bytes = fs::read(&args[4]).map_err(|e| format!("failed to read external certificate authority registry: {e}"))?;
            let registry = trellis_verify_wos::certificate_authorities_from_json(&registry_bytes)?;
            trellis_verify_wos::verify_export_zip_with_certificate_authorities(&bytes, &registry)
        }
        _ => return Err("usage: trellis-cli verify-export <bundle.zip> [--certificate-authorities <registry.json>]".into()),
    };
    for certificate in &report.trellis.certificates_of_completion {
        println!(
            "certificate={} operator_authority={:?} failures={:?}",
            certificate.certificate_id, certificate.attestation_authority, certificate.failures
        );
    }
    for warning in &report.trellis.warnings {
        println!("warning={warning:?}");
    }
    let trellis_failures = report.trellis.event_failures.len()
        + report.trellis.checkpoint_failures.len()
        + report.trellis.proof_failures.len();
    let wos_failures = report
        .wos_findings
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();
    let failures = trellis_failures + wos_failures;

    println!(
        "verified={} trellis_failures={} wos_findings={}",
        report.trellis.structure_verified && report.trellis.integrity_verified && failures == 0,
        trellis_failures,
        report.wos_findings.len()
    );
    if report.trellis.structure_verified && report.trellis.integrity_verified && failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "export verification failed with {failures} failure finding(s)"
        ))
    }
}

fn seal_completion_command(args: &[String]) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ClientConfig {
        endpoint: String,
        tenant: stack_common_http::tenant::TenantScope,
        bearer_token_file: String,
        caller_bearer_token_file: Option<String>,
    }
    if args.len() != 5 {
        return Err(
            "usage: trellis-cli seal-completion <client-config.json> <scope> <request.json>".into(),
        );
    }
    let config: ClientConfig = serde_json::from_slice(&read_bounded(&args[2], 32 * 1024)?)
        .map_err(|_| "invalid completion client configuration")?;
    let request: trellis_service_client::CompletionRequest =
        serde_json::from_slice(&read_bounded(&args[4], 32 * 1024)?)
            .map_err(|_| "invalid closed completion request")?;
    request.validate().map_err(|e| e.to_string())?;
    // A single manual call uses a token independently acquired by the caller.
    // The server verifies current identity/permissions; no CLI key or closure claim is accepted.
    let token_bytes = read_bounded(&config.bearer_token_file, 16 * 1024)?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| "invalid bearer token file")?
        .trim();
    let caller_authorization = config
        .caller_bearer_token_file
        .as_ref()
        .map(|path| {
            let bytes = read_bounded(path, 8 * 1024)?;
            let token = std::str::from_utf8(&bytes)
                .map_err(|_| "invalid caller bearer token file")?
                .trim();
            let authorization = format!("Bearer {token}");
            trellis_service_client::validate_completion_caller_authorization(&authorization)
                .map_err(|_| "invalid caller bearer token file")?;
            Ok::<_, String>(authorization)
        })
        .transpose()?;
    let client = trellis_service_client::TrellisServiceClient::new(
        trellis_service_client::TrellisServiceClientConfig::new(
            config.endpoint,
            stack_common_http::tenant::HeaderConfig::wos(),
        )
        .with_service_bearer_token(token),
    )
    .map_err(|_| "completion HTTP client configuration failed")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "completion runtime unavailable")?;
    let result = runtime
        .block_on(async {
            if let Some(authorization) = caller_authorization.as_deref() {
                client
                    .seal_completion_with_caller_authorization(
                        &args[3],
                        &config.tenant,
                        &request,
                        authorization,
                    )
                    .await
            } else {
                client
                    .seal_completion(&args[3], &config.tenant, &request)
                    .await
            }
        })
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|_| "completion receipt encoding failed")?
    );
    Ok(())
}

fn certificate_command(args: &[String]) -> Result<(), String> {
    if !matches!(args.len(), 7 | 9)
        || args[3] != "--certificate-id"
        || args[5] != "--out"
        || (args.len() == 9 && args[7] != "--certificate-authorities")
    {
        return Err("usage: trellis-cli certificate <bundle.zip> --certificate-id <id> --out <certificate.html> [--certificate-authorities <registry.json>]".into());
    }
    let zip = read_bounded(&args[2], 16 * 1024 * 1024)?;
    let registry = if args.len() == 9 {
        Some(trellis_verify_wos::certificate_authorities_from_json(
            &read_bounded(&args[8], 32 * 1024)?,
        )?)
    } else {
        None
    };
    let certificate =
        trellis_verify_wos::certificate_html_from_export(&zip, &args[4], registry.as_ref())?;
    use std::io::Write;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[6])
        .map_err(|_| "certificate output must be a new writable file")?;
    output
        .write_all(&certificate.bytes)
        .map_err(|_| "certificate output write failed")?;
    println!(
        "retained_html_bytes={} operator_authority={:?}",
        certificate.bytes.len(),
        certificate.operator_authority
    );
    Ok(())
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|_| "requested input file is unavailable")?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "requested input file is unreadable")?;
    if bytes.len() > maximum {
        return Err("requested input file exceeds limit".into());
    }
    Ok(bytes)
}

fn fixture_inputs(fixture: &FixtureCase) -> Result<(Vec<u8>, Vec<u8>), String> {
    let authored_event =
        fs::read(fixture_root(fixture.vector_dir).join("input-author-event-hash-preimage.cbor"))
            .map_err(|error| format!("failed to read authored fixture: {error}"))?;
    let signing_key = fs::read(key_path(fixture.key_file))
        .map_err(|error| format!("failed to read key fixture: {error}"))?;
    Ok((authored_event, signing_key))
}

fn fixture_root(dir: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../fixtures/vectors/append/{dir}"))
}

fn key_path(file: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../fixtures/vectors/_keys/{file}"))
}

#[cfg(test)]
mod tests {
    use super::{dispatch_command, run};

    #[test]
    fn dispatch_rejects_unknown_command() {
        assert_eq!(
            dispatch_command(
                &["trellis-cli".into(), "not-a-real-command".into()],
                "not-a-real-command"
            )
            .unwrap_err(),
            "unknown command `not-a-real-command`"
        );
    }

    #[test]
    fn dispatch_accepts_fixture_command_names() {
        for cmd in ["append-001", "append-002", "verify-001", "verify-002"] {
            assert!(
                dispatch_command(&["trellis-cli".into(), cmd.into()], cmd).is_ok(),
                "fixture command `{cmd}` should run against committed vectors"
            );
        }
    }

    #[test]
    fn verify_export_requires_path() {
        let err = run(&["trellis-cli".into(), "verify-export".into()]).unwrap_err();
        assert!(err.contains("verify-export <bundle.zip>"), "{err}");
    }
}
