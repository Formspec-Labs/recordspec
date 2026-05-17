// Rust guideline compliant 2026-05-17
//! Bundle-resident effective policy-closure validation for WOS/Formspec exports.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use ciborium::Value;
use integrity_verify::trellis::{DomainEvent, DomainExport, DomainFinding, Severity};
use trellis_types::{
    map_lookup_array, map_lookup_bool, map_lookup_fixed_bytes, map_lookup_map,
    map_lookup_optional_value, map_lookup_text, map_lookup_u64, sha256_bytes,
};

const EXPORT_MANIFEST_MEMBER: &str = "000-manifest.cbor";
const POLICY_CLOSURE_EXPORT_EXTENSION: &str = "trellis.export.policy-closure.v1";
const POLICY_CLOSURE_MEMBER: &str = "067-policy-closure.cbor";
const POLICY_CLOSURE_SCHEMA_VERSION: u64 = 1;
const REQUIRED_ARTIFACT_KINDS: [&str; 8] = [
    "formspec.signing-intent-registry.v1",
    "formspec.signature-method-registry.v1",
    "wos.signature-posture-floors.v1",
    "wos.signer-authority-shape.v1",
    "wos.identity-proofing-primitives.v1",
    "wos.signature-defaults.v1",
    "wos.signature-deny-rules.v1",
    "wos.signature-tombstones.v1",
];

#[derive(Clone, Debug)]
struct PolicyClosureExportExtension {
    closure_ref: String,
    closure_digest: [u8; 32],
    closure_version: String,
}

pub(crate) fn validate_policy_closure(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    let extension_bytes = export
        .manifest_extensions
        .get(POLICY_CLOSURE_EXPORT_EXTENSION);
    let member_bytes = export.members.get(POLICY_CLOSURE_MEMBER);
    match (extension_bytes, member_bytes) {
        (None, None) => missing_policy_closure_for_signed_scope(export),
        (None, Some(_)) => vec![finding(
            "policy_closure_unbound",
            "067-policy-closure.cbor is present without trellis.export.policy-closure.v1",
        )],
        (Some(_), None) => vec![finding(
            "missing_policy_closure",
            "export is missing 067-policy-closure.cbor",
        )],
        (Some(extension_bytes), Some(member_bytes)) => {
            validate_bound_policy_closure(extension_bytes, member_bytes)
        }
    }
}

fn missing_policy_closure_for_signed_scope(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    if is_export_bundle(export) && contains_signature_affirmation(export.events) {
        vec![advisory(
            "policy_closure_missing_for_signed_scope",
            "export contains signature affirmation events but no policy closure evidence",
        )]
    } else {
        Vec::new()
    }
}

fn is_export_bundle(export: &DomainExport<'_>) -> bool {
    // Parsed export ZIPs carry the signed manifest; projection-only unit contexts may not.
    export.members.contains_key(EXPORT_MANIFEST_MEMBER)
}

fn contains_signature_affirmation(events: &[DomainEvent]) -> bool {
    let signature_affirmation = crate::event_types::wos_signature_affirmation_event_type();
    events
        .iter()
        .any(|event| event.event_type == signature_affirmation)
}

fn validate_bound_policy_closure(
    extension_bytes: &[u8],
    member_bytes: &[u8],
) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    let extension = match parse_policy_closure_export_extension(extension_bytes) {
        Ok(extension) => extension,
        Err(error) => {
            return vec![finding(
                "policy_closure_invalid",
                format!("policy closure export extension is invalid: {error}"),
            )];
        }
    };
    if extension.closure_ref != POLICY_CLOSURE_MEMBER {
        findings.push(finding(
            "policy_closure_invalid",
            format!(
                "policy closure_ref must be {POLICY_CLOSURE_MEMBER}, got {}",
                extension.closure_ref
            ),
        ));
    }
    if sha256_bytes(member_bytes) != extension.closure_digest {
        findings.push(finding(
            "policy_closure_digest_mismatch",
            "policy closure digest does not match manifest extension",
        ));
    }
    if let Err(error) = validate_policy_closure_member(member_bytes, &extension.closure_version) {
        findings.push(finding(
            "policy_closure_invalid",
            format!("067-policy-closure.cbor is invalid: {error}"),
        ));
    }
    findings
}

fn parse_policy_closure_export_extension(
    bytes: &[u8],
) -> Result<PolicyClosureExportExtension, String> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "policy closure export extension is not a map".to_string())?;
    Ok(PolicyClosureExportExtension {
        closure_ref: map_lookup_text(map, "closure_ref").map_err(|error| error.to_string())?,
        closure_digest: map_lookup_fixed_bytes(map, "closure_digest", 32)
            .map_err(|error| error.to_string())?
            .as_slice()
            .try_into()
            .expect("fixed bytes length checked"),
        closure_version: map_lookup_text(map, "closure_version")
            .map_err(|error| error.to_string())?,
    })
}

fn validate_policy_closure_member(bytes: &[u8], expected_version: &str) -> Result<(), String> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "policy closure is not a map".to_string())?;
    let schema_version =
        map_lookup_u64(map, "closure_schema_version").map_err(|error| error.to_string())?;
    if schema_version != POLICY_CLOSURE_SCHEMA_VERSION {
        return Err(format!(
            "closure_schema_version must be {POLICY_CLOSURE_SCHEMA_VERSION}, got {schema_version}"
        ));
    }
    let closure_version =
        map_lookup_text(map, "closure_version").map_err(|error| error.to_string())?;
    if closure_version != expected_version {
        return Err(format!(
            "closure_version {closure_version} does not match manifest extension {expected_version}"
        ));
    }
    validate_verifier_boundary(
        map_lookup_map(map, "verifier_boundary").map_err(|error| error.to_string())?,
    )?;
    validate_artifacts(map_lookup_array(map, "artifacts").map_err(|error| error.to_string())?)
}

fn validate_verifier_boundary(map: &[(Value, Value)]) -> Result<(), String> {
    require_bool(map, "bundle_admission_policy_evidence", true)?;
    require_bool(map, "bundle_trust_roots_authoritative", false)?;
    require_bool(map, "verifier_supplied_trust_roots_required", true)?;
    require_bool(map, "verifier_supplied_adapter_allowlists_required", true)?;
    require_bool(map, "server_operational_config_included", false)
}

fn validate_artifacts(artifacts: &[Value]) -> Result<(), String> {
    if artifacts.is_empty() {
        return Err("artifacts must not be empty".to_string());
    }
    let mut seen_kinds = BTreeSet::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let map = artifact
            .as_map()
            .ok_or_else(|| format!("artifacts[{index}] is not a map"))?;
        validate_artifact(map, index, &mut seen_kinds)?;
    }
    for kind in REQUIRED_ARTIFACT_KINDS {
        if !seen_kinds.contains(kind) {
            return Err(format!("artifacts missing required kind {kind}"));
        }
    }
    Ok(())
}

fn validate_artifact(
    map: &[(Value, Value)],
    index: usize,
    seen_kinds: &mut BTreeSet<String>,
) -> Result<(), String> {
    for field in ["owner", "kind", "version", "ref", "valid_from"] {
        let value = map_lookup_text(map, field).map_err(|error| error.to_string())?;
        if value.trim().is_empty() {
            return Err(format!("artifacts[{index}].{field} must not be empty"));
        }
        if field == "kind" {
            seen_kinds.insert(value);
        }
    }
    let algorithm = map_lookup_text(map, "digest_algorithm").map_err(|error| error.to_string())?;
    if algorithm != "sha-256" {
        return Err(format!(
            "artifacts[{index}].digest_algorithm must be sha-256"
        ));
    }
    map_lookup_fixed_bytes(map, "digest", 32).map_err(|error| error.to_string())?;
    match map_lookup_optional_value(map, "valid_to") {
        None | Some(Value::Null) | Some(Value::Text(_)) => Ok(()),
        Some(_) => Err(format!("artifacts[{index}].valid_to must be text or null")),
    }
}

fn require_bool(map: &[(Value, Value)], key: &str, expected: bool) -> Result<(), String> {
    let actual = map_lookup_bool(map, key).map_err(|error| error.to_string())?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{key} must be {expected}"))
    }
}

fn decode_value(bytes: &[u8]) -> Result<Value, String> {
    ciborium::from_reader(bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
fn encode_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn finding(kind: impl Into<String>, message: impl Into<String>) -> DomainFinding {
    DomainFinding::new(kind, None, Severity::Failure, message)
}

fn advisory(kind: impl Into<String>, message: impl Into<String>) -> DomainFinding {
    DomainFinding::new(kind, None, Severity::Advisory, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use integrity_verify::trellis::{DomainEvent, DomainExport, RecordValidator, TrellisTimestamp};

    use super::*;
    use crate::validator::WosRecordValidator;

    #[test]
    fn policy_closure_validates_when_boundary_and_artifacts_are_present() {
        let member = closure_member("policy-closure-test-v1", false);
        let extension = extension_for(&member, "policy-closure-test-v1");
        let mut members = BTreeMap::new();
        members.insert(POLICY_CLOSURE_MEMBER.to_string(), member);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(POLICY_CLOSURE_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn policy_closure_absence_is_quiet_without_signature_affirmations() {
        let members = bundle_members();
        let manifest_extensions = BTreeMap::new();

        let findings = validate_policy_closure(&DomainExport {
            events: &[],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn policy_closure_missing_for_signed_scope_is_advisory() {
        let members = bundle_members();
        let manifest_extensions = BTreeMap::new();
        let events = vec![signature_affirmation_event()];

        let findings = validate_policy_closure(&DomainExport {
            events: &events,
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].kind, "policy_closure_missing_for_signed_scope");
        assert_eq!(findings[0].severity, Severity::Advisory);
    }

    #[test]
    fn policy_closure_digest_mismatch_is_failure() {
        let member = closure_member("policy-closure-test-v1", false);
        let mut extension = extension_for(&member, "policy-closure-test-v1");
        let mut decoded = decode_value(&extension).expect("extension");
        let map = decoded.as_map_mut().expect("map");
        for (key, value) in map.iter_mut() {
            if key.as_text() == Some("closure_digest") {
                *value = Value::Bytes([0xee; 32].to_vec());
            }
        }
        extension = encode_value(&decoded).expect("encode");
        let mut members = BTreeMap::new();
        members.insert(POLICY_CLOSURE_MEMBER.to_string(), member);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(POLICY_CLOSURE_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "policy_closure_digest_mismatch"),
            "{findings:#?}"
        );
    }

    #[test]
    fn policy_closure_cannot_claim_bundle_trust_roots_are_authoritative() {
        let member = closure_member("policy-closure-test-v1", true);
        let extension = extension_for(&member, "policy-closure-test-v1");
        let mut members = BTreeMap::new();
        members.insert(POLICY_CLOSURE_MEMBER.to_string(), member);
        let mut manifest_extensions = BTreeMap::new();
        manifest_extensions.insert(POLICY_CLOSURE_EXPORT_EXTENSION.to_string(), extension);

        let findings = WosRecordValidator.validate_export(DomainExport {
            events: &[],
            members: &members,
            manifest_extensions: &manifest_extensions,
        });

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "policy_closure_invalid"),
            "{findings:#?}"
        );
    }

    fn extension_for(member: &[u8], closure_version: &str) -> Vec<u8> {
        encode_value(
            &text_map(vec![
                (
                    "closure_digest",
                    Value::Bytes(sha256_bytes(member).to_vec()),
                ),
                (
                    "closure_ref",
                    Value::Text(POLICY_CLOSURE_MEMBER.to_string()),
                ),
                ("closure_version", Value::Text(closure_version.to_string())),
            ])
            .expect("extension"),
        )
        .expect("encode")
    }

    fn closure_member(closure_version: &str, bundle_trust_roots_authoritative: bool) -> Vec<u8> {
        encode_value(
            &text_map(vec![
                ("closure_schema_version", uint(1)),
                ("closure_version", Value::Text(closure_version.to_string())),
                (
                    "verifier_boundary",
                    text_map(vec![
                        ("bundle_admission_policy_evidence", Value::Bool(true)),
                        (
                            "bundle_trust_roots_authoritative",
                            Value::Bool(bundle_trust_roots_authoritative),
                        ),
                        ("verifier_supplied_trust_roots_required", Value::Bool(true)),
                        (
                            "verifier_supplied_adapter_allowlists_required",
                            Value::Bool(true),
                        ),
                        ("server_operational_config_included", Value::Bool(false)),
                    ])
                    .expect("boundary"),
                ),
                (
                    "artifacts",
                    Value::Array(
                        REQUIRED_ARTIFACT_KINDS
                            .iter()
                            .enumerate()
                            .map(|(index, kind)| artifact(index, kind))
                            .collect(),
                    ),
                ),
            ])
            .expect("closure"),
        )
        .expect("encode")
    }

    fn artifact(index: usize, kind: &str) -> Value {
        text_map(vec![
            ("owner", Value::Text(owner_for(kind).to_string())),
            ("kind", Value::Text(kind.to_string())),
            ("version", Value::Text("2026-05-16".to_string())),
            ("ref", Value::Text(format!("urn:test:policy:{kind}"))),
            ("digest_algorithm", Value::Text("sha-256".to_string())),
            ("digest", Value::Bytes([index as u8; 32].to_vec())),
            (
                "valid_from",
                Value::Text("2026-05-16T00:00:00Z".to_string()),
            ),
            ("valid_to", Value::Null),
        ])
        .expect("artifact")
    }

    fn owner_for(kind: &str) -> &str {
        if kind.starts_with("formspec.") {
            "formspec"
        } else {
            "wos"
        }
    }

    fn bundle_members() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([(EXPORT_MANIFEST_MEMBER.to_string(), Vec::new())])
    }

    fn signature_affirmation_event() -> DomainEvent {
        DomainEvent {
            event_type: crate::event_types::wos_signature_affirmation_event_type().to_string(),
            payload: None,
            canonical_event_hash: [0x67; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, String> {
        let mut fields = fields
            .into_iter()
            .map(|(key, value)| {
                let key = Value::Text(key.to_string());
                let encoded = encode_value(&key)?;
                Ok((encoded, key, value))
            })
            .collect::<Result<Vec<_>, String>>()?;
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Value::Map(
            fields
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect(),
        ))
    }

    fn uint(value: u64) -> Value {
        Value::Integer(value.into())
    }
}
