// Rust guideline compliant 2026-02-21
//! WOS record and catalog parsers.

#![forbid(unsafe_code)]

use ciborium::Value;
use trellis_types::{
    CborHelperError, map_lookup_array, map_lookup_bytes, map_lookup_fixed_bytes, map_lookup_map,
    map_lookup_optional_fixed_bytes, map_lookup_optional_value, map_lookup_text,
};

#[derive(Debug)]
pub(crate) struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

impl From<CborHelperError> for ParseError {
    fn from(value: CborHelperError) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for ParseError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ParseError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SignatureManifestEntry {
    pub(crate) canonical_event_hash: [u8; 32],
    pub(crate) signer_id: String,
    pub(crate) role_id: String,
    pub(crate) role: String,
    pub(crate) document_id: String,
    pub(crate) document_hash: String,
    pub(crate) document_hash_algorithm: String,
    pub(crate) signed_at: String,
    pub(crate) identity_binding: Value,
    pub(crate) consent_reference: Value,
    pub(crate) signature_provider: String,
    pub(crate) ceremony_id: String,
    pub(crate) source_signature_system: Option<String>,
    pub(crate) source_signature_id: Option<String>,
    pub(crate) signed_payload_digest: Option<String>,
    pub(crate) signed_payload_digest_algorithm: Option<String>,
    pub(crate) signing_intent: Option<String>,
    pub(crate) profile_ref: Option<String>,
    pub(crate) profile_key: Option<String>,
    pub(crate) formspec_response_ref: String,
    pub(crate) signing_act_id: String,
    pub(crate) presentation_hash: String,
    pub(crate) witnessed_signature_ref: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct SignatureAffirmationRecordDetails {
    pub(crate) signer_id: String,
    pub(crate) role_id: String,
    pub(crate) role: String,
    pub(crate) document_id: String,
    pub(crate) document_ref: Option<Value>,
    pub(crate) document_hash: String,
    pub(crate) document_hash_algorithm: String,
    pub(crate) signed_at: String,
    pub(crate) identity_binding: Value,
    pub(crate) consent_reference: Value,
    pub(crate) signature_provider: String,
    pub(crate) ceremony_id: String,
    pub(crate) source_signature_system: Option<String>,
    pub(crate) source_signature_id: Option<String>,
    pub(crate) signed_payload_digest: Option<String>,
    pub(crate) signed_payload_digest_algorithm: Option<String>,
    pub(crate) signing_intent: Option<String>,
    pub(crate) profile_ref: Option<String>,
    pub(crate) profile_key: Option<String>,
    pub(crate) formspec_response_ref: String,
    pub(crate) signing_act_id: Option<String>,
    pub(crate) presentation_hash: String,
    pub(crate) witnessed_signature_ref: Option<String>,
    pub(crate) primitive_verification: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct SignatureAdmissionFailedRecordDetails {
    pub(crate) reason: String,
    pub(crate) response_id: String,
    pub(crate) signed_payload_digest: String,
    pub(crate) signature_id: String,
    pub(crate) signing_intent: String,
    pub(crate) signer_id: Option<String>,
    pub(crate) emitted_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct IntakeManifestEntry {
    pub(crate) intake_event_hash: [u8; 32],
    pub(crate) case_created_event_hash: Option<[u8; 32]>,
    pub(crate) handoff: IntakeHandoffDetails,
    pub(crate) response_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct IntakeHandoffDetails {
    pub(crate) handoff_id: String,
    pub(crate) initiation_mode: String,
    pub(crate) case_ref: Option<String>,
    pub(crate) definition_url: String,
    pub(crate) definition_version: String,
    pub(crate) response_ref: String,
    pub(crate) response_hash: String,
    pub(crate) validation_report_ref: String,
    pub(crate) ledger_head_ref: String,
}

#[derive(Clone, Debug)]
pub(crate) struct IntakeAcceptedRecordDetails {
    pub(crate) intake_id: String,
    pub(crate) case_intent: String,
    pub(crate) case_disposition: String,
    pub(crate) case_ref: String,
    pub(crate) definition_url: Option<String>,
    pub(crate) definition_version: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CaseCreatedRecordDetails {
    pub(crate) case_ref: String,
    pub(crate) intake_handoff_ref: String,
    pub(crate) formspec_response_ref: String,
    pub(crate) validation_report_ref: String,
    pub(crate) ledger_head_ref: String,
    pub(crate) initiation_mode: String,
}

pub(crate) fn parse_signature_export_digest(bytes: &[u8]) -> Result<[u8; 32], ParseError> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "signature export extension is not a map".to_string())?;
    Ok(bytes_array(&map_lookup_fixed_bytes(
        map,
        "signature_catalog_digest",
        32,
    )?))
}

pub(crate) fn parse_intake_export_digest(bytes: &[u8]) -> Result<[u8; 32], ParseError> {
    let value = decode_value(bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "intake export extension is not a map".to_string())?;
    Ok(bytes_array(&map_lookup_fixed_bytes(
        map,
        "intake_catalog_digest",
        32,
    )?))
}

pub(crate) fn parse_signature_manifest_entries(
    manifest_bytes: &[u8],
) -> Result<Vec<SignatureManifestEntry>, ParseError> {
    let value = decode_value(manifest_bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| "signature affirmation catalog root is not an array".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let map = entry
                .as_map()
                .ok_or_else(|| "signature affirmation catalog entry is not a map".to_string())?;
            Ok(SignatureManifestEntry {
                canonical_event_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "canonical_event_hash",
                    32,
                )?),
                signer_id: map_lookup_text(map, "signer_id")?,
                role_id: map_lookup_text(map, "role_id")?,
                role: map_lookup_text(map, "role")?,
                document_id: map_lookup_text(map, "document_id")?,
                document_hash: map_lookup_text(map, "document_hash")?,
                document_hash_algorithm: map_lookup_text(map, "document_hash_algorithm")?,
                signed_at: map_lookup_text(map, "signed_at")?,
                identity_binding: map_lookup_value_clone(map, "identity_binding")?,
                consent_reference: map_lookup_value_clone(map, "consent_reference")?,
                signature_provider: map_lookup_text(map, "signature_provider")?,
                ceremony_id: map_lookup_text(map, "ceremony_id")?,
                source_signature_system: map_lookup_optional_text(map, "source_signature_system")?,
                source_signature_id: map_lookup_optional_text(map, "source_signature_id")?,
                signed_payload_digest: map_lookup_optional_text(map, "signed_payload_digest")?,
                signed_payload_digest_algorithm: map_lookup_optional_text(
                    map,
                    "signed_payload_digest_algorithm",
                )?,
                signing_intent: map_lookup_optional_text(map, "signing_intent")?,
                profile_ref: map_lookup_optional_text(map, "profile_ref")?,
                profile_key: map_lookup_optional_text(map, "profile_key")?,
                formspec_response_ref: map_lookup_text(map, "formspec_response_ref")?,
                signing_act_id: map_lookup_text(map, "signing_act_id")?,
                presentation_hash: map_lookup_text(map, "presentation_hash")?,
                witnessed_signature_ref: map_lookup_optional_text(map, "witnessed_signature_ref")?,
            })
        })
        .collect()
}

pub(crate) fn parse_intake_manifest_entries(
    manifest_bytes: &[u8],
) -> Result<Vec<IntakeManifestEntry>, ParseError> {
    let value = decode_value(manifest_bytes)?;
    let entries = value
        .as_array()
        .ok_or_else(|| "intake handoff catalog root is not an array".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let map = entry
                .as_map()
                .ok_or_else(|| "intake handoff catalog entry is not a map".to_string())?;
            let handoff = parse_intake_handoff_details(
                map_lookup_optional_value(map, "handoff")
                    .ok_or_else(|| "missing `handoff`".to_string())?,
            )?;
            Ok(IntakeManifestEntry {
                intake_event_hash: bytes_array(&map_lookup_fixed_bytes(
                    map,
                    "intake_event_hash",
                    32,
                )?),
                case_created_event_hash: map_lookup_optional_fixed_bytes(
                    map,
                    "case_created_event_hash",
                    32,
                )?
                .map(|bytes| bytes_array(&bytes)),
                handoff,
                response_bytes: map_lookup_bytes(map, "response_bytes")?,
            })
        })
        .collect()
}

pub(crate) fn parse_signature_affirmation_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<SignatureAffirmationRecordDetails, ParseError> {
    let value = decode_value(payload_bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "signature affirmation payload root is not a map".to_string())?;
    require_event(map, expected_event, "signature affirmation")?;
    let data = map_lookup_map(map, "data")?;
    Ok(SignatureAffirmationRecordDetails {
        signer_id: map_lookup_text(data, "signerId")?,
        role_id: map_lookup_text(data, "roleId")?,
        role: map_lookup_text(data, "role")?,
        document_id: map_lookup_text(data, "documentId")?,
        document_ref: map_lookup_optional_value(data, "documentRef").cloned(),
        document_hash: map_lookup_text(data, "documentHash")?,
        document_hash_algorithm: map_lookup_text(data, "documentHashAlgorithm")?,
        signed_at: map_lookup_text(data, "signedAt")?,
        identity_binding: map_lookup_value_clone(data, "identityBinding")?,
        consent_reference: map_lookup_value_clone(data, "consentReference")?,
        signature_provider: map_lookup_text(data, "signatureProvider")?,
        ceremony_id: map_lookup_text(data, "ceremonyId")?,
        source_signature_system: map_lookup_optional_text(data, "sourceSignatureSystem")?,
        source_signature_id: map_lookup_optional_text(data, "sourceSignatureId")?,
        signed_payload_digest: map_lookup_optional_text(data, "signedPayloadDigest")?,
        signed_payload_digest_algorithm: map_lookup_optional_text(
            data,
            "signedPayloadDigestAlgorithm",
        )?,
        signing_intent: map_lookup_optional_text(data, "signingIntent")?,
        profile_ref: map_lookup_optional_text(data, "profileRef")?,
        profile_key: map_lookup_optional_text(data, "profileKey")?,
        formspec_response_ref: map_lookup_text_alias(
            data,
            "sourceResponseRef",
            "formspecResponseRef",
        )?,
        signing_act_id: map_lookup_optional_text(data, "signingActId")?,
        presentation_hash: map_lookup_text(data, "presentationHash")?,
        witnessed_signature_ref: map_lookup_optional_text(data, "witnessedSignatureRef")?,
        primitive_verification: map_lookup_optional_value(data, "primitiveVerification")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

pub(crate) fn parse_signature_admission_failed_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<SignatureAdmissionFailedRecordDetails, ParseError> {
    let value = decode_value(payload_bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "signature admission-failed payload root is not a map".to_string())?;
    require_event(map, expected_event, "signature admission failed")?;
    let data = map_lookup_map(map, "data")?;
    let evidence = map_lookup_map(data, "evidenceBindings")?;
    Ok(SignatureAdmissionFailedRecordDetails {
        reason: map_lookup_text(data, "reason")?,
        response_id: map_lookup_text(evidence, "responseId")?,
        signed_payload_digest: map_lookup_text(evidence, "signedPayloadDigest")?,
        signature_id: map_lookup_text(evidence, "signatureId")?,
        signing_intent: map_lookup_text(evidence, "signingIntent")?,
        signer_id: map_lookup_optional_text(data, "signerId")?,
        emitted_at: map_lookup_text(data, "emittedAt")?,
    })
}

pub(crate) fn parse_intake_accepted_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<IntakeAcceptedRecordDetails, ParseError> {
    let value = decode_value(payload_bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "intake accepted payload root is not a map".to_string())?;
    require_event(map, expected_event, "intake accepted")?;
    let data = map_lookup_map(map, "data")?;
    let case_ref = map_lookup_text(data, "caseRef")?;
    let outputs = map_lookup_array(map, "outputs")?;
    let Some(output_case_ref) = first_array_text(outputs) else {
        return Err("intake accepted outputs array is missing or empty".into());
    };
    if output_case_ref != case_ref {
        return Err("intake accepted outputs[0] does not match data.caseRef".into());
    }
    Ok(IntakeAcceptedRecordDetails {
        intake_id: map_lookup_text(data, "intakeId")?,
        case_intent: map_lookup_text(data, "caseIntent")?,
        case_disposition: map_lookup_text(data, "caseDisposition")?,
        case_ref,
        definition_url: map_lookup_optional_text(data, "definitionUrl")?,
        definition_version: map_lookup_optional_text(data, "definitionVersion")?,
    })
}

pub(crate) fn parse_case_created_record(
    payload_bytes: &[u8],
    expected_event: &str,
) -> Result<CaseCreatedRecordDetails, ParseError> {
    let value = decode_value(payload_bytes)?;
    let map = value
        .as_map()
        .ok_or_else(|| "case created payload root is not a map".to_string())?;
    require_event(map, expected_event, "case created")?;
    let data = map_lookup_map(map, "data")?;
    let case_ref = map_lookup_text(data, "caseRef")?;
    let outputs = map_lookup_array(map, "outputs")?;
    let Some(output_case_ref) = first_array_text(outputs) else {
        return Err("case created outputs array is missing or empty".into());
    };
    if output_case_ref != case_ref {
        return Err("case created outputs[0] does not match data.caseRef".into());
    }
    Ok(CaseCreatedRecordDetails {
        case_ref,
        intake_handoff_ref: map_lookup_text(data, "intakeHandoffRef")?,
        formspec_response_ref: map_lookup_text(data, "formspecResponseRef")?,
        validation_report_ref: map_lookup_text(data, "validationReportRef")?,
        ledger_head_ref: map_lookup_text(data, "ledgerHeadRef")?,
        initiation_mode: map_lookup_text(data, "initiationMode")?,
    })
}

fn require_event(
    map: &[(Value, Value)],
    expected_event: &str,
    label: &str,
) -> Result<(), ParseError> {
    let event = map_lookup_text(map, "event")?;
    if event == expected_event {
        Ok(())
    } else {
        Err(format!("{label} payload event is not {expected_event}").into())
    }
}

fn parse_intake_handoff_details(value: &Value) -> Result<IntakeHandoffDetails, ParseError> {
    let map = value
        .as_map()
        .ok_or_else(|| "handoff is not a map".to_string())?;
    let initiation_mode = map_lookup_text(map, "initiationMode")?;
    let case_ref = map_lookup_optional_text(map, "caseRef")?;
    match initiation_mode.as_str() {
        "workflowInitiated" if case_ref.is_none() => {
            return Err("workflowInitiated handoff is missing caseRef".into());
        }
        "publicIntake" if case_ref.is_some() => {
            return Err("publicIntake handoff caseRef must be null or absent".into());
        }
        "workflowInitiated" | "publicIntake" => {}
        _ => return Err("handoff initiationMode is unsupported".into()),
    }
    let definition_ref = map_lookup_map(map, "definitionRef")?;
    let response_hash = map_lookup_text(map, "responseHash")?;
    parse_sha256_text(&response_hash)?;
    Ok(IntakeHandoffDetails {
        handoff_id: map_lookup_text(map, "handoffId")?,
        initiation_mode,
        case_ref,
        definition_url: map_lookup_text(definition_ref, "url")?,
        definition_version: map_lookup_text(definition_ref, "version")?,
        response_ref: map_lookup_text(map, "responseRef")?,
        response_hash,
        validation_report_ref: map_lookup_text(map, "validationReportRef")?,
        ledger_head_ref: map_lookup_text(map, "ledgerHeadRef")?,
    })
}

pub(crate) fn cbor_nested_map_semantic_eq(left: &Value, right: &Value) -> bool {
    normalize_cbor_value_for_compare(left) == normalize_cbor_value_for_compare(right)
}

fn normalize_cbor_value_for_compare(value: &Value) -> Value {
    match value {
        Value::Map(pairs) => {
            let mut normalized = pairs
                .iter()
                .map(|(key, value)| {
                    (
                        normalize_cbor_value_for_compare(key),
                        normalize_cbor_value_for_compare(value),
                    )
                })
                .collect::<Vec<_>>();
            normalized.sort_by(|(left, _), (right, _)| {
                cbor_map_key_sort_bytes(left).cmp(&cbor_map_key_sort_bytes(right))
            });
            Value::Map(normalized)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(normalize_cbor_value_for_compare).collect())
        }
        _ => value.clone(),
    }
}

fn cbor_map_key_sort_bytes(key: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(key, &mut buf).expect("cbor map key encode");
    buf
}

fn map_lookup_value_clone(map: &[(Value, Value)], key: &str) -> Result<Value, ParseError> {
    Ok(map_lookup_optional_value(map, key)
        .cloned()
        .ok_or_else(|| format!("missing `{key}`"))?)
}

fn map_lookup_optional_text(
    map: &[(Value, Value)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    let Some(value) = map_lookup_optional_value(map, key) else {
        return Ok(None);
    };
    match value {
        Value::Text(text) => Ok(Some(text.clone())),
        Value::Null => Ok(None),
        _ => Err(format!("{key} must be text or null").into()),
    }
}

fn map_lookup_text_alias(
    map: &[(Value, Value)],
    preferred: &str,
    legacy: &str,
) -> Result<String, ParseError> {
    if let Some(value) = map_lookup_optional_value(map, preferred) {
        return match value {
            Value::Text(text) => Ok(text.clone()),
            _ => Err(format!("{preferred} must be text").into()),
        };
    }
    map_lookup_text(map, legacy).map_err(ParseError::from)
}

fn first_array_text(values: &[Value]) -> Option<String> {
    match values.first()? {
        Value::Text(text) => Some(text.clone()),
        _ => None,
    }
}

pub(crate) fn response_hash_matches(
    value: &str,
    response_bytes: &[u8],
) -> Result<bool, ParseError> {
    Ok(parse_sha256_text(value)? == bytes_array(&trellis_types::sha256_bytes(response_bytes)))
}

fn parse_sha256_text(value: &str) -> Result<[u8; 32], ParseError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("hash text must use sha256: prefix".into());
    };
    let bytes = hex_decode(hex)?;
    Ok(bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sha256 hash text must be 32 bytes".to_string())?)
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ParseError> {
    if value.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Result<u8, ParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex string contains a non-hex digit".into()),
    }
}

pub(crate) fn bytes_array(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("caller validates fixed size")
}

fn decode_value(bytes: &[u8]) -> Result<Value, ParseError> {
    ciborium::from_reader(bytes).map_err(|error| error.to_string().into())
}
