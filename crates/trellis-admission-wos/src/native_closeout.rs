// Rust guideline compliant 2026-02-21
//! WOS native-provenance closeout records behind the [`NativeCloseout`] port.

use integrity_cbor::{decode_cbor_value, map_lookup_bytes, map_lookup_map, sha256_bytes};
use serde::Deserialize;
use stack_common_error::StackError;
use std::sync::Arc;
use trellis_server_ports::event_codec::{cbor_bad_request, event_summary};

use trellis_server_ports::{CloseoutRule, CloseoutSource, NativeCloseout};
use trellis_service_client::source_content::SourceContentIdentityV1;
use trellis_types::StoredEvent;
use wos_events::{
    CustodyAppendContext, CustodyAppendInput, NativeProvenanceEvent, ProvenanceKind,
    ProvenanceRecord, WOS_NATIVE_PROVENANCE_EVENT_LITERAL,
};

/// WOS closeout records carried by the native provenance event literal.
#[derive(Clone, Copy, Debug, Default)]
pub struct WosNativeCloseout;

/// The owning `closeoutRecord` predicate: record kind, optional event name, JSON-pointer tests.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloseoutRecordRule {
    record_kind: String,
    event: Option<String>,
    tests: Vec<ValueTest>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "test", rename_all = "camelCase", deny_unknown_fields)]
enum ValueTest {
    Equals {
        pointer: String,
        value: serde_json::Value,
    },
    Nonblank {
        pointer: String,
    },
}

impl CloseoutRecordRule {
    /// Reads the `closeoutRecord` rule from the owner's pinned native-selection document.
    fn parse(document: &serde_json::Value) -> Result<Self, StackError> {
        let rule = document
            .get("closeoutRecord")
            .ok_or_else(|| StackError::bad_request("Source native closeout rule absent"))?;
        let parsed: Self = serde_json::from_value(rule.clone())
            .map_err(|_| StackError::bad_request("Source native closeout rule invalid"))?;
        serde_json::from_value::<ProvenanceKind>(serde_json::Value::String(
            parsed.record_kind.clone(),
        ))
        .map_err(|_| StackError::bad_request("native Source closeout kind invalid"))?;
        if parsed.tests.len() > 32
            || parsed.tests.iter().any(|test| {
                let (ValueTest::Equals { pointer, .. } | ValueTest::Nonblank { pointer }) = test;
                !pointer.starts_with('/') || pointer.len() > 2048
            })
        {
            return Err(StackError::bad_request(
                "native Source closeout rule invalid",
            ));
        }
        Ok(parsed)
    }

    fn matches(&self, native: &serde_json::Value) -> bool {
        native.get("recordKind").and_then(serde_json::Value::as_str)
            == Some(self.record_kind.as_str())
            && self.event.as_ref().is_none_or(|event| {
                native.get("event").and_then(serde_json::Value::as_str) == Some(event.as_str())
            })
            && self.tests.iter().all(|test| match test {
                ValueTest::Equals { pointer, value } => native.pointer(pointer) == Some(value),
                ValueTest::Nonblank { pointer } => native
                    .pointer(pointer)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
            })
    }
}

impl CloseoutRule for CloseoutRecordRule {
    fn matching_record_id(&self, source: CloseoutSource<'_>) -> Result<Option<String>, StackError> {
        let Some(native) = record(source)? else {
            return Ok(None);
        };
        if !self.matches(&native) {
            return Ok(None);
        }
        native
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(|id| Some(id.to_owned()))
            .ok_or_else(|| StackError::conflict("native Source closeout id absent"))
    }
}

impl NativeCloseout for WosNativeCloseout {
    fn compile_rule(&self, rule: &serde_json::Value) -> Result<Arc<dyn CloseoutRule>, StackError> {
        Ok(Arc::new(CloseoutRecordRule::parse(rule)?))
    }

    fn validate(
        &self,
        source: CloseoutSource<'_>,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError> {
        let (native, event_type) = match source {
            CloseoutSource::Append(body) => (
                NativeProvenanceEvent::from_json(&body.payload)
                    .map_err(|_| StackError::conflict("native closeout payload invalid"))?,
                body.event_type.clone(),
            ),
            CloseoutSource::Stored(event) => {
                let payload = inline_payload(event, "native closeout event malformed")?;
                (
                    NativeProvenanceEvent::from_dcbor_slice(&payload)
                        .map_err(|_| StackError::conflict("native closeout payload invalid"))?,
                    event_summary(event)?.event_type,
                )
            }
        };
        validate_native_closeout(&native, &event_type, selected)
    }
}

/// Native record carried by `source`, or `None` when it is another event type.
fn record(source: CloseoutSource<'_>) -> Result<Option<serde_json::Value>, StackError> {
    match source {
        CloseoutSource::Append(body) => {
            if body.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
                return Ok(None);
            }
            NativeProvenanceEvent::from_json(&body.payload)
                .map(|native| Some(native.record().clone()))
                .map_err(|_| StackError::conflict("native Source closeout append payload invalid"))
        }
        CloseoutSource::Stored(event) => {
            if event_summary(event)?.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
                return Ok(None);
            }
            let bytes = inline_payload(event, "native event malformed")?;
            NativeProvenanceEvent::from_dcbor_slice(&bytes)
                .map(|native| Some(native.record().clone()))
                .map_err(|_| StackError::conflict("native Source closeout payload invalid"))
        }
    }
}

fn inline_payload(event: &StoredEvent, malformed: &'static str) -> Result<Vec<u8>, StackError> {
    let value = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
    let fields = value
        .as_map()
        .ok_or_else(|| StackError::conflict(malformed))?;
    let reference = map_lookup_map(fields, "payload_ref").map_err(cbor_bad_request)?;
    map_lookup_bytes(reference, "ciphertext").map_err(cbor_bad_request)
}

fn validate_native_closeout(
    native: &NativeProvenanceEvent,
    event_type: &str,
    selected: &SourceContentIdentityV1,
) -> Result<(), StackError> {
    let original: ProvenanceRecord = serde_json::from_value(native.record().clone())
        .map_err(|_| StackError::conflict("reserved native closeout record malformed"))?;
    let context = CustodyAppendContext {
        event_type_prefix: "wos".into(),
        case_id: Some(selected.case_ledger_id.clone()),
        max_inline_record_bytes: None,
        workflow_ref: Some(selected.workflow_url.clone()),
    };
    // Position does not alter authored record bytes in the maintained factory.
    let metadata = context
        .metadata_for_provenance_record(&selected.process_id, 0, &original)
        .map_err(|_| StackError::conflict("reserved native closeout metadata invalid"))?;
    let input = CustodyAppendInput::from_provenance_record(&original, &context, metadata)
        .map_err(|_| StackError::conflict("reserved native closeout input invalid"))?;
    if input.case_id != selected.case_ledger_id
        || input.record_id != selected.reserved_closeout_record_id
        || input.event_type != event_type
        || sha256_bytes(input.record_bytes()) != selected.reserved_native_closeout_record_sha256
    {
        return Err(StackError::conflict(
            "reserved native closeout identity changed",
        ));
    }
    Ok(())
}
