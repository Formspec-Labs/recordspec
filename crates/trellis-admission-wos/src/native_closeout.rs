// Rust guideline compliant 2026-02-21
//! WOS native-provenance closeout records behind the [`NativeCloseout`] port.

use integrity_cbor::{decode_cbor_value, map_lookup_bytes, map_lookup_map, sha256_bytes};
use stack_common_error::StackError;
use trellis_server_ports::NativeCloseout;
use trellis_server_ports::event_codec::{cbor_bad_request, event_summary};
use trellis_service_client::SubstrateAppendBody;
use trellis_service_client::source_content::SourceContentIdentityV1;
use trellis_types::StoredEvent;
use wos_events::{
    CustodyAppendContext, CustodyAppendInput, NativeProvenanceEvent, ProvenanceKind,
    ProvenanceRecord, WOS_NATIVE_PROVENANCE_EVENT_LITERAL,
};

/// WOS closeout records carried by the native provenance event literal.
#[derive(Clone, Copy, Debug, Default)]
pub struct WosNativeCloseout;

impl NativeCloseout for WosNativeCloseout {
    fn validate_rule_kind(&self, kind: &str) -> Result<(), StackError> {
        serde_json::from_value::<ProvenanceKind>(serde_json::Value::String(kind.to_owned()))
            .map_err(|_| StackError::bad_request("native Source closeout kind invalid"))?;
        Ok(())
    }

    fn record_from_append(
        &self,
        body: &SubstrateAppendBody,
    ) -> Result<Option<serde_json::Value>, StackError> {
        if body.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
            return Ok(None);
        }
        let native = NativeProvenanceEvent::from_json(&body.payload)
            .map_err(|_| StackError::conflict("native Source closeout append payload invalid"))?;
        Ok(Some(native.record().clone()))
    }

    fn record_from_stored(
        &self,
        event: &StoredEvent,
    ) -> Result<Option<serde_json::Value>, StackError> {
        if event_summary(event)?.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
            return Ok(None);
        }
        let bytes = inline_payload(event, "native event malformed")?;
        let native = NativeProvenanceEvent::from_dcbor_slice(&bytes)
            .map_err(|_| StackError::conflict("native Source closeout payload invalid"))?;
        Ok(Some(native.record().clone()))
    }

    fn validate_append(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError> {
        let native = NativeProvenanceEvent::from_json(payload)
            .map_err(|_| StackError::conflict("native closeout payload invalid"))?;
        validate_native_closeout(&native, event_type, selected)
    }

    fn validate_stored(
        &self,
        event: &StoredEvent,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError> {
        let payload = inline_payload(event, "native closeout event malformed")?;
        let native = NativeProvenanceEvent::from_dcbor_slice(&payload)
            .map_err(|_| StackError::conflict("native closeout payload invalid"))?;
        validate_native_closeout(&native, &event_summary(event)?.event_type, selected)
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
