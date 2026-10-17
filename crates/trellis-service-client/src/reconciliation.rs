// Rust guideline compliant 2026-02-21
//! Nonpublishing lookup of the existing Trellis append replay identity.

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use utoipa::ToSchema;

use crate::{COMPLETION_EVENT, SubstrateAppendBody, SubstrateAppendResult, validate_required};

/// Canonical payload bytes and their Trellis content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalAppendContent {
    pub payload_bytes: Vec<u8>,
    pub content_hash: [u8; 32],
}

/// Encodes an append payload once using the maintained Trellis hash construction.
///
/// # Errors
/// Refuses JSON values that cannot be encoded as canonical dCBOR.
pub fn canonical_append_content(
    payload: &serde_json::Value,
) -> Result<CanonicalAppendContent, StackError> {
    let payload_bytes = integrity_cbor::json_to_dcbor_bytes(payload, &[])
        .map_err(|_| StackError::bad_request("append payload cannot be encoded as dCBOR"))?;
    let content_hash =
        integrity_cbor::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &payload_bytes);
    Ok(CanonicalAppendContent {
        payload_bytes,
        content_hash,
    })
}

/// Exact retained identity to reconcile: an event type and idempotency key, plus either the
/// canonical payload hash or, for the completion seal, the certificate id.
///
/// The seal's payload is the HTML Trellis renders, so its caller cannot compute a content
/// hash: a [`COMPLETION_EVENT`] lookup names the `certificateId` instead, and every other event
/// type names the `contentHash`. Exactly one of the two is present. Actor, compute disclosure,
/// the Source-content claim and the original HTTP body digest are not retained replay identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendReconciliationRequest {
    pub event_type: String,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
}

impl AppendReconciliationRequest {
    /// Derives lookup identity from the original maintained append body.
    ///
    /// # Errors
    /// Refuses invalid append fields, keys or canonical payload encoding, and the completion
    /// event, whose lookup is [`Self::for_completion`].
    pub fn from_append_body(body: &SubstrateAppendBody) -> Result<Self, StackError> {
        body.validate()?;
        let request = Self {
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            content_hash: Some(canonical_append_content(&body.payload)?.content_hash),
            certificate_id: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Lookup identity of a completion seal: the seal request's key and certificate id.
    ///
    /// # Errors
    /// Refuses an invalid key or certificate id.
    pub fn for_completion(
        idempotency_key: impl Into<String>,
        certificate_id: impl Into<String>,
    ) -> Result<Self, StackError> {
        let request = Self {
            event_type: COMPLETION_EVENT.into(),
            idempotency_key: idempotency_key.into(),
            content_hash: None,
            certificate_id: Some(certificate_id.into()),
        };
        request.validate()?;
        Ok(request)
    }

    /// Checks the bounded lookup identity without admitting an append.
    ///
    /// # Errors
    /// Refuses empty event types, keys outside the Core byte bound, and an identity that is
    /// not exactly the certificate id for the completion event or the content hash otherwise.
    pub fn validate(&self) -> Result<(), StackError> {
        validate_required("event_type", &self.event_type)?;
        if !trellis_types::idempotency_key_length_in_bound(self.idempotency_key.as_bytes()) {
            return Err(StackError::bad_request(
                "reconciliation key outside Core byte bound",
            ));
        }
        let identity_ok = if self.event_type == COMPLETION_EVENT {
            self.content_hash.is_none()
                && self
                    .certificate_id
                    .as_deref()
                    .is_some_and(|id| !id.trim().is_empty() && id.len() <= 1024)
        } else {
            self.content_hash.is_some() && self.certificate_id.is_none()
        };
        if !identity_ok {
            return Err(StackError::bad_request(
                "reconciliation identity must be the certificate id for the completion event and the content hash otherwise",
            ));
        }
        Ok(())
    }
}

/// Why lookup cannot establish a complete verified receipt or read point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ReconciliationUnknown {
    StoreUnavailable,
    ReceiptUnavailable,
    VerificationFailed,
}

/// Read-only disposition of one original append identity.
///
/// Absence holds only at the reported read point, never for future sends. A committed event
/// without a complete verified retained publication is unknown, not absent. JSON receipt
/// fields are not an independent offline proof; consumers retain their existing proof checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum AppendReconciliation {
    Committed {
        receipt: SubstrateAppendResult,
    },
    Conflict,
    Absent {
        #[serde(rename = "eventCount")]
        event_count: u64,
        #[serde(rename = "lastEventHash")]
        last_event_hash: Option<String>,
    },
    Unknown {
        reason: ReconciliationUnknown,
    },
}
