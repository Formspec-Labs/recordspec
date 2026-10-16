//! Admits committed protected Source members before immutable bundle publication.
// Rust guideline compliant 2026-02-21

use std::collections::BTreeSet;
use std::io::{self, Write};

use async_trait::async_trait;
use integrity_cbor::{Value, decode_cbor_value, domain_separated_sha256, sha256_bytes};
use serde::Deserialize;
use stack_common_error::StackError;
use trellis_export_writer::ExportEvidenceMember;
use trellis_server_ports::{CloseoutSource, NativeCloseout};
use trellis_types::StoredEvent;

use crate::CompletionCallerContext;

// Match the owner's encoded auxiliary/read and final archive budget.
const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 32;

#[doc(inline)]
pub use trellis_service_client::source_content::{
    PreparedSourceContentBatchV1, PreparedSourceContentRecordV1, SourceContentIdentityV1,
    SourceContentOccurrenceV1, SourceContentRecordPins, SourceContentRoleV1,
    SourceContentSelection,
};

/// Request-local qualified context for final Source publication.
pub struct SourceContentRequest<'a> {
    pub selection: &'a SourceContentSelection,
    pub scope: &'a [u8],
    pub events: &'a [StoredEvent],
    pub caller: &'a CompletionCallerContext<'a>,
}

impl std::fmt::Debug for SourceContentRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceContentRequest")
            .field("selection", &self.selection)
            .field("scope", &self.scope)
            .field("event_count", &self.events.len())
            .field("caller", &self.caller)
            .finish()
    }
}

/// Resolves a locator using current configured owner authority and native facts.
pub struct SourceContentSelectionRequest<'a> {
    pub preparation_key: &'a str,
    pub scope: &'a str,
    pub prefix: &'a [StoredEvent],
    pub append_body: &'a trellis_service_client::SubstrateAppendBody,
    pub caller: &'a CompletionCallerContext<'a>,
    pub tenant: &'a stack_common_http::tenant::TenantScope,
}
impl std::fmt::Debug for SourceContentSelectionRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceContentSelectionRequest")
            .field("preparation_key", &self.preparation_key)
            .field("scope", &self.scope)
            .field("prefix_count", &self.prefix.len())
            .field("caller", &self.caller)
            .finish()
    }
}

/// Resolves independent selection before reading the exact committed first bytes.
#[async_trait]
pub trait SourceContentSelectionResolver: Send + Sync {
    /// Qualifies locator, actual native body/prefix and independently configured pins.
    ///
    /// # Errors
    /// Refuses foreign, changed, revoked, or unavailable owning selections.
    async fn select(
        &self,
        request: &SourceContentSelectionRequest<'_>,
    ) -> Result<SourceContentSelection, StackError>;
}

// The header is only a locator. It supplies neither provider URLs nor authority.
pub(crate) const PREPARATION_KEY_HEADER: &str =
    trellis_service_client::source_content::SOURCE_CONTENT_PREPARATION_KEY_HEADER;

pub(crate) fn preparation_key(headers: &axum::http::HeaderMap) -> Result<Option<&str>, StackError> {
    let mut values = headers.get_all(PREPARATION_KEY_HEADER).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(StackError::bad_request(
            "Source preparation locator is ambiguous",
        ));
    }
    first
        .map(|value| {
            let text = value
                .to_str()
                .map_err(|_| StackError::bad_request("Source preparation locator invalid"))?;
            if text.is_empty()
                || text.len() > 256
                || !text.is_ascii()
                || text
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            {
                return Err(StackError::bad_request(
                    "Source preparation locator invalid",
                ));
            }
            Ok(text)
        })
        .transpose()
}

/// Reads existing committed content with current owning read authority.
#[async_trait]
pub trait SourceContentContributor: Send + Sync {
    /// Reads the exact retained batch; preparation and writes are forbidden here.
    ///
    /// # Errors
    /// Refuses unavailable, foreign, revoked, incomplete, or changed selections.
    async fn read(
        &self,
        request: &SourceContentRequest<'_>,
    ) -> Result<PreparedSourceContentBatchV1, StackError>;

    /// Cross-checks the returned catalogs and every record with the owner's parsers.
    ///
    /// # Errors
    /// Refuses any catalog, inventory, locator or opening that differs from the selection.
    fn check_batch(
        &self,
        selected: &SourceContentSelection,
        batch: &PreparedSourceContentBatchV1,
    ) -> Result<(), StackError>;
}

/// Classifies a final prefix using independently configured native policy.
///
/// This pure gate performs no network read and runs before every retained shortcut.
pub trait SourceContentFinalPrefixGuard: Send + Sync {
    /// Matches actual native closeout identity under the configured policy.
    ///
    /// # Errors
    /// Refuses unsupported or ambiguous closeout policy and native associations.
    fn classify(
        &self,
        scope: &[u8],
        events: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError>;

    /// Classifies the actual append body before cached HTTP responses can be returned.
    ///
    /// # Errors
    /// Refuses unsupported native body or existing closeout relationships.
    fn classify_append(
        &self,
        scope: &[u8],
        body: &trellis_service_client::SubstrateAppendBody,
        prefix: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError>;
}

/// Mandatory publication purpose derived from independently configured native policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceContentPrefixClass {
    Ordinary,
    FinalCloseout {
        reserved_closeout_record_id: String,
        native_policy_hash: [u8; 32],
    },
}

/// Checks native, registry, checkpoint, and member relationships through the owner.
pub trait StructuralSourcePublicationVerifier: Send + Sync {
    /// Admits the complete export for explicit protected-member publication.
    ///
    /// # Errors
    /// Refuses any native, registry, checkpoint, or member identity failure.
    fn verify(&self, zip: &[u8]) -> Result<(), StackError>;
}

/// Explicit selected read and verification dependencies, without reader write authority.
#[derive(Clone)]
pub struct SourceContentComposition {
    pub selection_resolver: std::sync::Arc<dyn SourceContentSelectionResolver>,
    pub contributor: std::sync::Arc<dyn SourceContentContributor>,
    pub final_prefix_guard: std::sync::Arc<dyn SourceContentFinalPrefixGuard>,
    pub structural: std::sync::Arc<dyn StructuralSourcePublicationVerifier>,
}

/// Startup inputs the owner adapter needs to build its Source-content ports.
pub struct SourceContentInputs {
    pub client: trellis_service_client::TrellisServiceClient,
    pub tenant: stack_common_http::tenant::TenantScope,
    pub pins: ConfiguredSourceContentPins,
    pub authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
    pub closeout: std::sync::Arc<dyn NativeCloseout>,
}

/// The owner adapter's ports; the server adds its own final-prefix guard.
pub struct SourceContentParts {
    pub selection_resolver: std::sync::Arc<dyn SourceContentSelectionResolver>,
    pub contributor: std::sync::Arc<dyn SourceContentContributor>,
    pub structural: std::sync::Arc<dyn StructuralSourcePublicationVerifier>,
}

/// Builds the owner adapter's Source-content ports from startup inputs.
pub type SourceContentFactory =
    std::sync::Arc<dyn Fn(SourceContentInputs) -> SourceContentParts + Send + Sync>;
impl std::fmt::Debug for SourceContentComposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceContentComposition { selected read and verification ports }")
    }
}
impl SourceContentComposition {
    pub(crate) fn require_publication_purpose(
        &self,
        scope: &[u8],
        events: &[StoredEvent],
        source: Option<&ProtectedSourceMembersReady>,
        closeout: &dyn NativeCloseout,
    ) -> Result<(), StackError> {
        match (self.final_prefix_guard.classify(scope, events)?, source) {
            (SourceContentPrefixClass::Ordinary, None) => Ok(()),
            (
                SourceContentPrefixClass::FinalCloseout {
                    reserved_closeout_record_id,
                    native_policy_hash,
                },
                Some(source),
            ) if source.selection.identity.reserved_closeout_record_id
                == reserved_closeout_record_id
                && source.selection.identity.native_policy_hash == native_policy_hash =>
            {
                validate_prefix(scope, events, &source.selection, closeout)
            }
            (SourceContentPrefixClass::FinalCloseout { .. }, None) => Err(StackError::unavailable(
                "final closeout requires committed Source content",
            )),
            _ => Err(refused()),
        }
    }

    pub(crate) fn verify_structural(&self, zip: &[u8]) -> Result<(), StackError> {
        self.structural.verify(zip)
    }
}

/// Complete protected member admission; actual Source opening remains the reader gate.
#[derive(Clone, Debug)]
pub(crate) struct ProtectedSourceMembersReady {
    pub(crate) selection: SourceContentSelection,
    members: Vec<ExportEvidenceMember>,
}

struct EncodedBound(usize);
impl Write for EncodedBound {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_BATCH_BYTES)
            .ok_or_else(|| io::Error::other("Source batch encoded size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn refused() -> StackError {
    StackError::conflict("committed Source content selection differs")
}

pub(crate) async fn read_admitted(
    composition: &SourceContentComposition,
    closeout: &dyn NativeCloseout,
    request: &SourceContentRequest<'_>,
) -> Result<ProtectedSourceMembersReady, StackError> {
    if request.caller.person_authorization().is_none() {
        return Err(StackError::unavailable(
            "qualified Source content caller is absent",
        ));
    }
    validate_prefix(request.scope, request.events, request.selection, closeout)?;
    let batch = composition.contributor.read(request).await?;
    admit_batch(
        request.scope,
        request.events,
        request.selection,
        batch,
        composition.contributor.as_ref(),
        closeout,
    )
}

fn validate_prefix(
    scope: &[u8],
    events: &[StoredEvent],
    selected: &SourceContentSelection,
    closeout_codec: &dyn NativeCloseout,
) -> Result<(), StackError> {
    trellis_types::completion_selection::completion_prefix_bounds(events)
        .map_err(StackError::bad_request)?;
    let hashes = events
        .iter()
        .map(|event| crate::event_hash(scope, event))
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = selected.native_prefix_event_hashes.clone();
    expected.extend(&selected.photo_event_hashes);
    let closeout = events.last().ok_or_else(refused)?;
    closeout_codec.validate(CloseoutSource::Stored(closeout), &selected.identity)?;
    expected.push(crate::event_hash(scope, closeout)?);
    if hashes != expected {
        return Err(refused());
    }
    let n = selected.native_prefix_event_hashes.len();
    if n == 0
        || trellis_types::completion_selection::completion_selection_prefix_digest(
            scope,
            &events[..n],
        )
        .map_err(StackError::bad_request)?
            != selected.identity.native_prefix_digest
    {
        return Err(refused());
    }
    if events.iter().any(|event| event.scope() != scope) {
        return Err(refused());
    }
    // Every suffix hash was independently admitted; an arbitrary descendant is refused.
    Ok(())
}

/// Locator key the owner and the server both derive from a batch's selection and occurrences.
///
/// # Errors
/// Refuses a batch that cannot be canonically hashed.
pub fn source_content_batch_key(
    batch: &PreparedSourceContentBatchV1,
) -> Result<String, StackError> {
    let occurrences = batch
        .records
        .iter()
        .map(|record| &record.occurrence)
        .collect::<Vec<_>>();
    let value = serde_json::to_value((&batch.selection, occurrences)).map_err(|_| refused())?;
    stack_common_hash::canonical_json_hash(&value).map_err(|_| refused())
}

fn admit_batch(
    scope: &[u8],
    events: &[StoredEvent],
    selected: &SourceContentSelection,
    batch: PreparedSourceContentBatchV1,
    contributor: &dyn SourceContentContributor,
    closeout: &dyn NativeCloseout,
) -> Result<ProtectedSourceMembersReady, StackError> {
    validate_prefix(scope, events, selected, closeout)?;
    serde_json::to_writer(&mut EncodedBound(0), &batch).map_err(|_| refused())?;
    if batch.version != 1
        || source_content_batch_key(&batch)? != selected.preparation_key
        || batch.selection != selected.identity
        || batch.records.is_empty()
        || batch.records.len() > MAX_RECORDS
        || batch.records.len() != selected.record_pins.len()
        || sha256_bytes(&batch.intake_handoffs) != selected.intake_catalog_sha256
        || sha256_bytes(&batch.source_signed_tasks) != selected.task_catalog_sha256
    {
        return Err(refused());
    }
    contributor.check_batch(selected, &batch)?;
    let mut records = BTreeSet::new();
    let mut members = Vec::with_capacity(batch.records.len() + 2);
    for (record, pins) in batch.records.iter().zip(&selected.record_pins) {
        let actual = SourceContentRecordPins {
            role: record.occurrence.role,
            occurrence_event_hash: record.occurrence.occurrence_event_hash,
            response_id: record.occurrence.response_id.clone(),
            source_publication_hash: record.occurrence.publication_hash,
            public_signing_policy_hash: record.occurrence.public_signing_policy_hash,
            evaluation_registration_hash: record.occurrence.evaluation_registration_hash,
            record_sha256: record.record_sha256,
            member_content_hash: record.member_content_hash,
            locator_sha256: sha256_bytes(&record.locator_cbor),
        };
        if actual != *pins
            || !records.insert((
                record.occurrence.role,
                record.occurrence.occurrence_event_hash,
            ))
            || record.protected_record_bytes.is_empty()
            || sha256_bytes(&record.protected_record_bytes) != record.record_sha256
            || domain_separated_sha256(
                trellis_types::CONTENT_DOMAIN,
                &record.protected_record_bytes,
            ) != record.member_content_hash
            || !selected
                .native_prefix_event_hashes
                .contains(&record.occurrence.occurrence_event_hash)
            || (record.occurrence.role == SourceContentRoleV1::TaskProofPackage)
                != record.occurrence.response_id.is_none()
        {
            return Err(refused());
        }
        decode_cbor_value(&record.locator_cbor).map_err(|_| refused())?;
        members.push(ExportEvidenceMember::Payload {
            content_hash: record.member_content_hash,
            bytes: record.protected_record_bytes.clone(),
        });
    }
    members.push(ExportEvidenceMember::IntakeHandoffs {
        bytes: batch.intake_handoffs,
    });
    members.push(ExportEvidenceMember::SignatureAffirmations {
        bytes: batch.source_signed_tasks,
    });
    Ok(ProtectedSourceMembersReady {
        selection: selected.clone(),
        members,
    })
}

fn preserved_catalog(original: &[u8], prepared: &[u8]) -> Result<(), StackError> {
    let old = decode_cbor_value(original).map_err(|_| refused())?;
    let new = decode_cbor_value(prepared).map_err(|_| refused())?;
    let old_rows = old.as_array().ok_or_else(refused)?;
    let new_rows = new.as_array().ok_or_else(refused)?;
    for row in old_rows {
        if new_rows
            .iter()
            .filter(|candidate| *candidate == row)
            .count()
            != 1
        {
            return Err(refused());
        }
    }
    let encoded = new_rows
        .iter()
        .map(|row| integrity_cbor::encode_canonical_cbor_value(row).map_err(|_| refused()))
        .collect::<Result<Vec<_>, _>>()?;
    if encoded.iter().collect::<BTreeSet<_>>().len() != encoded.len() {
        return Err(refused());
    }
    Ok(())
}

impl ProtectedSourceMembersReady {
    pub(crate) fn verify_retained_members(&self, zip: &[u8]) -> Result<(), StackError> {
        archive_bound(zip)?;
        let entries = integrity_bundle::read_stored_zip(zip).map_err(|_| refused())?;
        for member in &self.members {
            let (path, expected) = match member {
                ExportEvidenceMember::Payload {
                    content_hash,
                    bytes,
                } => (
                    format!("060-payloads/{}.bin", hex::encode(content_hash)),
                    bytes,
                ),
                ExportEvidenceMember::IntakeHandoffs { bytes } => {
                    ("063-intake-handoffs.cbor".into(), bytes)
                }
                ExportEvidenceMember::SignatureAffirmations { bytes } => {
                    ("062-signature-affirmations.cbor".into(), bytes)
                }
                _ => return Err(refused()),
            };
            let suffix = format!("/{path}");
            let mut found = entries
                .iter()
                .filter(|entry| entry.path().ends_with(&suffix));
            let actual = found.next().ok_or_else(refused)?;
            if found.next().is_some() || actual.bytes() != expected {
                return Err(refused());
            }
        }
        Ok(())
    }

    pub(crate) fn merge_members(
        &self,
        existing: Vec<ExportEvidenceMember>,
    ) -> Result<Vec<ExportEvidenceMember>, StackError> {
        let mut members = Vec::with_capacity(existing.len() + self.members.len());
        for member in existing {
            let replacement = match &member {
                ExportEvidenceMember::SignatureAffirmations { bytes } => {
                    self.members.iter().find_map(|candidate| match candidate {
                        ExportEvidenceMember::SignatureAffirmations { bytes: prepared } => {
                            Some((bytes, prepared))
                        }
                        _ => None,
                    })
                }
                ExportEvidenceMember::IntakeHandoffs { bytes } => {
                    self.members.iter().find_map(|candidate| match candidate {
                        ExportEvidenceMember::IntakeHandoffs { bytes: prepared } => {
                            Some((bytes, prepared))
                        }
                        _ => None,
                    })
                }
                _ => None,
            };
            if let Some((old, prepared)) = replacement {
                preserved_catalog(old, prepared)?;
            } else {
                members.push(member);
            }
        }
        for member in &self.members {
            if let ExportEvidenceMember::Payload {
                content_hash,
                bytes,
            } = member
            {
                if let Some(previous) = members.iter().find_map(|candidate| match candidate {
                    ExportEvidenceMember::Payload {
                        content_hash: hash,
                        bytes,
                    } if hash == content_hash => Some(bytes),
                    _ => None,
                }) {
                    if previous != bytes {
                        return Err(refused());
                    }
                    continue;
                }
            }
            members.push(member.clone());
        }
        Ok(members)
    }
}

pub(crate) fn archive_bound(zip: &[u8]) -> Result<(), StackError> {
    if zip.len() > MAX_BATCH_BYTES {
        return Err(StackError::bad_request("final Source archive byte limit"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog(values: Vec<Value>) -> Vec<u8> {
        integrity_cbor::encode_canonical_cbor_value(&Value::Array(values)).unwrap()
    }
    #[test]
    fn replacement_preserves_every_existing_row_and_refuses_duplicate_rows() {
        let old = catalog(vec![Value::Text("existing affirmation".into())]);
        let good = catalog(vec![
            Value::Text("existing affirmation".into()),
            Value::Text("Source task".into()),
        ]);
        assert!(preserved_catalog(&old, &good).is_ok());
        assert!(
            preserved_catalog(&old, &catalog(vec![Value::Text("Source task".into())])).is_err()
        );
        assert!(
            preserved_catalog(
                &old,
                &catalog(vec![
                    Value::Text("existing affirmation".into()),
                    Value::Text("existing affirmation".into())
                ])
            )
            .is_err()
        );
    }
    #[test]
    fn encoded_bound_counts_json_byte_array_overhead() {
        let mut bounded = EncodedBound(MAX_BATCH_BYTES - 2);
        assert!(serde_json::to_writer(&mut bounded, &vec![255u8; 1]).is_err());
    }
}

/// Borrowed current append authority for one selected closeout attempt.
///
/// Selection comes from the owning service's qualified reply. Credentials remain
/// request-local and never enter commands, catalogs, state, or retained rows.
pub(crate) struct SourceContentAppendContext<'a> {
    pub(crate) selection: &'a SourceContentSelection,
    pub(crate) headers: &'a axum::http::HeaderMap,
    pub(crate) tenant: &'a stack_common_http::tenant::TenantScope,
    pub(crate) body: &'a trellis_service_client::SubstrateAppendBody,
}

impl SourceContentAppendContext<'_> {
    pub(crate) async fn current_permission(
        &self,
        state: &crate::TrellisServerState,
        scope: &str,
    ) -> Result<trellis_server_ports::AuthorizedScope, StackError> {
        let identity = state.authenticate(self.headers).await?;
        crate::auth::authorize_action(
            state,
            &identity,
            self.tenant,
            scope,
            trellis_server_ports::ScopeAction::Append,
            Some(self.body),
        )
        .await
    }
}

/// Startup-selected public provider pins, independent of returned catalogs.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfiguredSourceContentPins {
    pub provider_selection_hash: [u8; 32],
    pub native_policy_hash: [u8; 32],
    pub recipient_policy_hash: [u8; 32],
}

/// Classifies current native closeout using the independently pinned owning rule.
///
/// The owner's pinned selection document is opaque here; the injected [`NativeCloseout`] adapter owns its meaning.
#[derive(Clone, Debug)]
pub(crate) struct ConfiguredNativeCloseoutGuard {
    pub(crate) closeout: std::sync::Arc<dyn NativeCloseout>,
    native_policy_hash: [u8; 32],
    rule: serde_json::Value,
}
impl ConfiguredNativeCloseoutGuard {
    pub(crate) fn new(
        closeout: std::sync::Arc<dyn NativeCloseout>,
        native_policy_hash: [u8; 32],
        rule: serde_json::Value,
    ) -> Result<Self, StackError> {
        closeout.validate_rule(&rule)?;
        Ok(Self {
            closeout,
            native_policy_hash,
            rule,
        })
    }
    fn final_closeout(&self, id: String) -> SourceContentPrefixClass {
        SourceContentPrefixClass::FinalCloseout {
            reserved_closeout_record_id: id,
            native_policy_hash: self.native_policy_hash,
        }
    }
}
impl SourceContentFinalPrefixGuard for ConfiguredNativeCloseoutGuard {
    fn classify(
        &self,
        _scope: &[u8],
        events: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError> {
        let mut selected = None;
        for (index, event) in events.iter().enumerate() {
            if let Some(id) = self
                .closeout
                .matching_record_id(&self.rule, CloseoutSource::Stored(event))?
            {
                if selected.replace((index, id)).is_some() {
                    return Err(refused());
                }
            }
        }
        let Some((index, id)) = selected else {
            return Ok(SourceContentPrefixClass::Ordinary);
        };
        if index + 1 != events.len() {
            return Err(StackError::conflict(
                "Source-only closeout has an unsupported descendant",
            ));
        }
        Ok(self.final_closeout(id))
    }
    fn classify_append(
        &self,
        scope: &[u8],
        body: &trellis_service_client::SubstrateAppendBody,
        prefix: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError> {
        if let Some(id) = self
            .closeout
            .matching_record_id(&self.rule, CloseoutSource::Append(body))?
        {
            return Ok(self.final_closeout(id));
        }
        self.classify(scope, prefix)
    }
}
