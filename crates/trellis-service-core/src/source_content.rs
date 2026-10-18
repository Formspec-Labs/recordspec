//! Admits committed protected Source members before immutable bundle publication.
// Rust guideline compliant 2026-02-21

use std::collections::BTreeSet;

use async_trait::async_trait;
use integrity_cbor::{decode_cbor_value, domain_separated_sha256, sha256_bytes};
use serde::Deserialize;
use stack_common_error::StackError;
use trellis_export_writer::ExportEvidenceMember;
use trellis_server_ports::{CloseoutRule, CloseoutSource, NativeCloseout};
use trellis_types::StoredEvent;

use std::sync::Arc;
use std::time::Duration;

use stack_common_object_store::ScopedObjects;
use trellis_server_ports::{LedgerScope, SourceContentBinding, source_content_object_name};

use crate::TrellisScoped;

// Match the owner's encoded auxiliary/read and final archive budget.
const MAX_BATCH_BYTES: usize =
    trellis_service_client::source_content::MAX_PREPARED_SOURCE_CONTENT_BYTES;
use trellis_service_client::source_content::MAX_SOURCE_CONTENT_RECORDS as MAX_RECORDS;

/// Whole-append budget the object read draws from (ADR 0163 5.1: "the append's remaining budget").
pub(crate) const APPEND_BUDGET: Duration = Duration::from_secs(120);

#[doc(inline)]
pub use trellis_service_client::source_content::{
    PreparedSourceContentBatchV1, PreparedSourceContentRecordV1, SourceContentClaim,
    SourceContentIdentityV1, SourceContentOccurrenceV1, SourceContentRecordPins,
    SourceContentRoleV1, SourceContentSelection,
};

/// Stable refusal codes of ADR 0163 section 8. The code is the problem `title`; the
/// HTTP status and `INFRA` code follow the kind of refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceContentRefusal {
    /// The object cannot be read inside the budget: absent, store down or slow (503).
    ObjectMissing,
    /// The stored bytes are not the bytes the claim names (422).
    HashMismatch,
    /// The claim or object disagrees with the ledger or with itself (409).
    ClaimDiffers,
    /// The append principal is not the configured WOS Source publisher (403).
    PublisherMismatch,
    /// The claim's provider pins are not the configured pins (409).
    PinsDiffer,
}

impl SourceContentRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ObjectMissing => "source-content.object-missing",
            Self::HashMismatch => "source-content.hash-mismatch",
            Self::ClaimDiffers => "source-content.claim-differs",
            Self::PublisherMismatch => "source-content.publisher-mismatch",
            Self::PinsDiffer => "source-content.pins-differ",
        }
    }

    pub(crate) fn error(self) -> StackError {
        let (infra, status) = match self {
            Self::ObjectMissing => ("INFRA-5030", http::StatusCode::SERVICE_UNAVAILABLE),
            Self::HashMismatch => ("INFRA-4220", http::StatusCode::UNPROCESSABLE_ENTITY),
            Self::ClaimDiffers | Self::PinsDiffer => ("INFRA-4090", http::StatusCode::CONFLICT),
            Self::PublisherMismatch => ("INFRA-4030", http::StatusCode::FORBIDDEN),
        };
        StackError::new(
            stack_common_error::ErrorCode::new(infra).expect("static error code is valid"),
            status,
            self.code(),
        )
    }
}

/// A claim whose object was read, hash-checked and decoded during admission.
#[derive(Debug)]
pub(crate) struct AdmittedSourceContent {
    pub(crate) claim: SourceContentClaim,
    pub(crate) batch: PreparedSourceContentBatchV1,
}

/// Reads the prepared batch object the claim names, from Trellis's own derived key.
#[async_trait]
pub trait SourceContentObjectReader: Send + Sync {
    /// Reads `claim`'s object from the request scope's `objects`, verifies its SHA-256 and
    /// decodes it.
    ///
    /// The key is the scope's key and the claim's preparation key only; nothing in the claim can
    /// name another object, and `objects` reaches only the admitted scope. The read is bounded by
    /// the claimed size and `budget`.
    ///
    /// # Errors
    /// `source-content.object-missing` when the read fails or times out,
    /// `source-content.hash-mismatch` when the bytes differ from the claim's hash,
    /// `source-content.claim-differs` when they do not decode to the batch the key names.
    async fn read(
        &self,
        objects: &ScopedObjects,
        claim: &SourceContentClaim,
        budget: Duration,
    ) -> Result<PreparedSourceContentBatchV1, StackError>;
}

/// [`SourceContentObjectReader`] over the scope's Source-content objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct StoreSourceContentReader;

#[async_trait]
impl SourceContentObjectReader for StoreSourceContentReader {
    async fn read(
        &self,
        objects: &ScopedObjects,
        claim: &SourceContentClaim,
        budget: Duration,
    ) -> Result<PreparedSourceContentBatchV1, StackError> {
        let key = objects.key(&source_content_object_name(
            &claim.selection.preparation_key,
        )?)?;
        let max = usize::try_from(claim.size)
            .map_err(|_| StackError::bad_request("Source content claim invalid"))?;
        let bytes = objects
            .read_bounded(&key, max, budget)
            .await
            .map_err(|_| SourceContentRefusal::ObjectMissing.error())?;
        if hex::encode(sha256_bytes(&bytes)) != claim.hash {
            return Err(SourceContentRefusal::HashMismatch.error());
        }
        let batch: PreparedSourceContentBatchV1 = serde_json::from_slice(&bytes)
            .map_err(|_| SourceContentRefusal::ClaimDiffers.error())?;
        if source_content_batch_key(&batch)? != claim.selection.preparation_key {
            return Err(SourceContentRefusal::ClaimDiffers.error());
        }
        Ok(batch)
    }
}

/// The owner's parsers cross-check a batch against its selection.
pub trait SourceContentBatchChecker: Send + Sync {
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
    /// `last` is the ledger's most recent event. A closeout can only be the last event, so the body
    /// and `last` decide without reading the rest of the ledger.
    ///
    /// # Errors
    /// Refuses unsupported native body or existing closeout relationships.
    fn classify_append(
        &self,
        scope: &[u8],
        body: &trellis_service_client::SubstrateAppendBody,
        last: Option<&StoredEvent>,
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

/// Configured Source-content admission and verification dependencies.
#[derive(Clone)]
pub struct SourceContentComposition {
    pub object_reader: Arc<dyn SourceContentObjectReader>,
    pub batch_checker: Arc<dyn SourceContentBatchChecker>,
    pub final_prefix_guard: Arc<dyn SourceContentFinalPrefixGuard>,
    pub structural: Arc<dyn StructuralSourcePublicationVerifier>,
    pub pins: ConfiguredSourceContentPins,
    /// The only principal allowed to append a Source closeout (the WOS machine).
    pub publisher: String,
}

/// Startup inputs the owner adapter needs to build its Source-content ports.
pub struct SourceContentInputs {
    pub authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
}

/// The owner adapter's ports; the server adds its own reader, guard and pins.
pub struct SourceContentParts {
    pub batch_checker: Arc<dyn SourceContentBatchChecker>,
    pub structural: Arc<dyn StructuralSourcePublicationVerifier>,
}

/// Builds the owner adapter's Source-content ports from startup inputs.
pub type SourceContentFactory =
    Arc<dyn Fn(SourceContentInputs) -> SourceContentParts + Send + Sync>;
impl std::fmt::Debug for SourceContentComposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceContentComposition { selected read and verification ports }")
    }
}
impl SourceContentComposition {
    /// Checks that the classified prefix and the admitted Source members agree: an ordinary
    /// prefix carries none, a final closeout carries exactly the members its selection names.
    pub(crate) fn require_publication_purpose(
        &self,
        class: SourceContentPrefixClass,
        source: Option<&ProtectedSourceMembersReady>,
    ) -> Result<(), StackError> {
        match (class, source) {
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
                Ok(())
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

/// A batch admitted against its selection; actual Source opening remains the reader gate.
#[derive(Clone, Debug)]
pub(crate) struct ProtectedSourceMembersReady {
    pub(crate) selection: SourceContentSelection,
}

fn refused() -> StackError {
    SourceContentRefusal::ClaimDiffers.error()
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

/// Pure admission of the held batch against the planned ledger prefix; no I/O.
pub(crate) fn admit_batch(
    scope: &[u8],
    events: &[StoredEvent],
    selected: &SourceContentSelection,
    batch: &PreparedSourceContentBatchV1,
    checker: &dyn SourceContentBatchChecker,
    closeout: &dyn NativeCloseout,
) -> Result<ProtectedSourceMembersReady, StackError> {
    validate_prefix(scope, events, selected, closeout)?;
    if batch.version != 1
        || source_content_batch_key(batch)? != selected.preparation_key
        || batch.selection != selected.identity
        || batch.records.is_empty()
        || batch.records.len() > MAX_RECORDS
        || batch.records.len() != selected.record_pins.len()
        || sha256_bytes(&batch.intake_handoffs) != selected.intake_catalog_sha256
        || sha256_bytes(&batch.source_signed_tasks) != selected.task_catalog_sha256
    {
        return Err(refused());
    }
    // The owner's parser names its own reason; the stable code is the claim's.
    checker
        .check_batch(selected, batch)
        .map_err(|error| refused().with_detail(error.title().to_owned()))?;
    let mut records = BTreeSet::new();
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
    }
    Ok(ProtectedSourceMembersReady {
        selection: selected.clone(),
    })
}

/// The export members a Source batch carries: each protected record, the intake handoffs and the
/// signed tasks, in the order the writer binds them.
fn batch_members(batch: &PreparedSourceContentBatchV1) -> Vec<ExportEvidenceMember> {
    let mut members = Vec::with_capacity(batch.records.len() + 2);
    for record in &batch.records {
        members.push(ExportEvidenceMember::Payload {
            content_hash: record.member_content_hash,
            bytes: record.protected_record_bytes.clone(),
        });
    }
    members.push(ExportEvidenceMember::IntakeHandoffs {
        bytes: batch.intake_handoffs.clone(),
    });
    members.push(ExportEvidenceMember::SignatureAffirmations {
        bytes: batch.source_signed_tasks.clone(),
    });
    members
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

/// Merges a Source batch's members into the profile-derived ones: catalogs must preserve every
/// existing row, and a payload present in both must be the same bytes.
pub(crate) fn merge_source_members(
    existing: Vec<ExportEvidenceMember>,
    source: &[ExportEvidenceMember],
) -> Result<Vec<ExportEvidenceMember>, StackError> {
    let mut members = Vec::with_capacity(existing.len() + source.len());
    for member in existing {
        let replacement = match &member {
            ExportEvidenceMember::SignatureAffirmations { bytes } => {
                source.iter().find_map(|candidate| match candidate {
                    ExportEvidenceMember::SignatureAffirmations { bytes: prepared } => {
                        Some((bytes, prepared))
                    }
                    _ => None,
                })
            }
            ExportEvidenceMember::IntakeHandoffs { bytes } => {
                source.iter().find_map(|candidate| match candidate {
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
    for member in source {
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

const BATCH_KEY_ROOT: &str = "source-content-batches";

/// Writes Trellis's own copy of an admitted batch before the closeout commits.
///
/// WOS may purge its object once the closeout commits (ADR 0163), but the export at the closeout
/// checkpoint must still carry the batch's members, so the copy is Trellis's and write-once. The
/// name is the ledger scope plus the digest of the stored bytes, under the scope's key (ADR 0168
/// §1.4), so a retry writes the same bytes to the same key and no other scope can reach it.
///
/// # Errors
/// Refuses a batch over the byte budget or an unavailable artifact store.
pub(crate) async fn retain_batch(
    scoped: &TrellisScoped,
    scope: &LedgerScope,
    batch: &PreparedSourceContentBatchV1,
) -> Result<SourceContentBinding, StackError> {
    let bytes = serde_json::to_vec(batch).map_err(|_| refused())?;
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(StackError::bad_request("Source batch byte limit"));
    }
    let batch_hash = sha256_bytes(&bytes);
    let (key, _) = scoped
        .artifacts()
        .write_once(
            // Under the scope's key already, so the ledger id names the ledger.
            &format!(
                "{}/{BATCH_KEY_ROOT}/{}",
                scope.ledger_id(),
                hex::encode(batch_hash)
            ),
            &bytes,
        )
        .await?;
    Ok(SourceContentBinding {
        batch_hash,
        size: bytes.len() as u64,
        artifact_ref: key,
    })
}

/// The export members of the batch Trellis retained for the closeout the export ends at, whose
/// binding the export's rows carry.
///
/// # Errors
/// Unavailable when no batch is bound to the closeout or its bytes are gone, a conflict when they
/// differ from the binding.
pub(crate) async fn stored_members(
    scoped: &TrellisScoped,
    binding: Option<&SourceContentBinding>,
) -> Result<Vec<ExportEvidenceMember>, StackError> {
    let binding = binding.ok_or_else(|| {
        StackError::unavailable("final closeout requires committed Source content")
    })?;
    let bytes = scoped
        .artifacts()
        .read_optional(&binding.artifact_ref)
        .await?
        .ok_or_else(|| StackError::unavailable("retained Source batch unavailable"))?;
    if bytes.len() as u64 != binding.size || sha256_bytes(&bytes) != binding.batch_hash {
        return Err(StackError::conflict(
            "retained Source batch differs from its binding",
        ));
    }
    let batch: PreparedSourceContentBatchV1 =
        serde_json::from_slice(&bytes).map_err(|_| refused())?;
    Ok(batch_members(&batch))
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
    use integrity_cbor::Value;
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
}

/// The admitted closeout append: its body and the claim whose object admission already read.
pub(crate) struct SourceContentAppendContext<'a> {
    pub(crate) admitted: &'a AdmittedSourceContent,
    pub(crate) body: &'a trellis_service_client::SubstrateAppendBody,
}

impl SourceContentComposition {
    /// Admission steps 1-3 of ADR 0163 5.4 for a body that carries a claim: the append
    /// principal, the configured pins, the closeout body, then the object read.
    ///
    /// Runs before the HTTP replay decision, so every refusal here is current and unrecorded.
    pub(crate) async fn admit_claim(
        &self,
        closeout: &dyn NativeCloseout,
        scoped: &TrellisScoped,
        principal: &str,
        body: &trellis_service_client::SubstrateAppendBody,
        started: std::time::Instant,
    ) -> Result<AdmittedSourceContent, StackError> {
        let claim = body
            .source_content
            .as_ref()
            .ok_or_else(|| StackError::bad_request("Source content claim absent"))?;
        if principal != self.publisher {
            return Err(SourceContentRefusal::PublisherMismatch.error());
        }
        let identity = &claim.selection.identity;
        if identity.provider_selection_hash != self.pins.provider_selection_hash
            || identity.native_policy_hash != self.pins.native_policy_hash
            || identity.recipient_policy_hash != self.pins.recipient_policy_hash
        {
            return Err(SourceContentRefusal::PinsDiffer.error());
        }
        closeout.validate(CloseoutSource::Append(body), identity)?;
        let objects = scoped
            .source_content()
            .ok_or_else(|| StackError::unavailable("Source content object store is absent"))?;
        let batch = self
            .object_reader
            .read(
                objects,
                claim,
                APPEND_BUDGET.saturating_sub(started.elapsed()),
            )
            .await?;
        Ok(AdmittedSourceContent {
            claim: claim.clone(),
            batch,
        })
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
    native_policy_hash: [u8; 32],
    rule: std::sync::Arc<dyn CloseoutRule>,
}
impl ConfiguredNativeCloseoutGuard {
    pub(crate) fn new(
        closeout: std::sync::Arc<dyn NativeCloseout>,
        native_policy_hash: [u8; 32],
        rule: serde_json::Value,
    ) -> Result<Self, StackError> {
        let rule = closeout.compile_rule(&rule)?;
        Ok(Self {
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
                .rule
                .matching_record_id(CloseoutSource::Stored(event))?
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
        last: Option<&StoredEvent>,
    ) -> Result<SourceContentPrefixClass, StackError> {
        if let Some(id) = self.rule.matching_record_id(CloseoutSource::Append(body))? {
            return Ok(self.final_closeout(id));
        }
        self.classify(scope, last.map(std::slice::from_ref).unwrap_or_default())
    }
}
