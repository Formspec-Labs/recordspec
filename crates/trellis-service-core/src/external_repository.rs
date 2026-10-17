//! Atomic retained attachment append over a scope-locked unit of work.
//!
//! One transaction: read the (bounded) prefix, prepare the append through the caller's factory,
//! sign the event, issue its checkpoint, and write event, checkpoint and protected body together.

use stack_common_error::StackError;
use trellis_core::external_attachment::{
    ExternalAttachmentAppend, ExternalAttachmentStore, RetainedExternalAttachment,
    append_external_attachment,
};
use trellis_service_client::{ComputeContext, ComputeSensitivity};
use trellis_types::{
    CONTENT_DOMAIN, StoredCheckpoint, StoredEvent, Value, domain_separated_sha256,
};

use crate::TrellisServerState;
use crate::event_repository::{AttachmentRow, EventRepository};

// A finite scope bound applies before a factory can inspect or protect any input.
const FACTORY_PREFIX_MAX_EVENTS: usize = 256;

/// Prepares native attachment inputs inside the repository's serialized scope snapshot.
///
/// Implementations reuse complete retained protection on retries and obtain fresh protection
/// only for new operations. The repository checks returned scope and operation identity.
pub trait ExternalAttachmentFactory: Send + Sync {
    /// Prepares an append from committed events and an existing retained operation.
    ///
    /// # Errors
    /// Refuses unavailable protection, inconsistent accepted facts or changed retry identity.
    fn prepare(
        &self,
        events: &[StoredEvent],
        retained: Option<&RetainedExternalAttachment>,
    ) -> Result<ExternalAttachmentAppend, StackError>;
}

#[cfg(test)]
pub(crate) struct FixedInputFactory(pub(crate) ExternalAttachmentAppend);
#[cfg(test)]
impl ExternalAttachmentFactory for FixedInputFactory {
    fn prepare(
        &self,
        _events: &[StoredEvent],
        _retained: Option<&RetainedExternalAttachment>,
    ) -> Result<ExternalAttachmentAppend, StackError> {
        Ok(self.0.clone())
    }
}

fn validate_factory_request(scope: &[u8], key: &[u8]) -> Result<(), StackError> {
    if scope.is_empty() || !trellis_types::idempotency_key_length_in_bound(key) {
        return Err(StackError::conflict(
            "native factory scope or operation identity invalid",
        ));
    }
    Ok(())
}

fn validate_factory_identity(
    input: &ExternalAttachmentAppend,
    scope: &[u8],
    key: &[u8],
) -> Result<(), StackError> {
    if input.scope != scope || input.idempotency_key != key {
        return Err(StackError::conflict(
            "native factory scope or operation identity changed",
        ));
    }
    Ok(())
}

/// The scope as the core append sees it: the committed prefix, at most one retained retry, and
/// room for the one event it commits.
#[derive(Default)]
struct Snapshot {
    events: Vec<StoredEvent>,
    retained: Option<RetainedExternalAttachment>,
    committed: Option<RetainedExternalAttachment>,
}

impl ExternalAttachmentStore for Snapshot {
    type Error = std::io::Error;
    fn scope_events(&self, _scope: &[u8]) -> Result<Vec<StoredEvent>, Self::Error> {
        Ok(self.events.clone())
    }
    fn retained(
        &self,
        scope: &[u8],
        key: &[u8],
    ) -> Result<Option<RetainedExternalAttachment>, Self::Error> {
        Ok(self
            .retained
            .as_ref()
            .filter(|r| r.event().scope() == scope && r.event().idempotency_key() == Some(key))
            .cloned())
    }
    fn commit(&mut self, retained: RetainedExternalAttachment) -> Result<(), Self::Error> {
        if retained.event().sequence() != self.events.len() as u64 || self.committed.is_some() {
            return Err(std::io::Error::other("snapshot head changed"));
        }
        self.committed = Some(retained);
        Ok(())
    }
}

fn core_error(error: trellis_core::AppendError) -> StackError {
    StackError::conflict(format!("external attachment append refused: {error}"))
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StackError> {
    bytes
        .try_into()
        .map_err(|_| StackError::internal("stored external attachment metadata length invalid"))
}
fn restore(
    event: StoredEvent,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    identity: Vec<u8>,
    hash: Vec<u8>,
    key: Vec<u8>,
) -> Result<RetainedExternalAttachment, StackError> {
    if event.idempotency_key() != Some(key.as_slice())
        || fixed::<32>(hash)? != domain_separated_sha256(CONTENT_DOMAIN, &ciphertext)
    {
        return Err(StackError::internal(
            "stored external attachment row identity invalid",
        ));
    }
    RetainedExternalAttachment::restore_committed(
        event,
        ciphertext,
        fixed(nonce)?,
        fixed(identity)?,
    )
    .map_err(|e| StackError::internal(format!("stored external attachment invalid: {e}")))
}

fn validate_compute(compute: &ComputeContext) -> Result<(), StackError> {
    if compute.actor.trim().is_empty()
        || compute.declaration_id.trim().is_empty()
        || !matches!(
            compute.sensitivity,
            ComputeSensitivity::ReaderHeld | ComputeSensitivity::ProviderReadable
        )
    {
        return Err(StackError::conflict(
            "native attachment custody disclosure invalid",
        ));
    }
    Ok(())
}
pub(crate) fn validate_prefix(events: &[StoredEvent]) -> Result<(), StackError> {
    for event in events {
        if trellis_cddl::parse_external_attachment_profile(event.canonical_event())
            .map_err(|e| StackError::conflict(format!("native prefix profile invalid: {e}")))?
            .is_some()
        {
            continue;
        }
        let value = trellis_types::decode_cbor_value(event.canonical_event())
            .map_err(|e| StackError::conflict(e.to_string()))?;
        let root = value
            .as_map()
            .ok_or_else(|| StackError::conflict("native prefix event map invalid"))?;
        let header = trellis_types::map_lookup_map(root, "header")
            .map_err(|e| StackError::conflict(e.to_string()))?;
        if trellis_types::map_lookup_bytes(header, "classification")
            .map_err(|e| StackError::conflict(e.to_string()))?
            != b"x-trellis-service/public-metadata"
        {
            return Err(StackError::conflict(
                "native export prefix includes unqualified plaintext",
            ));
        }
        let reference = trellis_types::map_lookup_map(root, "payload_ref")
            .map_err(|e| StackError::conflict(e.to_string()))?;
        if trellis_types::map_lookup_text(reference, "ref_type")
            .map_err(|e| StackError::conflict(e.to_string()))?
            != "inline"
        {
            return Err(StackError::conflict(
                "native export prefix includes unmarked external payload",
            ));
        }
        if crate::event_summary(event)?.event_type == crate::completion::COMPLETION_EVENT {
            crate::completion::certificate_html(event)?;
            continue;
        }
        if let Some(Value::Map(extensions)) =
            trellis_types::map_lookup_optional_value(root, "extensions")
        {
            if trellis_types::map_lookup_optional_value(
                extensions,
                "trellis.evidence-attachment-binding.v1",
            )
            .is_some()
            {
                return Err(StackError::conflict(
                    "native export prefix includes unmarked attachment binding",
                ));
            }
        }
    }
    Ok(())
}

/// The committed attachment event and the checkpoint that commits to it.
pub(crate) struct Appended {
    pub(crate) retained: RetainedExternalAttachment,
    pub(crate) checkpoint: StoredCheckpoint,
}

/// Appends (or replays) the attachment named by `key` in one scope-locked transaction.
///
/// # Errors
/// Refuses excessive prefixes, changed custody, stale heads, factory failures and storage faults.
pub(crate) async fn append_with(
    state: &TrellisServerState,
    scope: &[u8],
    key: &[u8],
    compute: &ComputeContext,
    factory: &dyn ExternalAttachmentFactory,
) -> Result<Appended, StackError> {
    validate_factory_request(scope, key)?;
    validate_compute(compute)?;
    let mut tx = state.repository.begin(scope).await?;
    let events = tx.prefix(FACTORY_PREFIX_MAX_EVENTS as u64 + 1).await?;
    if events.len() > FACTORY_PREFIX_MAX_EVENTS {
        return Err(StackError::conflict("native prefix exceeds event bound"));
    }
    validate_prefix(&events)?;
    let retained = tx
        .attachment_by_key(key)
        .await?
        .map(retained_from_row)
        .transpose()?;
    if retained.as_ref().is_some_and(|(_, prior)| prior != compute) {
        return Err(StackError::conflict(
            "external attachment custody disclosure changed",
        ));
    }
    let mut snapshot = Snapshot {
        events,
        retained: retained.map(|(record, _)| record),
        committed: None,
    };
    let input = factory.prepare(&snapshot.events, snapshot.retained.as_ref())?;
    validate_factory_identity(&input, scope, key)?;
    let result = append_external_attachment(&mut snapshot, &state.signing_key.core_key(), input)
        .map_err(core_error)?;
    let Some(new) = snapshot.committed else {
        let checkpoint = tx
            .checkpoint_at(result.event().sequence() + 1)
            .await?
            .ok_or_else(|| StackError::internal("committed attachment has no checkpoint"))?;
        return Ok(Appended {
            retained: result,
            checkpoint,
        });
    };
    let head = tx.head().await?;
    let (event, checkpoint) = state.checkpointer().after(head.as_ref(), new.event())?;
    tx.insert(&event, &checkpoint).await?;
    tx.insert_attachment(&AttachmentRow {
        event: event.clone(),
        ciphertext: new.ciphertext().to_vec(),
        nonce: new.nonce().to_vec(),
        replay_identity: new.replay_identity().to_vec(),
        content_hash: domain_separated_sha256(CONTENT_DOMAIN, new.ciphertext()).to_vec(),
        idempotency_key: key.to_vec(),
        compute_json: serde_json::to_string(compute)
            .map_err(|e| StackError::internal(e.to_string()))?,
    })
    .await?;
    tx.commit().await?;
    Ok(Appended {
        retained: result,
        checkpoint,
    })
}

fn retained_from_row(
    row: AttachmentRow,
) -> Result<(RetainedExternalAttachment, ComputeContext), StackError> {
    let compute = decode_compute(&row.compute_json)?;
    let retained = restore(
        row.event,
        row.ciphertext,
        row.nonce,
        row.replay_identity,
        row.content_hash,
        row.idempotency_key,
    )?;
    Ok((retained, compute))
}

/// The retained ciphertext in `scope` whose `trellis-content-v1` hash is `hash`.
pub(crate) async fn body_by_hash(
    repository: &dyn EventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, StackError> {
    repository
        .attachment_by_content_hash(scope, hash)
        .await?
        .map(retained_from_row)
        .transpose()
        .map(|r| r.map(|(r, _)| r.ciphertext().to_vec()))
}

/// The custody disclosure under which the ciphertext with `hash` was retained.
pub(crate) async fn compute_by_hash(
    repository: &dyn EventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<ComputeContext>, StackError> {
    repository
        .attachment_by_content_hash(scope, hash)
        .await?
        .map(retained_from_row)
        .transpose()
        .map(|r| r.map(|(_, c)| c))
}

fn decode_compute(json: &str) -> Result<ComputeContext, StackError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| StackError::internal(format!("stored custody JSON invalid: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| StackError::internal("stored custody disclosure is not an object"))?;
    if object.len() != 3
        || object
            .keys()
            .any(|k| !["declarationId", "actor", "sensitivity"].contains(&k.as_str()))
    {
        return Err(StackError::internal(
            "stored custody disclosure fields invalid",
        ));
    }
    let compute = serde_json::from_value(value)
        .map_err(|e| StackError::internal(format!("stored custody disclosure invalid: {e}")))?;
    validate_compute(&compute).map_err(|e| StackError::internal(e.to_string()))?;
    Ok(compute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerSigningKey;
    use crate::event_repository::{
        EventRepository, InMemoryEventRepository, PostgresEventRepository,
    };
    use std::sync::Arc;
    use trellis_core::SigningKeyMaterial;
    use trellis_core::external_attachment::{ExternalAppendLimits, ExternalAttachmentHeader};
    use trellis_export_writer::TrellisTimestamp;
    use trellis_service_client::ComputeSensitivity;
    use trellis_types::{
        Value, decode_cbor_value, map_lookup_bytes, map_lookup_map, map_lookup_u64,
        map_lookup_value,
    };
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-store-postgres-async/tests/support/mod.rs"
        ));
    }
    fn fixture(scope: &[u8]) -> (ExternalAttachmentAppend, SigningKeyMaterial, ComputeContext) {
        let canonical = include_bytes!(
            "../../../fixtures/vectors/append/047-native-external-attachment/expected-event-payload.cbor"
        );
        let value = decode_cbor_value(canonical).unwrap();
        let root = value.as_map().unwrap();
        let header = map_lookup_map(root, "header").unwrap();
        let timestamp = map_lookup_value(header, "authored_at")
            .unwrap()
            .as_array()
            .unwrap();
        let parsed = trellis_cddl::parse_external_attachment_profile(canonical)
            .unwrap()
            .unwrap();
        let input = ExternalAttachmentAppend {
            scope: scope.to_vec(), idempotency_key: parsed.idempotency_key,
            header: ExternalAttachmentHeader {
                event_type: String::from_utf8(map_lookup_bytes(header,"event_type").unwrap()).unwrap(),
                classification: String::from_utf8(map_lookup_bytes(header,"classification").unwrap()).unwrap(),
                authored_at_seconds: u64::try_from(timestamp[0].as_integer().unwrap()).unwrap(),
                authored_at_nanos: u32::try_from(timestamp[1].as_integer().unwrap()).unwrap(),
                retention_tier: map_lookup_u64(header,"retention_tier").unwrap(),
            },
            extensions: map_lookup_value(root,"extensions").unwrap().clone(),
            key_bag: map_lookup_value(root,"key_bag").unwrap().clone(),
            ciphertext: include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/input-attachment-ciphertext.bin").to_vec(),
            nonce: *include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/nonce.bin"),
            original_sha256: parsed.original_sha256, original_byte_length: parsed.original_byte_length,
            preparation_identity: [7;32], expected_head: None,
            limits: ExternalAppendLimits { ciphertext_bytes: 65536, events: 32, metadata_bytes: 65536 },
        };
        (
            input,
            SigningKeyMaterial::new(
                include_bytes!("../../../fixtures/vectors/_keys/issuer-001.cose_key").to_vec(),
            ),
            ComputeContext::new(
                "compute:test-reader",
                "reader",
                ComputeSensitivity::ReaderHeld,
            ),
        )
    }
    fn ordinary_after(prior: &StoredEvent, key: &SigningKeyMaterial) -> StoredEvent {
        let mut value = decode_cbor_value(prior.canonical_event()).unwrap();
        let Value::Map(fields) = &mut value else {
            panic!("event map");
        };
        fields.retain(|(k, _)| k.as_text() != Some("author_event_hash"));
        for (k, v) in fields {
            match k.as_text().unwrap() {
                "sequence" => *v = Value::Integer((prior.sequence() + 1).into()),
                "prev_hash" => *v = Value::Bytes(prior.canonical_event_hash().unwrap().to_vec()),
                "idempotency_key" => *v = Value::Bytes(b"ordinary-later-event".to_vec()),
                "extensions" => *v = Value::Null,
                "content_hash" => {
                    *v = Value::Bytes(
                        domain_separated_sha256(CONTENT_DOMAIN, b"public metadata").to_vec(),
                    )
                }
                "payload_ref" => {
                    *v = Value::Map(vec![
                        (Value::Text("ref_type".into()), Value::Text("inline".into())),
                        (
                            Value::Text("ciphertext".into()),
                            Value::Bytes(b"public metadata".to_vec()),
                        ),
                        (Value::Text("nonce".into()), Value::Bytes(vec![0; 12])),
                    ])
                }
                "header" => {
                    let Value::Map(header) = v else {
                        panic!("header");
                    };
                    header
                        .iter_mut()
                        .find(|(k, _)| k.as_text() == Some("classification"))
                        .unwrap()
                        .1 = Value::Bytes(b"x-trellis-service/public-metadata".to_vec());
                }
                "key_bag" => {
                    *v = Value::Map(vec![(Value::Text("entries".into()), Value::Array(vec![]))])
                }
                _ => {}
            }
        }
        #[derive(Default)]
        struct Capture(Option<StoredEvent>);
        impl trellis_core::LedgerStore for Capture {
            type Error = std::convert::Infallible;
            fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
                self.0 = Some(event);
                Ok(())
            }
        }
        let mut capture = Capture::default();
        let artifacts = trellis_core::append_event(
            &mut capture,
            key,
            &trellis_core::AuthoredEvent::new(
                trellis_types::encode_canonical_cbor_value(&value).unwrap(),
            ),
        )
        .unwrap();
        capture
            .0
            .unwrap()
            .with_canonical_event_hash(Some(artifacts.canonical_event_hash))
    }
    fn state_over(repository: Arc<dyn EventRepository>) -> TrellisServerState {
        TrellisServerState::new(
            repository,
            ServerSigningKey::from_cose_key_bytes(
                include_bytes!("../../../fixtures/vectors/_keys/issuer-001.cose_key").to_vec(),
                TrellisTimestamp::new(0, 0).unwrap(),
            )
            .unwrap(),
            crate::test_adapters::adapters(),
        )
    }
    async fn append(
        state: &TrellisServerState,
        input: &ExternalAttachmentAppend,
        compute: &ComputeContext,
    ) -> Result<Appended, StackError> {
        append_with(
            state,
            &input.scope,
            &input.idempotency_key,
            compute,
            &FixedInputFactory(input.clone()),
        )
        .await
    }
    /// Appends an event the way the ordinary coordinator would: next sequence, next checkpoint.
    async fn append_ordinary(
        state: &TrellisServerState,
        event: &StoredEvent,
    ) -> Result<(), StackError> {
        let mut tx = state.repository.begin(event.scope()).await?;
        let head = tx.head().await?;
        let (event, checkpoint) = state.checkpointer().after(head.as_ref(), event)?;
        tx.insert(&event, &checkpoint).await?;
        tx.commit().await
    }
    #[tokio::test]
    async fn memory_retains_exact_retry_after_head_advance_and_refuses_changed_custody() {
        let state = state_over(Arc::new(InMemoryEventRepository::new()));
        let (input, key, compute) = fixture(b"memory-native");
        let first = append(&state, &input, &compute).await.unwrap();
        append_ordinary(&state, &ordinary_after(first.retained.event(), &key))
            .await
            .unwrap();
        let retry = append(&state, &input, &compute).await.unwrap();
        assert_eq!(first.retained, retry.retained);
        assert_eq!(
            first.checkpoint, retry.checkpoint,
            "the retry names the original checkpoint"
        );
        assert_eq!(
            state
                .repository
                .list_scope(&input.scope)
                .await
                .unwrap()
                .len(),
            2
        );
        let hash = domain_separated_sha256(CONTENT_DOMAIN, first.retained.ciphertext());
        assert_eq!(
            body_by_hash(state.repository.as_ref(), &input.scope, &hash)
                .await
                .unwrap(),
            Some(first.retained.ciphertext().to_vec())
        );
        assert_eq!(
            compute_by_hash(state.repository.as_ref(), &input.scope, &hash)
                .await
                .unwrap(),
            Some(compute.clone())
        );
        assert!(
            body_by_hash(state.repository.as_ref(), b"other-scope", &hash)
                .await
                .unwrap()
                .is_none()
        );
        let changed =
            ComputeContext::new("changed", "operator", ComputeSensitivity::ProviderReadable);
        assert!(append(&state, &input, &changed).await.is_err());
    }
    #[tokio::test]
    async fn postgres_retention_recovers_on_new_repository_and_exact_retry_after_head_advance() {
        let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
        let pool = support::tls_pool(&cluster, 4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        let state = state_over(Arc::new(PostgresEventRepository::new(pool.clone())));
        let (input, key, compute) = fixture(b"pg-native-recovery");
        let first = append(&state, &input, &compute).await.unwrap();
        let restarted = state_over(Arc::new(PostgresEventRepository::new(pool.clone())));
        append_ordinary(&restarted, &ordinary_after(first.retained.event(), &key))
            .await
            .unwrap();
        let retry = append(&restarted, &input, &compute).await.unwrap();
        assert_eq!(retry.retained, first.retained);
        assert_eq!(retry.checkpoint, first.checkpoint);
        let hash = domain_separated_sha256(CONTENT_DOMAIN, first.retained.ciphertext());
        assert_eq!(
            body_by_hash(restarted.repository.as_ref(), &input.scope, &hash)
                .await
                .unwrap(),
            Some(first.retained.ciphertext().to_vec())
        );
        assert_eq!(
            compute_by_hash(restarted.repository.as_ref(), &input.scope, &hash)
                .await
                .unwrap(),
            Some(compute.clone())
        );
        assert!(
            body_by_hash(restarted.repository.as_ref(), b"foreign", &hash)
                .await
                .unwrap()
                .is_none()
        );
        let changed =
            ComputeContext::new("changed", "operator", ComputeSensitivity::ProviderReadable);
        assert!(append(&restarted, &input, &changed).await.is_err());
        pool.close().await;
    }
    #[tokio::test]
    async fn postgres_body_insert_failure_rolls_back_signed_event_checkpoint_and_body() {
        let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
        let pool = support::tls_pool(&cluster, 4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE trellis_external_attachments ADD CONSTRAINT test_body_insert_refusal CHECK (false)").execute(&pool).await.unwrap();
        let state = state_over(Arc::new(PostgresEventRepository::new(pool.clone())));
        let (input, _key, compute) = fixture(b"pg-native-rollback");
        assert!(append(&state, &input, &compute).await.is_err());
        assert!(
            state
                .repository
                .list_scope(&input.scope)
                .await
                .unwrap()
                .is_empty()
        );
        for table in ["trellis_external_attachments", "trellis_checkpoints"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        sqlx::query(
            "ALTER TABLE trellis_external_attachments DROP CONSTRAINT test_body_insert_refusal",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(append(&state, &input, &compute).await.is_ok());
        pool.close().await;
    }
    #[tokio::test]
    async fn postgres_cross_instance_appends_share_scope_lock_and_reject_stale_head() {
        let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
        let pool = support::tls_pool(&cluster, 4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        let state = state_over(Arc::new(PostgresEventRepository::new(pool.clone())));
        let other = state_over(Arc::new(PostgresEventRepository::new(pool.clone())));
        let (input, key, compute) = fixture(b"pg-native-concurrent");
        let (a, b) = tokio::join!(
            append(&state, &input, &compute),
            append(&other, &input, &compute)
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.retained, b.retained);
        assert_eq!(a.checkpoint, b.checkpoint);
        assert_eq!(
            state
                .repository
                .list_scope(&input.scope)
                .await
                .unwrap()
                .len(),
            1
        );
        let mut stale = input.clone();
        stale.scope = b"pg-stale-empty".to_vec();
        stale.expected_head = Some([9; 32]);
        assert!(append(&other, &stale, &compute).await.is_err());
        assert!(
            other
                .repository
                .list_scope(&stale.scope)
                .await
                .unwrap()
                .is_empty()
        );
        // A held scope lock also blocks an ordinary append on another instance.
        let event = ordinary_after(a.retained.event(), &key);
        let held = trellis_store_postgres_async::begin_scope(&pool, &input.scope)
            .await
            .unwrap();
        let pending = append_ordinary(&other, &event);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
                .await
                .is_err()
        );
        held.commit().await.unwrap();
        pending.await.unwrap();
        assert_eq!(
            state
                .repository
                .list_scope(&input.scope)
                .await
                .unwrap()
                .len(),
            2
        );
        pool.close().await;
    }
    #[test]
    fn retained_restoration_refuses_tampered_body_nonce_and_row_identity() {
        let canonical=include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/expected-event-payload.cbor").to_vec();
        let parsed = trellis_cddl::parse_canonical_event(&canonical).unwrap();
        let hash = trellis_types::domain_separated_sha256(
            trellis_types::EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(&parsed.ledger_scope, &canonical),
        );
        let event=StoredEvent::with_idempotency_key(parsed.ledger_scope,parsed.sequence,canonical,include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/expected-event.cbor").to_vec(),parsed.idempotency_key).with_canonical_event_hash(Some(hash));
        let body=include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/input-attachment-ciphertext.bin").to_vec();
        let nonce = *include_bytes!(
            "../../../fixtures/vectors/append/047-native-external-attachment/nonce.bin"
        );
        assert!(
            RetainedExternalAttachment::restore_committed(
                event.clone(),
                body.clone(),
                nonce,
                [7; 32]
            )
            .is_ok()
        );
        let mut changed = body.clone();
        changed[0] ^= 1;
        assert!(
            RetainedExternalAttachment::restore_committed(event.clone(), changed, nonce, [7; 32])
                .is_err()
        );
        assert!(
            RetainedExternalAttachment::restore_committed(event, body, [0; 12], [7; 32]).is_err()
        );
    }
    #[test]
    fn rejects_unqualified_plaintext_prefix_and_unsupported_custody() {
        let canonical = include_bytes!(
            "../../../fixtures/vectors/append/047-native-external-attachment/expected-event-payload.cbor"
        );
        let mut value = decode_cbor_value(canonical).unwrap();
        let Value::Map(fields) = &mut value else {
            panic!("map");
        };
        fields
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("extensions"))
            .unwrap()
            .1 = Value::Null;
        let event = StoredEvent::new(
            b"neutral-test".to_vec(),
            0,
            trellis_types::encode_canonical_cbor_value(&value).unwrap(),
            vec![],
        );
        assert!(
            validate_prefix(&[event])
                .unwrap_err()
                .to_string()
                .contains("unqualified plaintext")
        );
        assert!(validate_compute(&ComputeContext::no_delegated_compute("operator")).is_err());
        assert!(decode_compute(r#"{"declarationId":"test","actor":"reader","sensitivity":"readerHeld","extra":true}"#).is_err());
    }
    #[test]
    fn rejects_unmarked_external_and_attachment_bound_public_prefix() {
        let (input, key, _compute) = fixture(b"neutral-prefix");
        let canonical=include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/expected-event-payload.cbor").to_vec();
        let parsed = trellis_cddl::parse_canonical_event(&canonical).unwrap();
        let prior = StoredEvent::with_idempotency_key(
            parsed.ledger_scope,
            parsed.sequence,
            canonical,
            vec![],
            input.idempotency_key,
        )
        .with_canonical_event_hash(Some([1; 32]));
        let ordinary = ordinary_after(&prior, &key);
        assert!(validate_prefix(&[ordinary.clone()]).is_ok());
        for kind in ["external", "binding"] {
            let mut value = decode_cbor_value(ordinary.canonical_event()).unwrap();
            let Value::Map(fields) = &mut value else {
                panic!("map");
            };
            if kind == "external" {
                fields
                    .iter_mut()
                    .find(|(k, _)| k.as_text() == Some("payload_ref"))
                    .unwrap()
                    .1 = Value::Map(vec![(
                    Value::Text("ref_type".into()),
                    Value::Text("external".into()),
                )]);
            } else {
                fields
                    .iter_mut()
                    .find(|(k, _)| k.as_text() == Some("extensions"))
                    .unwrap()
                    .1 = Value::Map(vec![(
                    Value::Text("trellis.evidence-attachment-binding.v1".into()),
                    Value::Null,
                )]);
            }
            let event = StoredEvent::new(
                b"neutral-prefix".to_vec(),
                0,
                trellis_types::encode_canonical_cbor_value(&value).unwrap(),
                vec![],
            );
            assert!(
                validate_prefix(&[event]).is_err(),
                "accepted unmarked {kind}"
            );
        }
    }
    #[tokio::test]
    async fn lazy_factory_observes_retained_retry_and_refuses_changed_identity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Factory {
            input: ExternalAttachmentAppend,
            fresh: AtomicUsize,
            replay: AtomicUsize,
        }
        impl ExternalAttachmentFactory for Factory {
            fn prepare(
                &self,
                events: &[StoredEvent],
                retained: Option<&RetainedExternalAttachment>,
            ) -> Result<ExternalAttachmentAppend, StackError> {
                if let Some(prior) = retained {
                    assert!(!events.is_empty());
                    assert_eq!(prior.ciphertext(), self.input.ciphertext);
                    self.replay.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.fresh.fetch_add(1, Ordering::SeqCst);
                }
                Ok(self.input.clone())
            }
        }
        let state = state_over(Arc::new(InMemoryEventRepository::new()));
        let (input, _key, compute) = fixture(b"lazy-factory");
        let factory = Factory {
            input: input.clone(),
            fresh: AtomicUsize::new(0),
            replay: AtomicUsize::new(0),
        };
        async fn run(
            state: &TrellisServerState,
            scope: &[u8],
            input: &ExternalAttachmentAppend,
            compute: &ComputeContext,
            factory: &dyn ExternalAttachmentFactory,
        ) -> Result<Appended, StackError> {
            append_with(state, scope, &input.idempotency_key, compute, factory).await
        }
        let first = run(&state, &input.scope, &input, &compute, &factory)
            .await
            .unwrap();
        let retry = run(&state, &input.scope, &input, &compute, &factory)
            .await
            .unwrap();
        assert_eq!(first.retained, retry.retained);
        assert_eq!(factory.fresh.load(Ordering::SeqCst), 1);
        assert_eq!(factory.replay.load(Ordering::SeqCst), 1);
        assert!(
            run(&state, b"other-scope", &input, &compute, &factory)
                .await
                .is_err()
        );
        assert!(
            state
                .repository
                .list_scope(b"other-scope")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
