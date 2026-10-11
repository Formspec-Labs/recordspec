//! Atomic retained attachment adapters for the maintained Core append path.

use super::{
    ExternalAttachmentFactory, InMemoryEventRepository, PostgresEventRepository,
    map_postgres_append_error,
};
use sqlx::{Postgres, Transaction};
use stack_common_error::StackError;
use std::collections::HashMap;
use trellis_core::{
    SigningKeyMaterial,
    external_attachment::{
        ExternalAttachmentAppend, ExternalAttachmentStore, RetainedExternalAttachment,
        append_external_attachment,
    },
};
use trellis_service_client::{ComputeContext, ComputeSensitivity};
use trellis_types::{CONTENT_DOMAIN, StoredEvent, Value, domain_separated_sha256};

// A finite scope bound applies before a factory can inspect or protect any input.
const FACTORY_PREFIX_MAX_EVENTS: usize = 256;
pub(super) struct FixedInputFactory(pub(super) ExternalAttachmentAppend);
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

#[derive(Default)]
pub(super) struct MemoryState {
    pub(super) events: HashMap<Vec<u8>, Vec<StoredEvent>>,
    retained: HashMap<(Vec<u8>, Vec<u8>), RetainedExternalAttachment>,
    compute: HashMap<(Vec<u8>, Vec<u8>), ComputeContext>,
}

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
fn db_error(error: sqlx::Error) -> StackError {
    StackError::unavailable(format!("external attachment store failed: {error}"))
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
pub(super) fn validate_prefix(events: &[StoredEvent]) -> Result<(), StackError> {
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

pub(super) async fn memory_append_with(
    repo: &InMemoryEventRepository,
    scope: &[u8],
    key: &[u8],
    signing_key: &SigningKeyMaterial,
    compute: &ComputeContext,
    factory: &dyn ExternalAttachmentFactory,
) -> Result<RetainedExternalAttachment, StackError> {
    validate_factory_request(scope, key)?;
    validate_compute(compute)?;
    let mut state = repo.state.lock().await;
    if state
        .events
        .get(scope)
        .is_some_and(|events| events.len() > FACTORY_PREFIX_MAX_EVENTS)
    {
        return Err(StackError::conflict("native prefix exceeds event bound"));
    }
    let scope = scope.to_vec();
    let key = key.to_vec();
    if state
        .compute
        .get(&(scope.clone(), key.clone()))
        .is_some_and(|prior| prior != compute)
    {
        return Err(StackError::conflict(
            "external attachment custody disclosure changed",
        ));
    }

    let mut snapshot = Snapshot {
        events: state.events.get(&scope).cloned().unwrap_or_default(),
        retained: state.retained.get(&(scope.clone(), key.clone())).cloned(),
        committed: None,
    };
    validate_prefix(&snapshot.events)?;
    let input = factory.prepare(&snapshot.events, snapshot.retained.as_ref())?;
    validate_factory_identity(&input, &scope, &key)?;
    let retained =
        append_external_attachment(&mut snapshot, signing_key, input).map_err(core_error)?;
    if let Some(new) = snapshot.committed {
        state
            .events
            .entry(scope.clone())
            .or_default()
            .push(new.event().clone());
        state
            .compute
            .insert((scope.clone(), key.clone()), compute.clone());
        state.retained.insert((scope, key), new);
    }
    Ok(retained)
}
pub(super) async fn memory_body(
    repo: &InMemoryEventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, StackError> {
    let state = repo.state.lock().await;
    Ok(state
        .retained
        .values()
        .find(|r| {
            r.event().scope() == scope
                && &domain_separated_sha256(CONTENT_DOMAIN, r.ciphertext()) == hash
        })
        .map(|r| r.ciphertext().to_vec()))
}

/// Both ordinary and typed appends use this exact transaction-scoped scope lock.
pub(super) async fn lock_scope(
    tx: &mut Transaction<'_, Postgres>,
    scope: &[u8],
) -> Result<(), StackError> {
    let hash = domain_separated_sha256("trellis-append-scope-lock-v1", scope);
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash[..8]);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(prefix))
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}

type EventRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
fn event_from_row(
    (scope, sequence, canonical, signed, key, hash): EventRow,
) -> Result<StoredEvent, StackError> {
    let sequence =
        u64::try_from(sequence).map_err(|_| StackError::internal("stored sequence is negative"))?;
    let event = match key {
        Some(key) => StoredEvent::with_idempotency_key(scope, sequence, canonical, signed, key),
        None => StoredEvent::new(scope, sequence, canonical, signed),
    };
    Ok(event.with_canonical_event_hash(hash.map(fixed::<32>).transpose()?))
}
// All body rows are joined to their committed event, never synthesized from request data.
type RetainedRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
);
fn retained_from_row(
    row: RetainedRow,
) -> Result<(RetainedExternalAttachment, ComputeContext), StackError> {
    let (
        scope,
        seq,
        canonical,
        signed,
        event_key,
        event_hash,
        body,
        nonce,
        identity,
        hash,
        key,
        compute,
    ) = row;
    let retained = restore(
        event_from_row((scope, seq, canonical, signed, event_key, event_hash))?,
        body,
        nonce,
        identity,
        hash,
        key,
    )?;
    Ok((retained, decode_compute(&compute)?))
}
const RETAINED_SELECT: &str = "SELECT e.scope,e.sequence,e.canonical_event,e.signed_event,e.idempotency_key,e.canonical_event_hash,a.ciphertext,a.nonce,a.replay_identity,a.content_hash,a.idempotency_key,a.compute_json FROM trellis_external_attachments a JOIN trellis_events e ON e.scope=a.scope AND e.sequence=a.sequence";

pub(super) async fn postgres_append_with(
    repo: &PostgresEventRepository,
    scope: &[u8],
    key: &[u8],
    signing_key: &SigningKeyMaterial,
    compute: &ComputeContext,
    factory: &dyn ExternalAttachmentFactory,
) -> Result<RetainedExternalAttachment, StackError> {
    validate_factory_request(scope, key)?;
    validate_compute(compute)?;
    let limit = (FACTORY_PREFIX_MAX_EVENTS + 1) as i64;
    let mut tx = repo.pool.begin().await.map_err(db_error)?;
    lock_scope(&mut tx, scope).await?;
    let rows = sqlx::query_as::<_,EventRow>("SELECT scope,sequence,canonical_event,signed_event,idempotency_key,canonical_event_hash FROM trellis_events WHERE scope=$1 ORDER BY sequence LIMIT $2")
        .bind(scope).bind(limit).fetch_all(&mut *tx).await.map_err(db_error)?;
    let events = rows
        .into_iter()
        .map(event_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    if events.len() > FACTORY_PREFIX_MAX_EVENTS {
        return Err(StackError::conflict("native prefix exceeds event bound"));
    }
    validate_prefix(&events)?;
    let query = format!("{RETAINED_SELECT} WHERE a.scope=$1 AND a.idempotency_key=$2");
    let retained = sqlx::query_as::<_, RetainedRow>(&query)
        .bind(scope)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
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
    let result =
        append_external_attachment(&mut snapshot, signing_key, input).map_err(core_error)?;
    if let Some(new) = snapshot.committed {
        trellis_store_postgres_async::append_event_in_tx(&mut tx, new.event())
            .await
            .map_err(map_postgres_append_error)?;
        let sequence = i64::try_from(new.event().sequence())
            .map_err(|_| StackError::internal("external sequence out of database domain"))?;
        let hash = domain_separated_sha256(CONTENT_DOMAIN, new.ciphertext());
        sqlx::query("INSERT INTO trellis_external_attachments(scope,sequence,idempotency_key,content_hash,ciphertext,nonce,replay_identity,compute_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(new.event().scope()).bind(sequence).bind(new.event().idempotency_key()).bind(hash.as_slice()).bind(new.ciphertext()).bind(new.nonce().as_slice()).bind(new.replay_identity().as_slice())
            .bind(serde_json::to_string(compute).map_err(|e| StackError::internal(e.to_string()))?)
            .execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(result)
}

pub(super) async fn postgres_body(
    repo: &PostgresEventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, StackError> {
    let query = format!(
        "{RETAINED_SELECT} WHERE a.scope=$1 AND a.content_hash=$2 ORDER BY a.sequence LIMIT 1"
    );
    sqlx::query_as::<_, RetainedRow>(&query)
        .bind(scope)
        .bind(hash.as_slice())
        .fetch_optional(&repo.pool)
        .await
        .map_err(db_error)?
        .map(retained_from_row)
        .transpose()
        .map(|r| r.map(|(r, _)| r.ciphertext().to_vec()))
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
pub(super) async fn memory_compute(
    repo: &InMemoryEventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<ComputeContext>, StackError> {
    let state = repo.state.lock().await;
    let key = state
        .retained
        .iter()
        .find(|(_, r)| {
            r.event().scope() == scope
                && &domain_separated_sha256(CONTENT_DOMAIN, r.ciphertext()) == hash
        })
        .map(|(k, _)| k);
    Ok(key.and_then(|k| state.compute.get(k)).cloned())
}
pub(super) async fn postgres_compute(
    repo: &PostgresEventRepository,
    scope: &[u8],
    hash: &[u8; 32],
) -> Result<Option<ComputeContext>, StackError> {
    let query = format!(
        "{RETAINED_SELECT} WHERE a.scope=$1 AND a.content_hash=$2 ORDER BY a.sequence LIMIT 1"
    );
    sqlx::query_as::<_, RetainedRow>(&query)
        .bind(scope)
        .bind(hash.as_slice())
        .fetch_optional(&repo.pool)
        .await
        .map_err(db_error)?
        .map(retained_from_row)
        .transpose()
        .map(|r| r.map(|(_, c)| c))
}

#[cfg(test)]
mod tests {
    use super::super::EventRepository;
    use super::*;
    use trellis_core::external_attachment::{ExternalAppendLimits, ExternalAttachmentHeader};
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
    #[tokio::test]
    async fn memory_retains_exact_retry_after_head_advance_and_refuses_changed_custody() {
        let repo = InMemoryEventRepository::new();
        let (input, key, compute) = fixture(b"memory-native");
        let retained = repo
            .append_external_attachment(input.clone(), &key, &compute)
            .await
            .unwrap();
        repo.append_event(ordinary_after(retained.event(), &key))
            .await
            .unwrap();
        let retry = repo
            .append_external_attachment(input.clone(), &key, &compute)
            .await
            .unwrap();
        assert_eq!(retained, retry);
        assert_eq!(repo.list_scope(&input.scope).await.unwrap().len(), 2);
        let hash = domain_separated_sha256(CONTENT_DOMAIN, retained.ciphertext());
        assert_eq!(
            repo.external_attachment_body(&input.scope, &hash)
                .await
                .unwrap(),
            Some(retained.ciphertext().to_vec())
        );
        assert_eq!(
            repo.external_attachment_compute(&input.scope, &hash)
                .await
                .unwrap(),
            Some(compute.clone())
        );
        assert!(
            repo.external_attachment_body(b"other-scope", &hash)
                .await
                .unwrap()
                .is_none()
        );
        let changed =
            ComputeContext::new("changed", "operator", ComputeSensitivity::ProviderReadable);
        assert!(
            repo.append_external_attachment(input, &key, &changed)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn postgres_retention_recovers_on_new_repository_and_exact_retry_after_head_advance() {
        let cluster = support::TestCluster::start_without_migrations();
        let pool = cluster.tls_pool(4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        let repo = PostgresEventRepository::new(pool.clone());
        let (input, key, compute) = fixture(b"pg-native-recovery");
        let retained = repo
            .append_external_attachment(input.clone(), &key, &compute)
            .await
            .unwrap();
        let restarted = PostgresEventRepository::new(pool.clone());
        restarted
            .append_event(ordinary_after(retained.event(), &key))
            .await
            .unwrap();
        assert_eq!(
            restarted
                .append_external_attachment(input.clone(), &key, &compute)
                .await
                .unwrap(),
            retained
        );
        let hash = domain_separated_sha256(CONTENT_DOMAIN, retained.ciphertext());
        assert_eq!(
            restarted
                .external_attachment_body(&input.scope, &hash)
                .await
                .unwrap(),
            Some(retained.ciphertext().to_vec())
        );
        assert_eq!(
            restarted
                .external_attachment_compute(&input.scope, &hash)
                .await
                .unwrap(),
            Some(compute.clone())
        );
        assert!(
            restarted
                .external_attachment_body(b"foreign", &hash)
                .await
                .unwrap()
                .is_none()
        );
        let changed =
            ComputeContext::new("changed", "operator", ComputeSensitivity::ProviderReadable);
        assert!(
            restarted
                .append_external_attachment(input, &key, &changed)
                .await
                .is_err()
        );
        pool.close().await;
    }
    #[tokio::test]
    async fn postgres_body_insert_failure_rolls_back_signed_event_and_body() {
        let cluster = support::TestCluster::start_without_migrations();
        let pool = cluster.tls_pool(4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE trellis_external_attachments ADD CONSTRAINT test_body_insert_refusal CHECK (false)").execute(&pool).await.unwrap();
        let repo = PostgresEventRepository::new(pool.clone());
        let (input, key, compute) = fixture(b"pg-native-rollback");
        assert!(
            repo.append_external_attachment(input.clone(), &key, &compute)
                .await
                .is_err()
        );
        assert!(repo.list_scope(&input.scope).await.unwrap().is_empty());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM trellis_external_attachments")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        sqlx::query(
            "ALTER TABLE trellis_external_attachments DROP CONSTRAINT test_body_insert_refusal",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            repo.append_external_attachment(input, &key, &compute)
                .await
                .is_ok()
        );
        pool.close().await;
    }
    #[tokio::test]
    async fn postgres_cross_instance_appends_share_scope_lock_and_reject_stale_head() {
        let cluster = support::TestCluster::start_without_migrations();
        let pool = cluster.tls_pool(4).await;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .unwrap();
        let repo = PostgresEventRepository::new(pool.clone());
        let other = PostgresEventRepository::new(pool.clone());
        let (input, key, compute) = fixture(b"pg-native-concurrent");
        let (a, b) = tokio::join!(
            repo.append_external_attachment(input.clone(), &key, &compute),
            other.append_external_attachment(input.clone(), &key, &compute)
        );
        assert_eq!(a.unwrap(), b.unwrap());
        assert_eq!(repo.list_scope(&input.scope).await.unwrap().len(), 1);
        let mut stale = input.clone();
        stale.scope = b"pg-stale-empty".to_vec();
        stale.expected_head = Some([9; 32]);
        assert!(
            other
                .append_external_attachment(stale.clone(), &key, &compute)
                .await
                .is_err()
        );
        assert!(other.list_scope(&stale.scope).await.unwrap().is_empty());
        // A held native scope lock also blocks an ordinary append on another instance.
        let retained = repo
            .append_external_attachment(input.clone(), &key, &compute)
            .await
            .unwrap();
        let event = ordinary_after(retained.event(), &key);
        let mut tx = pool.begin().await.unwrap();
        lock_scope(&mut tx, &input.scope).await.unwrap();
        let pending = other.append_event(event);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        pending.await.unwrap();
        assert_eq!(repo.list_scope(&input.scope).await.unwrap().len(), 2);
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
        let repo = InMemoryEventRepository::new();
        let (input, key, compute) = fixture(b"lazy-factory");
        let factory = Factory {
            input: input.clone(),
            fresh: AtomicUsize::new(0),
            replay: AtomicUsize::new(0),
        };
        let first = repo
            .append_external_attachment_with(
                &input.scope,
                &input.idempotency_key,
                &key,
                &compute,
                &factory,
            )
            .await
            .unwrap();
        let retry = repo
            .append_external_attachment_with(
                &input.scope,
                &input.idempotency_key,
                &key,
                &compute,
                &factory,
            )
            .await
            .unwrap();
        assert_eq!(first, retry);
        assert_eq!(factory.fresh.load(Ordering::SeqCst), 1);
        assert_eq!(factory.replay.load(Ordering::SeqCst), 1);
        assert!(
            repo.append_external_attachment_with(
                b"other-scope",
                &input.idempotency_key,
                &key,
                &compute,
                &factory
            )
            .await
            .is_err()
        );
        assert!(repo.list_scope(b"other-scope").await.unwrap().is_empty());
    }
}
