// Rust guideline compliant 2026-02-21
//! Authors explicitly selected external attachments and retains exact protection results.

use crate::{AppendError, AuthoredEvent, LedgerStore, SigningKeyMaterial, append_event};
use trellis_cddl::{
    EXTERNAL_ATTACHMENT_PROFILE, PROFILE_EXTENSION, parse_external_attachment_profile,
};
use trellis_types::{
    CONTENT_DOMAIN, EVENT_DOMAIN, StoredEvent, Value, domain_separated_sha256,
    encode_canonical_cbor_value, map_lookup_bytes, map_lookup_optional_value,
};

/// Exact protected result and admitted author inputs supplied by composition.
///
/// The owning producer authenticates Source facts and obtains protection from
/// the selected maintained cryptographic adapter. No raw plaintext is accepted.
#[derive(Clone, Debug)]
pub struct ExternalAttachmentAppend {
    pub scope: Vec<u8>,
    pub idempotency_key: Vec<u8>,
    pub header: ExternalAttachmentHeader,
    pub extensions: Value,
    pub key_bag: Value,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub original_sha256: [u8; 32],
    pub original_byte_length: u64,
    /// Digest of immutable consumer preparation facts, including accepted origin.
    pub preparation_identity: [u8; 32],
    /// Head against which the owning consumer prepared this new operation.
    pub expected_head: Option<[u8; 32]>,
    pub limits: ExternalAppendLimits,
}

/// Deployment-selected finite native append bounds.
#[derive(Clone, Copy, Debug)]
pub struct ExternalAppendLimits {
    pub ciphertext_bytes: usize,
    pub events: usize,
    pub metadata_bytes: usize,
}

/// Closed Phase-1 header supplied by the admitted owning composition.
#[derive(Clone, Debug)]
pub struct ExternalAttachmentHeader {
    pub event_type: String,
    pub authored_at_seconds: u64,
    pub authored_at_nanos: u32,
    pub classification: String,
    pub retention_tier: u64,
}
impl ExternalAttachmentHeader {
    fn value(&self) -> Result<Value, AppendError> {
        if self.event_type.trim().is_empty()
            || self.classification.trim().is_empty()
            || self.authored_at_nanos >= 1_000_000_000
            || self.retention_tier > 3
        {
            return Err(failure("invalid native attachment header"));
        }
        Ok(map(vec![
            (
                "event_type",
                Value::Bytes(self.event_type.as_bytes().to_vec()),
            ),
            (
                "authored_at",
                Value::Array(vec![
                    Value::Integer(self.authored_at_seconds.into()),
                    Value::Integer(self.authored_at_nanos.into()),
                ]),
            ),
            ("retention_tier", Value::Integer(self.retention_tier.into())),
            (
                "classification",
                Value::Bytes(self.classification.as_bytes().to_vec()),
            ),
            ("outcome_commitment", Value::Null),
            ("subject_ref_commitment", Value::Null),
            ("tag_commitment", Value::Null),
            ("witness_ref", Value::Null),
            ("extensions", Value::Null),
        ]))
    }
}

/// Atomic retained attachment: signed event, exact body, nonce and replay identity.
#[derive(Clone, Debug, PartialEq)]
pub struct RetainedExternalAttachment {
    event: StoredEvent,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    replay_identity: [u8; 32],
}

impl RetainedExternalAttachment {
    /// Reconstructs a committed retained result after checking its stored byte associations.
    ///
    /// This is a trusted-store restoration boundary, not signer authorization. The caller
    /// supplies only committed rows and separately verifies signatures and checkpoint trust.
    ///
    /// # Errors
    /// Refuses mismatched canonical/signed bytes, event identity, body hash/length or nonce.
    pub fn restore_committed(
        event: StoredEvent,
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        replay_identity: [u8; 32],
    ) -> Result<Self, AppendError> {
        let parsed = parse_external_attachment_profile(event.canonical_event())
            .map_err(|e| failure(e.to_string()))?
            .ok_or_else(|| failure("retained external profile absent"))?;
        let canonical = trellis_cddl::parse_canonical_event(event.canonical_event())
            .map_err(|e| failure(e.to_string()))?;
        let cose = integrity_cose::decode_cose_sign1(event.signed_event())
            .map_err(|e| failure(e.to_string()))?;
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(event.scope(), event.canonical_event()),
        );
        if canonical.ledger_scope != event.scope()
            || canonical.sequence != event.sequence()
            || event.idempotency_key() != Some(parsed.idempotency_key.as_slice())
            || event.canonical_event_hash() != Some(&hash)
            || cose.payload() != Some(event.canonical_event())
            || parsed.content_hash != domain_separated_sha256(CONTENT_DOMAIN, &ciphertext)
            || parsed.original_byte_length.checked_add(16) != Some(ciphertext.len() as u64)
        {
            return Err(failure("retained external attachment associations invalid"));
        }
        let derived = integrity_hpke::external_attachment::derive_external_attachment_nonce(
            integrity_hpke::external_attachment::AttachmentContext {
                idempotency_key: &parsed.idempotency_key,
                original_sha256: parsed.original_sha256,
                original_byte_length: parsed.original_byte_length,
            },
        )
        .map_err(|e| failure(e.to_string()))?;
        if nonce != derived {
            return Err(failure("retained external nonce invalid"));
        }
        Ok(Self {
            event,
            ciphertext,
            nonce,
            replay_identity,
        })
    }

    /// Returns the retained signed and canonical event.
    pub fn event(&self) -> &StoredEvent {
        &self.event
    }
    /// Returns exact ciphertext and authentication tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// Returns the retained decoding nonce.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    /// Returns the complete operation replay identity.
    pub fn replay_identity(&self) -> &[u8; 32] {
        &self.replay_identity
    }
}

/// Storage boundary that atomically retains the event and its protected body.
///
/// Implementations serialize a scope or compare the supplied sequence/head
/// during commit. They enforce unique `(scope,key)`, exact replay identity,
/// and scope-wide fresh encapsulated keys. Failure retains neither new record
/// nor body. This port does not authorize callers or publish an export.
pub trait ExternalAttachmentStore {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Reads the complete committed prefix for one authorized scope.
    ///
    /// # Errors
    /// Returns storage or inconsistent-prefix failures.
    fn scope_events(&self, scope: &[u8]) -> Result<Vec<StoredEvent>, Self::Error>;
    /// Reads the immutable protection result for one committed operation.
    ///
    /// # Errors
    /// Returns storage or inconsistent-operation failures.
    fn retained(
        &self,
        scope: &[u8],
        key: &[u8],
    ) -> Result<Option<RetainedExternalAttachment>, Self::Error>;
    /// Atomically retains a new event and its complete protected body.
    ///
    /// # Errors
    /// Refuses changed operation identity, stale heads, reused wraps or storage failures.
    fn commit(&mut self, attachment: RetainedExternalAttachment) -> Result<(), Self::Error>;
}

fn failure(message: impl Into<String>) -> AppendError {
    AppendError::new(message)
}
fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn encoded(value: &Value) -> Result<Vec<u8>, AppendError> {
    encode_canonical_cbor_value(value).map_err(|e| failure(e.to_string()))
}
fn with_profile(extensions: &Value) -> Result<Value, AppendError> {
    let Value::Map(fields) = extensions else {
        return Err(failure("attachment extensions must be a map"));
    };
    let mut fields = fields.clone();
    if let Some(value) = map_lookup_optional_value(&fields, PROFILE_EXTENSION) {
        if value != &Value::Text(EXTERNAL_ATTACHMENT_PROFILE.into()) {
            return Err(failure("external protection profile mismatch"));
        }
    } else {
        fields.push((
            Value::Text(PROFILE_EXTENSION.into()),
            Value::Text(EXTERNAL_ATTACHMENT_PROFILE.into()),
        ));
    }
    Ok(Value::Map(fields))
}

/// Appends through the maintained signer with atomic exact-output retention.
///
/// Ordinary JSON append is separate. Composition supplies trusted admitted
/// facts and retains randomness before retrying. A concurrent stale head must
/// be refused by the selected atomic store; callers retry from a fresh prefix.
///
/// # Errors
/// Refuses malformed profiles, changed replay inputs, missing protection,
/// invalid original associations, scope prefixes or storage/signing failures.
pub fn append_external_attachment<S: ExternalAttachmentStore>(
    store: &mut S,
    key: &SigningKeyMaterial,
    input: ExternalAttachmentAppend,
) -> Result<RetainedExternalAttachment, AppendError> {
    if input.scope.is_empty()
        || input.ciphertext.len() > input.limits.ciphertext_bytes
        || input.limits.metadata_bytes == 0
    {
        return Err(failure("empty attachment scope"));
    }
    let extensions = with_profile(&input.extensions)?;
    let content_hash = domain_separated_sha256(CONTENT_DOMAIN, &input.ciphertext);
    let payload_ref = map(vec![
        ("ref_type", Value::Text("external".into())),
        ("content_hash", Value::Bytes(content_hash.to_vec())),
        ("availability", Value::Integer(0.into())),
        ("retrieval_hint", Value::Null),
    ]);
    let header = input.header.value()?;
    let header_map = header
        .as_map()
        .ok_or_else(|| failure("attachment header must be a map"))?;
    let _ = map_lookup_bytes(header_map, "event_type").map_err(|e| failure(e.to_string()))?;
    let replay_header = Value::Map(
        header_map
            .iter()
            .filter(|(k, _)| k != &Value::Text("authored_at".into()))
            .cloned()
            .collect(),
    );
    let replay_bytes = encoded(&Value::Array(vec![
        Value::Bytes(input.scope.clone()),
        Value::Bytes(input.idempotency_key.clone()),
        replay_header,
        extensions.clone(),
        input.key_bag.clone(),
        payload_ref.clone(),
        Value::Bytes(content_hash.to_vec()),
        Value::Bytes(input.nonce.to_vec()),
        Value::Bytes(input.original_sha256.to_vec()),
        Value::Integer(input.original_byte_length.into()),
        Value::Bytes(input.preparation_identity.to_vec()),
    ]))?;
    if replay_bytes.len() > input.limits.metadata_bytes {
        return Err(failure("attachment metadata limit"));
    }
    let replay_identity =
        domain_separated_sha256("trellis-external-attachment-replay-v1", &replay_bytes);
    let events = store
        .scope_events(&input.scope)
        .map_err(|e| failure(e.to_string()))?;
    if events.len() > input.limits.events {
        return Err(failure("attachment prefix limit"));
    }
    let mut previous: Option<[u8; 32]> = None;
    for (index, event) in events.iter().enumerate() {
        let parsed = trellis_cddl::parse_canonical_event(event.canonical_event())
            .map_err(|e| failure(e.to_string()))?;
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(&input.scope, event.canonical_event()),
        );
        if event.scope() != input.scope
            || event.sequence() != index as u64
            || parsed.ledger_scope != input.scope
            || parsed.sequence != index as u64
            || event.canonical_event_hash() != Some(&hash)
            || event.idempotency_key() != Some(parsed.idempotency_key.as_slice())
        {
            return Err(failure("attachment prefix identity invalid"));
        }
        let value = trellis_types::decode_cbor_value(event.canonical_event())
            .map_err(|e| failure(e.to_string()))?;
        let fields = value
            .as_map()
            .ok_or_else(|| failure("prior event map invalid"))?;
        let expected = previous.map_or(Value::Null, |h: [u8; 32]| Value::Bytes(h.to_vec()));
        if map_lookup_optional_value(fields, "prev_hash") != Some(&expected) {
            return Err(failure("attachment prefix link invalid"));
        }
        previous = Some(hash);
    }
    let authored = encoded(&map(vec![
        ("version", Value::Integer(1.into())),
        ("ledger_scope", Value::Bytes(input.scope.clone())),
        ("sequence", Value::Integer((events.len() as u64).into())),
        (
            "prev_hash",
            previous.map_or(Value::Null, |h| Value::Bytes(h.to_vec())),
        ),
        ("causal_deps", Value::Null),
        ("content_hash", Value::Bytes(content_hash.to_vec())),
        ("header", header),
        ("commitments", Value::Null),
        ("payload_ref", payload_ref),
        ("key_bag", input.key_bag),
        (
            "idempotency_key",
            Value::Bytes(input.idempotency_key.clone()),
        ),
        ("extensions", extensions),
    ]))?;
    let parsed = parse_external_attachment_profile(&authored)
        .map_err(|e| failure(e.to_string()))?
        .ok_or_else(|| failure("external profile missing"))?;
    if parsed.original_sha256 != input.original_sha256
        || parsed.original_byte_length != input.original_byte_length
        || input.original_byte_length.checked_add(16) != Some(input.ciphertext.len() as u64)
    {
        return Err(failure(
            "protector original facts or ciphertext length differ",
        ));
    }
    let derived_nonce = integrity_hpke::external_attachment::derive_external_attachment_nonce(
        integrity_hpke::external_attachment::AttachmentContext {
            idempotency_key: &parsed.idempotency_key,
            original_sha256: parsed.original_sha256,
            original_byte_length: parsed.original_byte_length,
        },
    )
    .map_err(|e| failure(e.to_string()))?;
    if derived_nonce != input.nonce {
        return Err(failure("native attachment nonce mismatch"));
    }
    if let Some(retained) = store
        .retained(&input.scope, &input.idempotency_key)
        .map_err(|e| failure(e.to_string()))?
    {
        if retained.replay_identity != replay_identity
            || retained.ciphertext != input.ciphertext
            || retained.nonce != input.nonce
        {
            return Err(failure("external attachment idempotency conflict"));
        }
        return Ok(retained);
    }
    if input.expected_head != previous {
        return Err(failure("attachment preparation head changed"));
    }
    if events
        .iter()
        .any(|e| e.idempotency_key() == Some(input.idempotency_key.as_slice()))
    {
        return Err(failure(
            "ordinary event cannot acquire external attachment protection",
        ));
    }
    // Scope-wide freshness also includes older generic external/inline events.
    for event in &events {
        let value = trellis_types::decode_cbor_value(event.canonical_event())
            .map_err(|e| failure(e.to_string()))?;
        let fields = value
            .as_map()
            .ok_or_else(|| failure("prior event map invalid"))?;
        if let Some(Value::Map(bag)) = map_lookup_optional_value(fields, "key_bag") {
            if let Some(Value::Array(entries)) = map_lookup_optional_value(bag, "entries") {
                for entry in entries {
                    let fields = entry
                        .as_map()
                        .ok_or_else(|| failure("prior wrap map invalid"))?;
                    let ephemeral = map_lookup_bytes(fields, "ephemeral_pubkey")
                        .map_err(|e| failure(e.to_string()))?;
                    if parsed
                        .key_bag_entries
                        .iter()
                        .any(|next| next.ephemeral_pubkey.as_slice() == ephemeral)
                    {
                        return Err(failure("external attachment ephemeral key reused"));
                    }
                }
            }
        }
    }
    #[derive(Default)]
    struct Capture(Option<StoredEvent>);
    impl LedgerStore for Capture {
        type Error = std::convert::Infallible;
        fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
            self.0 = Some(event);
            Ok(())
        }
    }
    let mut capture = Capture::default();
    let artifacts = append_event(&mut capture, key, &AuthoredEvent::new(authored))?;
    let event = capture
        .0
        .ok_or_else(|| failure("signer emitted no attachment"))?
        .with_canonical_event_hash(Some(artifacts.canonical_event_hash));
    let retained = RetainedExternalAttachment {
        event,
        ciphertext: input.ciphertext,
        nonce: input.nonce,
        replay_identity,
    };
    store
        .commit(retained.clone())
        .map_err(|e| failure(e.to_string()))?;
    Ok(retained)
}

/// Opens a selected native attachment after authenticating its signed profile.
///
/// The caller resolves the authorized signing key and recipient and checks the
/// export checkpoint/inclusion and current authority policy before this call.
/// This method checks the event signature, profile, content hash and original
/// identity. It does not establish Source acceptance or complete case history.
///
/// # Errors
/// Refuses invalid signatures/profiles, missing recipients, excessive metadata,
/// mismatched body identity, wrong keys, modified wraps or changed originals.
pub fn open_native_external_attachment(
    signing_public_key: [u8; 32],
    signed_event: &[u8],
    ciphertext: &[u8],
    recipient_id: &[u8],
    recipient_private_key: &[u8; 32],
    limits: integrity_hpke::external_attachment::ProtectionLimits,
    metadata_bytes: usize,
) -> Result<Vec<u8>, AppendError> {
    if signed_event.len() > metadata_bytes {
        return Err(failure("external signed metadata limit"));
    }
    let cose =
        integrity_cose::decode_cose_sign1(signed_event).map_err(|e| failure(e.to_string()))?;
    let kid = integrity_cose::derive_kid(1, signing_public_key);
    if cose.alg() != Some(-8)
        || cose.suite_id() != Some(1)
        || cose.artifact_type() != Some("event")
        || cose.kid() != Some(kid.as_slice())
        || !integrity_cose::verify_ed25519_sign1(signing_public_key, signed_event, None)
            .map_err(|e| failure(e.to_string()))?
    {
        return Err(failure("external attachment event signature invalid"));
    }
    let canonical = cose
        .payload()
        .ok_or_else(|| failure("external event payload detached"))?;
    trellis_cddl::parse_canonical_event(canonical).map_err(|e| failure(e.to_string()))?;
    let parsed = parse_external_attachment_profile(canonical)
        .map_err(|e| failure(e.to_string()))?
        .ok_or_else(|| failure("native protection profile absent"))?;
    if ciphertext.len() > limits.original_bytes.saturating_add(16)
        || parsed.content_hash != domain_separated_sha256(CONTENT_DOMAIN, ciphertext)
    {
        return Err(failure("external attachment body identity invalid"));
    }
    let wrap = parsed
        .key_bag_entries
        .iter()
        .find(|w| w.recipient == recipient_id)
        .ok_or_else(|| failure("selected recipient absent from signed key bag"))?;
    integrity_hpke::external_attachment::open_external_attachment(
        integrity_hpke::external_attachment::AttachmentContext {
            idempotency_key: &parsed.idempotency_key,
            original_sha256: parsed.original_sha256,
            original_byte_length: parsed.original_byte_length,
        },
        ciphertext,
        &integrity_hpke::external_attachment::WrappedPayloadKey {
            recipient: wrap.recipient.clone(),
            suite: 1,
            ephemeral_pubkey: wrap.ephemeral_pubkey,
            wrapped_dek: wrap.wrapped_dek.to_vec(),
        },
        recipient_private_key,
        limits,
    )
    .map_err(|e| failure(e.to_string()))
}
