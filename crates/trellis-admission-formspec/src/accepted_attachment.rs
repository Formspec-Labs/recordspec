// Rust guideline compliant 2026-02-21
//! Prepares genuine accepted-attachment bindings without publishing or inventing Source facts.
//!
//! The composition supplies immutable accepted Source evidence and its protected
//! bytes. This library checks the descriptor, original byte identity, ciphertext
//! identity and prior ledger bindings. It does not authenticate Source evidence,
//! protect/decrypt bytes, sign an event or prove portable readability. The ordinary
//! append route deliberately does not register this operation while it still
//! constructs events with null extensions.

use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, encode_canonical_cbor_value,
    json_to_dcbor_bytes, map_lookup_bytes, map_lookup_optional_value, map_lookup_text,
    map_lookup_u64,
};
use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_hash::sha256_prefixed;
use trellis_cddl::{canonical_event_hash_preimage, parse_canonical_event};
use trellis_server_ports::{
    AdmittedDescriptor, AdmittedEvent, AttachmentBinding, DirectSubmitPolicy, EventFamilyId,
    EventPrivacyClass, ExternalAttachmentAdmission, SchemaRef,
};
use trellis_types::ArtifactType;
use trellis_types::{CONTENT_DOMAIN, EVENT_DOMAIN, StoredEvent};

/// Generic accepted-filing attachment operation; not a historical upload act.
pub const ACCEPTED_ATTACHMENT_EVENT: &str = "substrate.append.accepted_attachment_binding";
/// Producer-owned family for accepted-filing attachment bindings.
pub const ACCEPTED_ATTACHMENT_FAMILY: &str = "formspec.accepted_attachment";
use trellis_cddl::ATTACHMENT_BINDING_EXTENSION;
use trellis_server_ports::AttachmentLimits;
// Descriptors are metadata, independent of the selected binary payload limit.
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// Closed Source facts retained by the accepted Submit transaction.
///
/// `accepted_attachment_id` identifies an accepted occurrence. The separately
/// selected `binding_attachment_id` identifies the logical slot across actual
/// replacements. A descriptor grants no authority and must come from the owning
/// immutable accepted record, not a caller's asserted upload history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedAttachmentDescriptor {
    pub version: u8,
    pub response_id: String,
    pub response_hash: String,
    pub source_id: String,
    pub service_binding_id: String,
    pub accepted_actor_ref: String,
    pub form_id: String,
    pub subject_ref: String,
    pub field_path: String,
    pub upload_id: String,
    pub accepted_attachment_id: String,
    pub binding_attachment_id: String,
    #[serde(deserialize_with = "required_nullable")]
    #[schema(required = true)]
    pub filename: Option<String>,
    pub media_type: String,
    pub byte_length: u64,
    pub attachment_sha256: String,
    pub object_uri: String,
    #[serde(deserialize_with = "required_nullable")]
    #[schema(required = true)]
    pub prior_binding_hash: Option<String>,
}

/// Validated binding and exact borrowed ciphertext for an owning typed author.
///
/// The replay digest binds preparation inputs, not a new signed provenance
/// extension. The owning author must also bind its KeyBag and decoding metadata
/// into its complete replay identity and preserve actual Source associations.
pub struct PreparedAcceptedAttachment<'a> {
    scope: Vec<u8>,
    expected_head: Option<[u8; 32]>,
    descriptor: AcceptedAttachmentDescriptor,
    ciphertext: &'a [u8],
    content_hash: [u8; 32],
    binding: Value,
    replay_digest: [u8; 32],
}

fn invalid(message: &str) -> StackError {
    StackError::bad_request(message)
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(de)
}

fn media_type(value: &str) -> bool {
    let mut parts = value.split('/');
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if token(a) && token(b))
}

fn hash_string(value: &str) -> Result<[u8; 32], StackError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("hash must use sha256: followed by lowercase hex"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("hash must use sha256: followed by lowercase hex"));
    }
    let mut bytes = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

fn text_map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}

fn same_text(map: &[(Value, Value)], key: &str, expected: &str) -> bool {
    matches!(map_lookup_optional_value(map, key), Some(Value::Text(actual)) if actual == expected)
}

/// Admits the closed descriptor for an explicitly selected typed append implementation.
///
/// This does not register the ordinary JSON append route, authenticate the
/// producer, or certify retained bytes. Call `prepare` before event authoring.
///
/// # Errors
/// Refuses invalid closed descriptor fields or schema identity.
pub fn admit_accepted_attachment_descriptor(bytes: &[u8]) -> Result<AdmittedEvent, StackError> {
    AcceptedAttachmentDescriptor::decode(bytes)?;
    Ok(AdmittedEvent {
        event_type: ACCEPTED_ATTACHMENT_EVENT.into(),
        event_family: EventFamilyId::new(ACCEPTED_ATTACHMENT_FAMILY)
            .map_err(|_| invalid("accepted attachment family identity"))?,
        schema_ref: SchemaRef::new(crate::formspec_schema_ref(ACCEPTED_ATTACHMENT_EVENT))
            .map_err(|_| invalid("accepted attachment schema identity"))?,
        artifact_type: ArtifactType::Event,
        direct_submit: DirectSubmitPolicy::ServiceOnly,
    })
}

impl AcceptedAttachmentDescriptor {
    /// Decodes and validates a closed, bounded accepted-operation descriptor.
    ///
    /// # Errors
    /// Refuses unknown/duplicate fields, malformed identity, hashes or excessive metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, StackError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(invalid(
                "accepted attachment descriptor exceeds metadata limit",
            ));
        }
        let descriptor: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid closed accepted attachment descriptor"))?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Checks descriptor shape without asserting Source authority or byte custody.
    ///
    /// # Errors
    /// Refuses unsupported versions, empty identity, invalid pointers or digest formats.
    pub fn validate(&self) -> Result<(), StackError> {
        let strings = [
            &self.response_id,
            &self.source_id,
            &self.service_binding_id,
            &self.accepted_actor_ref,
            &self.form_id,
            &self.subject_ref,
            &self.upload_id,
            &self.accepted_attachment_id,
            &self.binding_attachment_id,
            &self.object_uri,
        ];
        if self.version != 1
            || strings
                .iter()
                .any(|s| s.is_empty() || s.trim() != s.as_str())
            || !self.field_path.starts_with('/')
            || self.field_path.len() < 2
            || !media_type(&self.media_type)
            || self.byte_length == 0
        {
            return Err(invalid("invalid accepted attachment identity or metadata"));
        }
        for token in self.field_path.split('/').skip(1) {
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    return Err(invalid("invalid accepted field JSON pointer"));
                }
            }
        }
        hash_string(&self.response_hash)?;
        hash_string(&self.attachment_sha256)?;
        if let Some(hash) = &self.prior_binding_hash {
            hash_string(hash)?;
        }
        let bytes = serde_json::to_vec(self).map_err(|_| invalid("descriptor encode failed"))?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(invalid(
                "accepted attachment descriptor exceeds metadata limit",
            ));
        }
        Ok(())
    }

    /// Prepares an exact binding against a complete retained event prefix.
    ///
    /// The caller supplies an already trusted, committed prefix. These checks
    /// do not authenticate signatures or prove completeness against a live head.
    /// Requiring the latest same-slot binding is the selected Source policy.
    ///
    /// Original bytes and supplied ciphertext are distinct inputs. Their
    /// encryption relationship and retained key/decoding metadata remain the
    /// selected protector's responsibility; this method never labels raw bytes
    /// as encrypted or fetches a caller-provided object URI.
    ///
    /// # Errors
    /// Refuses changed original bytes, excessive inputs, malformed/foreign
    /// prefixes, missing prior bindings, slot changes or stale replacements.
    pub fn prepare<'a>(
        self,
        scope: &[u8],
        original: &[u8],
        ciphertext: &'a [u8],
        prior: &[StoredEvent],
        limits: AttachmentLimits,
    ) -> Result<PreparedAcceptedAttachment<'a>, StackError> {
        self.validate()?;
        if scope.is_empty()
            || original.is_empty()
            || ciphertext.is_empty()
            || original.len() > limits.original_bytes
            || ciphertext.len() > limits.ciphertext_bytes
            || prior.len() > limits.prior_events
        {
            return Err(invalid("accepted attachment input limit or empty input"));
        }
        if self.byte_length != original.len() as u64
            || self.attachment_sha256 != sha256_prefixed(original)
        {
            return Err(invalid(
                "original attachment bytes differ from accepted custody",
            ));
        }
        validate_prior(&self, scope, prior, limits.prior_event_bytes)?;
        let content_hash = domain_separated_sha256(CONTENT_DOMAIN, ciphertext);
        let content_hex = format!(
            "sha256:{}",
            content_hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let binding = text_map(vec![
            (
                "attachment_id",
                Value::Text(self.binding_attachment_id.clone()),
            ),
            ("slot_path", Value::Text(self.field_path.clone())),
            ("media_type", Value::Text(self.media_type.clone())),
            ("byte_length", Value::Integer(self.byte_length.into())),
            (
                "attachment_sha256",
                Value::Text(self.attachment_sha256.clone()),
            ),
            ("payload_content_hash", Value::Text(content_hex)),
            (
                "filename",
                self.filename.clone().map_or(Value::Null, Value::Text),
            ),
            (
                "prior_binding_hash",
                self.prior_binding_hash
                    .clone()
                    .map_or(Value::Null, Value::Text),
            ),
        ]);
        let descriptor_bytes = json_to_dcbor_bytes(
            &serde_json::to_value(&self).map_err(|_| invalid("descriptor encode failed"))?,
            &[],
        )
        .map_err(|_| invalid("descriptor canonical encode failed"))?;
        let replay_bytes = encode_canonical_cbor_value(&Value::Array(vec![
            Value::Text(ACCEPTED_ATTACHMENT_EVENT.into()),
            Value::Bytes(scope.to_vec()),
            Value::Bytes(descriptor_bytes),
            binding.clone(),
            Value::Bytes(content_hash.to_vec()),
        ]))
        .map_err(|_| invalid("accepted attachment replay encode failed"))?;
        // This hashes a preparation descriptor, not a Trellis artifact or content hash.
        let replay_digest =
            domain_separated_sha256("formspec-accepted-attachment-preparation-v1", &replay_bytes);
        Ok(PreparedAcceptedAttachment {
            scope: scope.to_vec(),
            expected_head: prior
                .last()
                .and_then(|event| event.canonical_event_hash().copied()),
            descriptor: self,
            ciphertext,
            content_hash,
            binding,
            replay_digest,
        })
    }
}

fn validate_prior(
    descriptor: &AcceptedAttachmentDescriptor,
    scope: &[u8],
    prior: &[StoredEvent],
    max_bytes: usize,
) -> Result<(), StackError> {
    let mut latest = None;
    let mut previous_hash: Option<[u8; 32]> = None;
    let mut total = 0usize;
    for (sequence, event) in prior.iter().enumerate() {
        total = total
            .checked_add(event.canonical_event().len())
            .ok_or_else(|| invalid("prior prefix byte limit"))?;
        if total > max_bytes {
            return Err(invalid("prior prefix byte limit"));
        }
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &canonical_event_hash_preimage(scope, event.canonical_event()),
        );
        if event.scope() != scope
            || event.sequence() != sequence as u64
            || event.canonical_event_hash() != Some(&hash)
        {
            return Err(invalid("prior prefix event identity differs"));
        }
        let value = decode_cbor_value(event.canonical_event())
            .map_err(|_| invalid("prior prefix canonical event decode failed"))?;
        if encode_canonical_cbor_value(&value)
            .map_err(|_| invalid("prior canonical encoding invalid"))?
            != event.canonical_event()
        {
            return Err(invalid("prior event CBOR is not canonical"));
        }
        parse_canonical_event(event.canonical_event())
            .map_err(|_| invalid("prior canonical event structure invalid"))?;
        let map = value
            .as_map()
            .ok_or_else(|| invalid("prior event is not a map"))?;
        if map_lookup_bytes(map, "ledger_scope").map_err(|_| invalid("prior scope missing"))?
            != scope
            || map_lookup_u64(map, "sequence").map_err(|_| invalid("prior sequence missing"))?
                != sequence as u64
        {
            return Err(invalid("prior prefix canonical identity differs"));
        }
        match (previous_hash, map_lookup_optional_value(map, "prev_hash")) {
            (None, Some(Value::Null)) => {}
            (Some(expected), Some(Value::Bytes(actual))) if actual.as_slice() == expected => {}
            _ => return Err(invalid("prior prefix hash chain differs")),
        }
        previous_hash = Some(hash);
        if let Some(Value::Map(extensions)) = map_lookup_optional_value(map, "extensions") {
            if let Some(binding) =
                map_lookup_optional_value(extensions, ATTACHMENT_BINDING_EXTENSION)
            {
                let binding = binding
                    .as_map()
                    .ok_or_else(|| invalid("prior binding is not a map"))?;
                if same_text(binding, "attachment_id", &descriptor.binding_attachment_id) {
                    validate_prior_binding(binding, map)?;
                    if !same_text(binding, "slot_path", &descriptor.field_path) {
                        return Err(invalid("logical attachment slot changed"));
                    }
                    latest = Some(hash);
                }
            }
        }
    }
    let selected = descriptor
        .prior_binding_hash
        .as_deref()
        .map(hash_string)
        .transpose()?;
    if latest != selected {
        return Err(invalid(
            "prior binding must resolve to the latest actual logical slot binding",
        ));
    }
    Ok(())
}

fn validate_prior_binding(
    binding: &[(Value, Value)],
    event: &[(Value, Value)],
) -> Result<(), StackError> {
    let required_text = |key| {
        map_lookup_text(binding, key).map_err(|_| invalid("prior attachment binding field missing"))
    };
    let mime = required_text("media_type")?;
    if !media_type(&mime)
        || map_lookup_u64(binding, "byte_length")
            .map_err(|_| invalid("prior attachment byte length missing"))?
            == 0
    {
        return Err(invalid("prior attachment metadata invalid"));
    }
    hash_string(&required_text("attachment_sha256")?)?;
    let content = hash_string(&required_text("payload_content_hash")?)?;
    if map_lookup_bytes(event, "content_hash")
        .map_err(|_| invalid("prior event content hash missing"))?
        != content
    {
        return Err(invalid("prior binding content hash differs from event"));
    }
    for key in ["filename", "prior_binding_hash"] {
        match map_lookup_optional_value(binding, key) {
            None | Some(Value::Null) => {}
            Some(Value::Text(value)) => {
                if key == "prior_binding_hash" {
                    hash_string(value)?;
                }
            }
            _ => return Err(invalid("prior attachment optional field invalid")),
        }
    }
    Ok(())
}

impl PreparedAcceptedAttachment<'_> {
    /// Borrows the immutable accepted Source descriptor.
    #[must_use]
    pub fn scope(&self) -> &[u8] {
        &self.scope
    }
    /// Returns the actual validated preparation prefix head.
    #[must_use]
    pub fn expected_head(&self) -> Option<[u8; 32]> {
        self.expected_head
    }
    /// Returns immutable accepted Source descriptor facts.
    #[must_use]
    pub fn descriptor(&self) -> &AcceptedAttachmentDescriptor {
        &self.descriptor
    }
    /// Borrows the exact supplied protected bytes without another payload copy.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
    /// Returns the ciphertext-domain hash for event and external-reference identity.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }
    /// Returns the preparation identity for full-descriptor replay comparison.
    #[must_use]
    pub fn replay_digest(&self) -> [u8; 32] {
        self.replay_digest
    }
    /// Encodes only the registered ADR-0072 outer extension.
    ///
    /// # Errors
    /// Returns an error if canonical CBOR encoding fails.
    pub fn extensions_cbor(&self) -> Result<Vec<u8>, StackError> {
        encode_canonical_cbor_value(&text_map(vec![(
            ATTACHMENT_BINDING_EXTENSION,
            self.binding.clone(),
        )]))
        .map_err(|_| invalid("attachment extension encode failed"))
    }
}

/// Formspec accepted-attachment adapter for the generic protected-attachment transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct FormspecAttachmentAdmission;

impl ExternalAttachmentAdmission for FormspecAttachmentAdmission {
    fn event_type(&self) -> &'static str {
        ACCEPTED_ATTACHMENT_EVENT
    }

    fn admit(&self, descriptor_json: &str) -> Result<AdmittedDescriptor, StackError> {
        let descriptor = AcceptedAttachmentDescriptor::decode(descriptor_json.as_bytes())?;
        Ok(AdmittedDescriptor {
            payload: serde_json::to_value(&descriptor)
                .map_err(|_| StackError::internal("descriptor encode failed"))?,
            byte_length: descriptor.byte_length,
            attachment_sha256: descriptor.attachment_sha256,
        })
    }

    fn bind(
        &self,
        payload: &serde_json::Value,
        scope: &[u8],
        original: &[u8],
        ciphertext: &[u8],
        prior: &[StoredEvent],
        limits: AttachmentLimits,
    ) -> Result<AttachmentBinding, StackError> {
        let descriptor: AcceptedAttachmentDescriptor = serde_json::from_value(payload.clone())
            .map_err(|_| invalid("invalid closed accepted attachment descriptor"))?;
        let prepared = descriptor.prepare(scope, original, ciphertext, prior, limits)?;
        Ok(AttachmentBinding {
            extensions_cbor: prepared.extensions_cbor()?,
            replay_digest: prepared.replay_digest(),
            expected_head: prepared.expected_head(),
        })
    }
}

/// Registers the dedicated typed operation without enabling the ordinary JSON router.
#[must_use]
pub fn accepted_attachment_event_type_spec() -> trellis_server_ports::EventTypeSpec {
    let mut spec = super::formspec_event_type_spec(
        ACCEPTED_ATTACHMENT_EVENT,
        ACCEPTED_ATTACHMENT_FAMILY,
        "trellis-server::external_transport::v1",
    );
    spec.privacy_class = EventPrivacyClass::PrivateAttachment;
    spec.budget_review.plaintext_fields = [
        "ledger_scope",
        "idempotency_key",
        "event_type",
        "classification",
        "attachment_id",
        "slot_path",
        "media_type",
        "byte_length",
        "attachment_sha256",
        "payload_content_hash",
        "filename",
        "prior_binding_hash",
        "recipient",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    spec
}
