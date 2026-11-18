// Rust guideline compliant 2026-02-21
//! Validates the canonical authority payloads against their authored schema.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use std::collections::HashSet;
use std::sync::LazyLock;

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, BudgetReviewRecord, DirectSubmitPolicy, EventAdmissionPolicy,
    EventFamilyId, EventPrivacyClass, EventTypeSpec, SchemaRef,
};
use trellis_types::ArtifactType;

const FAMILY: &str = "trellis.authority";
const SCHEMA: &str = include_str!("../../../specs/authority-events.schema.json");
/// Serialized activation limit, allowing room for escaped artifacts in the 2 MiB append body.
pub const ACTIVATION_PAYLOAD_LIMIT: usize = 1792 * 1024;

/// Ledger prefix for grants, revocations and activations.
pub const AUTHORITY_LEDGER_PREFIX: &str = "authority-";
/// Ledger prefix for authorization decision records.
pub const DECISIONS_LEDGER_PREFIX: &str = "authority-decisions-";

const TUPLE_CHANGE: &str = "tupleChange";
const ACTIVATION: &str = "activation";
const DECISION: &str = "decision";

struct Event {
    literal: &'static str,
    ledger_prefix: &'static str,
    definition: &'static str,
}

const EVENTS: [Event; 4] = [
    Event {
        literal: "trellis.authority.grant.v1",
        ledger_prefix: AUTHORITY_LEDGER_PREFIX,
        definition: TUPLE_CHANGE,
    },
    Event {
        literal: "trellis.authority.revocation.v1",
        ledger_prefix: AUTHORITY_LEDGER_PREFIX,
        definition: TUPLE_CHANGE,
    },
    Event {
        literal: "trellis.authority.activation.v1",
        ledger_prefix: AUTHORITY_LEDGER_PREFIX,
        definition: ACTIVATION,
    },
    Event {
        literal: "trellis.authority.decision.v1",
        ledger_prefix: DECISIONS_LEDGER_PREFIX,
        definition: DECISION,
    },
];

struct Validators {
    tuple_change: jsonschema::Validator,
    activation: jsonschema::Validator,
    decision: jsonschema::Validator,
    contract_id: jsonschema::Validator,
    schema: serde_json::Value,
}

static VALIDATORS: LazyLock<Validators> = LazyLock::new(|| {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).expect("authority schema JSON");
    let build = |definition| {
        let mut schema = schema.clone();
        schema["$ref"] = format!("#/$defs/{definition}").into();
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("authority schema validator")
    };
    Validators {
        tuple_change: build(TUPLE_CHANGE),
        activation: build(ACTIVATION),
        decision: build(DECISION),
        contract_id: build("contractId"),
        schema,
    }
});

impl Event {
    fn schema_ref(&self) -> SchemaRef {
        let id = VALIDATORS.schema["$id"]
            .as_str()
            .expect("authority schema ID");
        SchemaRef::new(format!("{id}#/$defs/{}", self.definition))
            .expect("authority payload schema reference")
    }
}

/// Checks a ledger's contract suffix against the authored identifier schema.
#[must_use]
pub fn valid_contract_id(contract: &str) -> bool {
    VALIDATORS
        .contract_id
        .is_valid(&serde_json::json!(contract))
}

/// Literals reserved for the ledger prefix.
pub fn authority_literals(prefix: &str) -> impl Iterator<Item = &'static str> + '_ {
    EVENTS
        .iter()
        .filter(move |event| event.ledger_prefix == prefix)
        .map(|event| event.literal)
}

/// Authority metadata for the service's event-type catalog.
pub fn authority_event_type_specs() -> impl Iterator<Item = EventTypeSpec> {
    EVENTS.iter().map(|event| EventTypeSpec {
        event_type: event.literal.into(),
        event_family: EventFamilyId::new(FAMILY).expect("authority event family"),
        schema_ref: event.schema_ref(),
        artifact_type: ArtifactType::Event,
        direct_submit: DirectSubmitPolicy::ServiceOnly,
        privacy_class: EventPrivacyClass::PublicMetadata,
        budget_review: BudgetReviewRecord {
            reviewer: "RecordsSpec authority schema".into(),
            plaintext_fields: VALIDATORS.schema["$defs"][event.definition]["properties"]
                .as_object()
                .expect("authority payload properties")
                .keys()
                .cloned()
                .collect(),
            considered: true,
        },
    })
}

/// Admits a payload of the authority event family.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthorityAdmissionPolicy;

#[async_trait]
impl EventAdmissionPolicy for AuthorityAdmissionPolicy {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        let spec = EVENTS
            .iter()
            .find(|spec| spec.literal == event.event_type)
            .ok_or_else(|| StackError::bad_request("unknown authority event type"))?;
        let validator = match spec.definition {
            TUPLE_CHANGE => &VALIDATORS.tuple_change,
            ACTIVATION => {
                if event.payload.len() > ACTIVATION_PAYLOAD_LIMIT {
                    return Err(StackError::bad_request(
                        "authority payload exceeds activation limit",
                    ));
                }
                &VALIDATORS.activation
            }
            DECISION => &VALIDATORS.decision,
            _ => unreachable!("authority event definitions are closed"),
        };
        let payload = serde_json::from_slice(event.payload)
            .map_err(|_| StackError::bad_request("authority payload is not valid JSON"))?;
        validator.validate(&payload).map_err(|error| {
            StackError::bad_request(format!(
                "authority payload does not match its schema at {}",
                error.instance_path()
            ))
        })?;
        if spec.definition == ACTIVATION {
            verify_artifacts(&payload)?;
        }
        Ok(AdmittedEvent {
            event_type: spec.literal.into(),
            event_family: EventFamilyId::new(FAMILY).expect("authority event family"),
            schema_ref: spec.schema_ref(),
            artifact_type: ArtifactType::Event,
            direct_submit: DirectSubmitPolicy::ServiceOnly,
            max_scope_events: None,
        })
    }
}

// The activation schema has already checked each artifact's shape.
fn verify_artifacts(payload: &serde_json::Value) -> Result<(), StackError> {
    let artifacts = payload["artifacts"]
        .as_array()
        .expect("validated artifacts");
    let mut paths = HashSet::with_capacity(artifacts.len());
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("validated artifact path");
        if !paths.insert(path) {
            return Err(StackError::bad_request(
                "authority activation has duplicate artifact paths",
            ));
        }
        let content = artifact["content"]
            .as_str()
            .expect("validated artifact content");
        let digest = integrity_cbor::sha256_bytes(content.as_bytes());
        if artifact["sha256"] != format!("sha256:{}", hex::encode(digest)) {
            return Err(StackError::bad_request(
                "authority activation artifact digest does not match content",
            ));
        }
    }
    Ok(())
}
