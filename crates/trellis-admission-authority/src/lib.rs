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

/// Shared ledger id for grants, revocations and activations.
pub const AUTHORITY_LEDGER_ID: &str = "authority";
/// Shared ledger id for authorization decision records.
pub const DECISIONS_LEDGER_ID: &str = "authority-decisions";

const TUPLE_CHANGE: &str = "tupleChange";
const ACTIVATION: &str = "activation";
const DECISION: &str = "decision";
const GENESIS_CONTRACT: &str = "genesis";
const GENESIS_GRANT_EVENT_TYPE: &str = "trellis.authority.grant.v1";
const GENESIS_RELATION: &str = "authority_admin";
const GENESIS_OPERATOR_DOMAIN_TAG: &str = "stack-authz-genesis-operator-v1";
const GENESIS_OBJECT_PREFIX: &str = "space:";

/// Deterministic canonical genesis `actor` (`service:<digest>`).
#[must_use]
pub fn canonical_genesis_actor() -> String {
    let digest = integrity_cbor::domain_separated_sha256(GENESIS_OPERATOR_DOMAIN_TAG, b"");
    format!("service:{}", hex::encode(digest))
}

struct Event {
    literal: &'static str,
    ledger_id: &'static str,
    definition: &'static str,
}

const EVENTS: [Event; 4] = [
    Event {
        literal: "trellis.authority.grant.v1",
        ledger_id: AUTHORITY_LEDGER_ID,
        definition: TUPLE_CHANGE,
    },
    Event {
        literal: "trellis.authority.revocation.v1",
        ledger_id: AUTHORITY_LEDGER_ID,
        definition: TUPLE_CHANGE,
    },
    Event {
        literal: "trellis.authority.activation.v1",
        ledger_id: AUTHORITY_LEDGER_ID,
        definition: ACTIVATION,
    },
    Event {
        literal: "trellis.authority.decision.v1",
        ledger_id: DECISIONS_LEDGER_ID,
        definition: DECISION,
    },
];

struct Validators {
    tuple_change: jsonschema::Validator,
    activation: jsonschema::Validator,
    decision: jsonschema::Validator,
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

/// Literals reserved for the shared ledger id.
pub fn authority_literals(ledger_id: &str) -> impl Iterator<Item = &'static str> + '_ {
    EVENTS
        .iter()
        .filter(move |event| event.ledger_id == ledger_id)
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
        verify_genesis_grant(event.scope, spec.literal, &payload)?;
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

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_scope_key(scope: &[u8]) -> Result<&str, StackError> {
    let text = std::str::from_utf8(scope)
        .map_err(|_| StackError::bad_request("authority event scope must be UTF-8"))?;
    let (key, _ledger) = text
        .split_once('.')
        .filter(|(key, ledger)| is_lower_hex_64(key) && !ledger.is_empty())
        .ok_or_else(|| {
            StackError::bad_request("authority event scope must be `<64-hex scope_key>.<ledger>`")
        })?;
    Ok(key)
}

fn is_canonical_user_subject(subject: &str) -> bool {
    subject.strip_prefix("user:").is_some_and(is_lower_hex_64)
}

fn verify_genesis_grant(
    scope: &[u8],
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(), StackError> {
    if payload["contract"].as_str() != Some(GENESIS_CONTRACT) {
        return Ok(());
    }
    if event_type != GENESIS_GRANT_EVENT_TYPE {
        return Err(StackError::bad_request(
            "contract \"genesis\" is only valid for trellis.authority.grant.v1",
        ));
    }
    let scope_key = parse_scope_key(scope)?;
    let expected_space = format!("{GENESIS_OBJECT_PREFIX}{scope_key}");
    if payload["tuple"]["relation"].as_str() != Some(GENESIS_RELATION) {
        return Err(StackError::bad_request(
            "genesis authority grants require relation \"authority_admin\"",
        ));
    }
    if payload["tuple"]["object"].as_str() != Some(expected_space.as_str()) {
        return Err(StackError::bad_request(format!(
            "genesis authority grants require object \"{expected_space}\" for the admitted scope"
        )));
    }
    if !payload["tuple"]["subject"]
        .as_str()
        .is_some_and(is_canonical_user_subject)
    {
        return Err(StackError::bad_request(
            "genesis authority grants require a canonical `user:<64 lowercase hex>` subject",
        ));
    }
    let expected_actor = canonical_genesis_actor();
    if payload["actor"].as_str() != Some(expected_actor.as_str()) {
        return Err(StackError::bad_request(
            "genesis authority grants require the canonical genesis actor",
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_partition_between_exact_shared_ledgers() {
        let authority: Vec<_> = authority_literals(AUTHORITY_LEDGER_ID).collect();
        assert_eq!(
            authority,
            [
                "trellis.authority.grant.v1",
                "trellis.authority.revocation.v1",
                "trellis.authority.activation.v1",
            ]
        );
        let decisions: Vec<_> = authority_literals(DECISIONS_LEDGER_ID).collect();
        assert_eq!(decisions, ["trellis.authority.decision.v1"]);
        assert!(authority_literals("authority-sample").next().is_none());
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => {
                panic!("AuthorityAdmissionPolicy::admit must complete immediately")
            }
        }
    }

    #[test]
    fn admits_multi_contract_decisions_and_strict_genesis_contract_ids() {
        let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../fixtures/conformance/authority-events.json"
        ))
        .expect("conformance fixture");
        let policy = AuthorityAdmissionPolicy;
        for (index, case) in cases.iter().enumerate() {
            let event_type = case["eventType"].as_str().unwrap();
            let scope = format!("{}.{}", "a".repeat(64), case["ledger"].as_str().unwrap());
            let mut payload = case["payload"].clone();
            for contract in ["wos", "formspec", "decisions", "decisions-9"] {
                payload["contract"] = contract.into();
                block_on(policy.admit(&AdmissionEvent {
                    scope: scope.as_bytes(),
                    event_type,
                    payload: &serde_json::to_vec(&payload).unwrap(),
                }))
                .unwrap_or_else(|err| panic!("{event_type} {contract}: {err}"));
            }
            if index == 4 {
                let genesis_scope_key = case["payload"]["tuple"]["object"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("space:")
                    .unwrap();
                let genesis_scope =
                    format!("{genesis_scope_key}.{}", case["ledger"].as_str().unwrap());
                block_on(policy.admit(&AdmissionEvent {
                    scope: genesis_scope.as_bytes(),
                    event_type,
                    payload: &serde_json::to_vec(&case["payload"]).unwrap(),
                }))
                .expect("canonical genesis fixture grant must be admitted on its scope");
                assert!(
                    block_on(policy.admit(&AdmissionEvent {
                        scope: scope.as_bytes(),
                        event_type,
                        payload: &serde_json::to_vec(&case["payload"]).unwrap(),
                    }))
                    .is_err(),
                    "canonical genesis fixture grant must refuse a mismatched scope"
                );
            } else {
                payload["contract"] = "genesis".into();
                assert!(
                    block_on(policy.admit(&AdmissionEvent {
                        scope: scope.as_bytes(),
                        event_type,
                        payload: &serde_json::to_vec(&payload).unwrap(),
                    }))
                    .is_err(),
                    "non-genesis fixture case {index} ({event_type}) must refuse contract \"genesis\""
                );
            }
            for invalid in ["", "Sample", "0sample", "bad_id"] {
                payload["contract"] = invalid.into();
                let err = block_on(policy.admit(&AdmissionEvent {
                    scope: scope.as_bytes(),
                    event_type,
                    payload: &serde_json::to_vec(&payload).unwrap(),
                }))
                .unwrap_err();
                assert!(
                    err.to_string().contains("/contract"),
                    "{event_type} {invalid}: {err}"
                );
            }
        }
    }

    #[test]
    fn strict_genesis_admission_rejects_non_grant_and_non_canonical_fields() {
        let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../fixtures/conformance/authority-events.json"
        ))
        .expect("conformance fixture");
        let policy = AuthorityAdmissionPolicy;
        let canonical = cases[4]["payload"].clone();
        let canonical_scope_key = canonical["tuple"]["object"]
            .as_str()
            .unwrap()
            .strip_prefix("space:")
            .unwrap();
        let auth_scope = format!("{canonical_scope_key}.authority");
        let other_auth_scope = format!("{}.authority", "a".repeat(64));
        let dec_scope = format!("{canonical_scope_key}.authority-decisions");
        assert_eq!(
            canonical["actor"].as_str().unwrap(),
            "service:6e70406f0eaa4a6dd1f83c93ae711b6fbc28c19dac996c381b31ca49150564e7"
        );

        // Revocation, activation, and decision with contract "genesis" must all refuse (400).
        for (event_type, scope, base) in [
            (
                "trellis.authority.revocation.v1",
                &auth_scope,
                canonical.clone(),
            ),
            (
                "trellis.authority.activation.v1",
                &auth_scope,
                cases[2]["payload"].clone(),
            ),
            (
                "trellis.authority.decision.v1",
                &dec_scope,
                cases[3]["payload"].clone(),
            ),
        ] {
            let mut payload = base;
            payload["contract"] = "genesis".into();
            let err = block_on(policy.admit(&AdmissionEvent {
                scope: scope.as_bytes(),
                event_type,
                payload: &serde_json::to_vec(&payload).unwrap(),
            }))
            .unwrap_err();
            assert_eq!(err.status().as_u16(), 400);
        }

        // Grant with wrong actor, wrong relation, wrong/unscoped object, or non-user subject must refuse.
        let mut bad_actor = canonical.clone();
        bad_actor["actor"] =
            "service:0000000000000000000000000000000000000000000000000000000000000000".into();
        let mut caller_actor = canonical.clone();
        caller_actor["actor"] = "service:wos-server".into();
        let mut bad_relation = canonical.clone();
        bad_relation["tuple"]["relation"] = "viewer".into();
        let mut non_space_object = canonical.clone();
        non_space_object["tuple"]["object"] = "record:sample".into();
        let mut sample_space_object = canonical.clone();
        sample_space_object["tuple"]["object"] = "space:sample".into();
        let mut other_space_object = canonical.clone();
        other_space_object["tuple"]["object"] = format!("space:{}", "a".repeat(64)).into();

        let valid_user = canonical["tuple"]["subject"].as_str().unwrap();
        let uppercase_user = valid_user.to_ascii_uppercase();
        let service_subject = valid_user.replace("user:", "service:");
        let userset_subject = format!("{valid_user}#member");
        let mut bad_cases = vec![
            bad_actor,
            caller_actor,
            bad_relation,
            non_space_object,
            sample_space_object,
            other_space_object,
        ];
        for bad_subject in [
            "person:admin",
            "user:*",
            "user:alice",
            "user:short",
            uppercase_user.as_str(),
            service_subject.as_str(),
            userset_subject.as_str(),
        ] {
            let mut bad = canonical.clone();
            bad["tuple"]["subject"] = bad_subject.into();
            bad_cases.push(bad);
        }
        for bad in bad_cases {
            let err = block_on(policy.admit(&AdmissionEvent {
                scope: auth_scope.as_bytes(),
                event_type: "trellis.authority.grant.v1",
                payload: &serde_json::to_vec(&bad).unwrap(),
            }))
            .unwrap_err();
            assert_eq!(err.status().as_u16(), 400, "{bad}");
        }

        // Canonical payload submitted against a different scope key or malformed/non-UTF-8 scope refuses (400).
        for bad_scope in [
            other_auth_scope.as_bytes(),
            b"not-utf8-\xff.authority".as_slice(),
            b"authority".as_slice(),
            b"badkey.authority".as_slice(),
        ] {
            let err = block_on(policy.admit(&AdmissionEvent {
                scope: bad_scope,
                event_type: "trellis.authority.grant.v1",
                payload: &serde_json::to_vec(&canonical).unwrap(),
            }))
            .unwrap_err();
            assert_eq!(err.status().as_u16(), 400);
        }
    }
}
