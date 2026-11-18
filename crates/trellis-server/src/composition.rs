// Rust guideline compliant 2026-02-21
//! Assembles the shipped adapters into the generic server's injection points.
//!
//! Adding an ecosystem overlay is a new `trellis-admission-*` adapter crate plus
//! one `register_for_literals(...)` entry in [`default_admission_policy`].

use std::sync::Arc;

use trellis_admission_authority::{
    AUTHORITY_LEDGER_ID, AuthorityAdmissionPolicy, DECISIONS_LEDGER_ID, authority_event_type_specs,
    authority_literals,
};
use trellis_admission_formspec::accepted_attachment::{
    FormspecAttachmentAdmission, accepted_attachment_event_type_spec,
};
use trellis_admission_formspec::{FormspecAppendAdmissionPolicy, formspec_event_type_specs};
use trellis_admission_wos::{WosEventAdmissionPolicy, WosNativeCloseout, wos_event_type_specs};
use trellis_export_profile_wos::WosExportProfile;
use trellis_server_ports::{EventTypeSpec, NativeCloseout};
use trellis_service_core::{AdmissionRouter, ServerAdapters};

use crate::source_content::source_content_parts;

/// The shipped WOS and Formspec adapters.
#[must_use]
pub fn adapters() -> ServerAdapters {
    ServerAdapters {
        admission_policy: default_admission_policy(),
        event_type_specs: default_event_type_specs(),
        external_attachment_admission: Arc::new(FormspecAttachmentAdmission),
        export_profile: Arc::new(WosExportProfile),
        native_closeout: native_closeout(),
        source_content: Arc::new(source_content_parts),
    }
}

/// WOS native-provenance closeout records for Source-content selection.
#[must_use]
pub fn native_closeout() -> Arc<dyn NativeCloseout> {
    Arc::new(WosNativeCloseout)
}

/// Registers every shipped adapter against the literals it owns.
#[must_use]
pub fn default_admission_policy() -> AdmissionRouter {
    let literals = |specs: Vec<EventTypeSpec>| {
        specs
            .into_iter()
            .map(|spec| spec.event_type)
            .collect::<Vec<_>>()
    };
    AdmissionRouter::new()
        .reserve_ledger(
            AUTHORITY_LEDGER_ID,
            Arc::new(AuthorityAdmissionPolicy),
            authority_literals(AUTHORITY_LEDGER_ID),
        )
        .reserve_ledger(
            DECISIONS_LEDGER_ID,
            Arc::new(AuthorityAdmissionPolicy),
            authority_literals(DECISIONS_LEDGER_ID),
        )
        .register_for_literals(
            Arc::new(WosEventAdmissionPolicy::new()),
            literals(wos_event_type_specs()),
        )
        .register_for_literals(
            Arc::new(FormspecAppendAdmissionPolicy::new()),
            literals(formspec_event_type_specs()),
        )
}

/// The event-type vocabulary the shipped adapters declare.
#[must_use]
pub fn default_event_type_specs() -> Vec<EventTypeSpec> {
    let mut specs = wos_event_type_specs();
    specs.extend(formspec_event_type_specs());
    specs.extend(authority_event_type_specs());
    specs.push(accepted_attachment_event_type_spec());
    specs
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_common_typeid::testing::fixture_minter;
    use trellis_admission_formspec::{
        FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH, FORMSPEC_RESPONSE_SUBMITTED,
    };
    use trellis_server_ports::{AdmissionEvent, EventAdmissionPolicy};
    use wos_events::WOS_NATIVE_PROVENANCE_EVENT_LITERAL;

    #[tokio::test]
    async fn given_default_policy_when_wos_literal_admits_then_wos_metadata() {
        let policy = default_admission_policy();
        let mut record = wos_events::ProvenanceRecord::blank(
            &fixture_minter(),
            wos_events::ProvenanceKind::CaseCreated,
        );
        record.id = "prov-default-route".to_string();
        let payload = serde_json::to_vec(&record).expect("serialize record");
        let event = AdmissionEvent {
            scope: b"case-1",
            event_type: "wos.kernel.case_created",
            payload: payload.as_slice(),
        };
        let admitted = policy.admit(&event).await.expect("wos branch admits");
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn given_default_policy_when_formspec_literal_admits_then_formspec_metadata() {
        let policy = default_admission_policy();
        let payload = br#"{"aggregateType":"t","aggregateId":"i","payload":{}}"#;
        let event = AdmissionEvent {
            scope: b"formspec",
            event_type: FORMSPEC_RESPONSE_SUBMITTED,
            payload,
        };
        let admitted = policy.admit(&event).await.expect("formspec branch admits");
        assert_eq!(admitted.event_family.as_str(), "formspec.response");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn given_default_policy_when_response_action_batch_admits_then_formspec_action_metadata()
    {
        let policy = default_admission_policy();
        let payload = br#"{"aggregateType":"formspec.response_action_session_op_batch","aggregateId":"urn:formspec:session:session-1","payload":{"ledgerScope":"urn:formspec:session:session-1","branchId":"branch-main","opBatch":{"semanticOps":[]},"opBatchHash":"sha256:e7a089ec840bca120002285859beed5ed98b0aaae8ea512e357bf87b926485b3","ledgerPortIdempotencyKey":"sha256:5ce46ef23b95a440dad50a1fb18dca127c399e12bbaeab3cf0cd272704b6e34b","mode":"require-anchored"}}"#;
        let event = AdmissionEvent {
            scope: b"formspec",
            event_type: FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
            payload,
        };
        let admitted = policy
            .admit(&event)
            .await
            .expect("response-action branch admits");
        assert_eq!(
            admitted.event_type,
            FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH
        );
        assert_eq!(admitted.event_family.as_str(), "formspec.response_action");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn given_unregistered_literal_when_default_policy_admits_then_rejects() {
        // Unknown literals (e.g., a hypothetical future overlay not yet
        // registered at composition) must reject at admission, never reach
        // append. This is the load-bearing dispatch contract.
        let policy = default_admission_policy();
        let event = AdmissionEvent {
            scope: b"unknown",
            event_type: "c2pa.assertion.created",
            payload: b"{}",
        };
        let err = policy
            .admit(&event)
            .await
            .expect_err("unregistered must reject");
        assert!(
            err.to_string().contains("not registered for admission"),
            "router must surface the registration gap; got: {err}"
        );
    }

    #[test]
    fn given_event_type_specs_when_combined_then_include_wos_and_formspec_literals() {
        let specs = default_event_type_specs();
        assert!(
            specs
                .iter()
                .any(|spec| spec.event_type == "wos.kernel.case_created")
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.event_type == FORMSPEC_RESPONSE_SUBMITTED)
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.event_type == FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH)
        );
    }

    #[test]
    fn given_event_type_specs_when_collected_then_carry_family_artifact_and_direct_submit() {
        let specs = default_event_type_specs();
        let wos = specs
            .iter()
            .find(|spec| spec.event_type == "wos.kernel.case_created")
            .expect("WOS kernel spec");
        assert_eq!(wos.event_family.as_str(), "wos.kernel");
        assert_eq!(wos.artifact_type, trellis_types::ArtifactType::Event);
        assert_eq!(
            wos.direct_submit,
            trellis_server_ports::DirectSubmitPolicy::ServiceOnly
        );

        let governance = specs
            .iter()
            .find(|spec| spec.event_type == "wos.governance.amendment_authorized")
            .expect("WOS governance spec");
        assert_eq!(governance.event_family.as_str(), "wos.governance");

        let formspec = specs
            .iter()
            .find(|spec| spec.event_type == FORMSPEC_RESPONSE_SUBMITTED)
            .expect("Formspec spec");
        assert_eq!(formspec.event_family.as_str(), "formspec.response");
        assert_eq!(formspec.artifact_type, trellis_types::ArtifactType::Event);

        let response_action = specs
            .iter()
            .find(|spec| spec.event_type == FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH)
            .expect("Formspec Response Actions spec");
        assert_eq!(
            response_action.event_family.as_str(),
            "formspec.response_action"
        );
        assert_eq!(
            response_action.artifact_type,
            trellis_types::ArtifactType::Event
        );
    }
    #[tokio::test]
    async fn native_provenance_dispatch_reaches_owning_adapter() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/conformance/native-provenance-routing.json"
        ))
        .unwrap();
        let bytes = serde_json::to_vec(&fixture["payload"]).unwrap();
        let admitted = default_admission_policy()
            .admit(&AdmissionEvent {
                scope: b"case-1",
                event_type: WOS_NATIVE_PROVENANCE_EVENT_LITERAL,
                payload: &bytes,
            })
            .await
            .expect("generic route registered independently of canonical literals");
        assert_eq!(admitted.event_type, WOS_NATIVE_PROVENANCE_EVENT_LITERAL);
        assert!(
            default_event_type_specs()
                .iter()
                .any(|spec| spec.event_type == WOS_NATIVE_PROVENANCE_EVENT_LITERAL)
        );
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use trellis_server_ports::{AdmissionEvent, EventAdmissionPolicy};

    #[tokio::test]
    async fn t1_authority_payloads_and_ledger_binding() {
        let policy = default_admission_policy();
        for case in cases() {
            let event_type = case["eventType"].as_str().unwrap();
            let ledger = case["ledger"].as_str().unwrap();
            let bytes = serde_json::to_vec(&case["payload"]).unwrap();
            for id in [
                "authority",
                "authority-decisions",
                "authority-sample",
                "authority-decisions-sample",
                "authority-other",
                "authority-decisions-other",
                "authority-Sample",
                "authority-0sample",
                "authority-abcdefghijklmnopqrstuvwxyz0123456",
                "case_123",
                "other.authority",
            ] {
                let scope = format!("{}.{id}", "a".repeat(64));
                let result = policy
                    .admit(&AdmissionEvent {
                        scope: scope.as_bytes(),
                        event_type,
                        payload: &bytes,
                    })
                    .await;
                assert_eq!(
                    result.is_ok(),
                    id == ledger,
                    "{id} {event_type}: {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn t1_authority_rejects_closed_shape_and_bad_tuple_grammar() {
        let policy = default_admission_policy();
        for case in cases() {
            let event_type = case["eventType"].as_str().unwrap();
            let scope = format!("{}.{}", "a".repeat(64), case["ledger"].as_str().unwrap());
            let mut invalid = Vec::new();
            let mut extra = case["payload"].clone();
            extra["extra"] = true.into();
            invalid.push(extra);
            if case["payload"].get("tuple").is_some() {
                for (field, value) in [
                    ("subject", "person:*"),
                    ("subject", "person:a#"),
                    ("object", "bad type:a"),
                    ("relation", "can@read"),
                ] {
                    let mut bad = case["payload"].clone();
                    bad["tuple"][field] = value.into();
                    invalid.push(bad);
                }
            }
            for payload in invalid {
                let result = policy
                    .admit(&AdmissionEvent {
                        scope: scope.as_bytes(),
                        event_type,
                        payload: &serde_json::to_vec(&payload).unwrap(),
                    })
                    .await;
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("authority payload"),
                    "{payload:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn t1_non_authority_events_cannot_enter_either_authority_ledger() {
        for ledger in ["authority", "authority-decisions"] {
            let scope = format!("{}.{ledger}", "a".repeat(64));
            let error = default_admission_policy()
                .admit(&AdmissionEvent {
                    scope: scope.as_bytes(),
                    event_type: trellis_admission_formspec::FORMSPEC_RESPONSE_SUBMITTED,
                    payload: br#"{"aggregateType":"t","aggregateId":"i","payload":{}}"#,
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("ledger"), "{ledger}: {error}");

            let error = default_admission_policy()
                .admit(&AdmissionEvent {
                    scope: scope.as_bytes(),
                    event_type: "wos.kernel.case_created",
                    payload: b"{}",
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("ledger"), "{ledger}: {error}");
        }
    }

    async fn admit(
        event_type: &str,
        ledger: &str,
        payload: &serde_json::Value,
    ) -> Result<(), stack_common_error::StackError> {
        let scope = format!("{}.{ledger}", "a".repeat(64));
        default_admission_policy()
            .admit(&AdmissionEvent {
                scope: scope.as_bytes(),
                event_type,
                payload: &serde_json::to_vec(payload).unwrap(),
            })
            .await
            .map(|_| ())
    }

    fn cases() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!(
            "../../../fixtures/conformance/authority-events.json"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn t1_shared_ledgers_accept_any_valid_contract_and_genesis_and_refuse_cross_ledger() {
        let cases = cases();
        let long_valid = "a1234567890123456789012345678901";
        let long_invalid = "a12345678901234567890123456789012";
        for case in &cases {
            let event_type = case["eventType"].as_str().unwrap();
            let ledger = case["ledger"].as_str().unwrap();
            let other_ledger = if ledger == "authority" {
                "authority-decisions"
            } else {
                "authority"
            };
            let mut payload = case["payload"].clone();
            for contract in [
                "wos",
                "formspec",
                "genesis",
                "decisions",
                "decisions-9",
                "decisionsx",
                long_valid,
            ] {
                payload["contract"] = contract.into();
                admit(event_type, ledger, &payload)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{event_type} on {ledger} refused contract {contract}: {error}")
                    });
                assert!(
                    admit(event_type, other_ledger, &payload).await.is_err(),
                    "{event_type} unexpectedly admitted on {other_ledger}"
                );
                assert!(
                    admit(event_type, "authority-sample", &payload)
                        .await
                        .is_err(),
                    "{event_type} unexpectedly admitted on authority-sample"
                );
                assert!(
                    admit(event_type, "authority-decisions-sample", &payload)
                        .await
                        .is_err(),
                    "{event_type} unexpectedly admitted on authority-decisions-sample"
                );
            }
            for invalid in ["", "Sample", "0sample", "bad_id", long_invalid] {
                payload["contract"] = invalid.into();
                let error = admit(event_type, ledger, &payload).await.unwrap_err();
                assert!(
                    error.to_string().contains("contract"),
                    "{event_type} invalid contract {invalid}: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn t1_checks_activation_artifact_digests_and_unique_paths() {
        let mut activation = cases().remove(2);
        let event_type = activation["eventType"].as_str().unwrap().to_owned();
        let ledger = activation["ledger"].as_str().unwrap().to_owned();
        let payload = &mut activation["payload"];
        payload["artifacts"][0]["content"] = "wrong bytes".into();
        let error = admit(&event_type, &ledger, payload).await.unwrap_err();
        assert!(error.to_string().contains("digest"), "{error}");
        payload["artifacts"][0]["content"] = "".into();
        let duplicate = payload["artifacts"][0].clone();
        payload["artifacts"].as_array_mut().unwrap().push(duplicate);
        let error = admit(&event_type, &ledger, payload).await.unwrap_err();
        assert!(error.to_string().contains("path"), "{error}");
    }

    #[tokio::test]
    async fn t1_validates_each_revised_fragment() {
        let cases = cases();
        for (index, field) in [
            (0, "contract"),
            (1, "contract"),
            (2, "configuration"),
            (3, "attempt"),
            (3, "authorityPrefix"),
        ] {
            let case = &cases[index];
            let mut payload = case["payload"].clone();
            payload.as_object_mut().unwrap().remove(field);
            let error = admit(
                case["eventType"].as_str().unwrap(),
                case["ledger"].as_str().unwrap(),
                &payload,
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("authority payload"),
                "{field}: {error}"
            );
        }
        let case = &cases[3];
        let event_type = case["eventType"].as_str().unwrap();
        let ledger = case["ledger"].as_str().unwrap();
        let mut payload = case["payload"].clone();
        payload["entitlement"] = serde_json::json!({"source":"native","rule":"operator"});
        admit(event_type, ledger, &payload).await.unwrap();
        payload["entitlement"]["relation"] = "viewer".into();
        assert!(admit(event_type, ledger, &payload).await.is_err());
        payload["entitlement"] = serde_json::json!({"source":"relationship","rule":"operator"});
        assert!(admit(event_type, ledger, &payload).await.is_err());
    }
}
