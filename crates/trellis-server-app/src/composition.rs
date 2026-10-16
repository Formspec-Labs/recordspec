// Rust guideline compliant 2026-02-21
//! Assembles the shipped adapters into the generic server's injection points.
//!
//! Adding an ecosystem overlay is a new `trellis-admission-*` adapter crate plus
//! one `register_for_literals(...)` entry in [`default_admission_policy`].

use std::sync::Arc;

use stack_common_error::StackError;
use stack_common_http::tenant::HeaderConfig;
use trellis_admission_formspec::accepted_attachment::{
    FormspecAttachmentAdmission, accepted_attachment_event_type_spec,
};
use trellis_admission_formspec::{FormspecAppendAdmissionPolicy, formspec_event_type_specs};
use trellis_admission_wos::{WosEventAdmissionPolicy, WosNativeCloseout, wos_event_type_specs};
use trellis_export_profile_wos::WosExportProfile;
use trellis_server::{AdmissionRouter, ServerAdapters, TenantHeaders};
use trellis_server_ports::{EventAdmissionPolicy, EventTypeSpec, NativeCloseout};

/// The shipped WOS and Formspec adapters, accepting the given tenant headers.
#[must_use]
pub fn adapters(tenant_headers: TenantHeaders) -> ServerAdapters {
    ServerAdapters {
        admission_policy: default_admission_policy(),
        event_type_specs: default_event_type_specs(),
        external_attachment_admission: Arc::new(FormspecAttachmentAdmission),
        export_profile: Arc::new(WosExportProfile),
        tenant_headers,
    }
}

/// WOS native-provenance closeout records for Source-content selection.
#[must_use]
pub fn native_closeout() -> Arc<dyn NativeCloseout> {
    Arc::new(WosNativeCloseout)
}

/// Both producers' tenant headers, WOS first.
#[must_use]
pub fn mixed_tenant_headers() -> TenantHeaders {
    TenantHeaders::new(HeaderConfig::wos()).or_else(HeaderConfig::formspec())
}

/// Reads `TRELLIS_TENANT_HEADER_SET=wos|formspec|mixed` (default `mixed`).
///
/// # Errors
/// Refuses any other value.
pub fn tenant_headers_from_env() -> Result<TenantHeaders, StackError> {
    match std::env::var("TRELLIS_TENANT_HEADER_SET")
        .unwrap_or_else(|_| "mixed".to_string())
        .as_str()
    {
        "wos" => Ok(TenantHeaders::new(HeaderConfig::wos())),
        "formspec" => Ok(TenantHeaders::new(HeaderConfig::formspec())),
        "mixed" => Ok(mixed_tenant_headers()),
        other => Err(StackError::bad_request(format!(
            "unsupported TRELLIS_TENANT_HEADER_SET `{other}`"
        ))),
    }
}

/// Registers every shipped adapter against the literals it owns.
#[must_use]
pub fn default_admission_policy() -> Arc<dyn EventAdmissionPolicy<Error = StackError>> {
    let literals = |specs: Vec<EventTypeSpec>| {
        specs
            .into_iter()
            .map(|spec| spec.event_type)
            .collect::<Vec<_>>()
    };
    Arc::new(
        AdmissionRouter::new()
            .register_for_literals(
                Arc::new(WosEventAdmissionPolicy::new()),
                literals(wos_event_type_specs()),
            )
            .register_for_literals(
                Arc::new(FormspecAppendAdmissionPolicy::new()),
                literals(formspec_event_type_specs()),
            ),
    )
}

/// The event-type vocabulary the shipped adapters declare.
#[must_use]
pub fn default_event_type_specs() -> Vec<EventTypeSpec> {
    let mut specs = wos_event_type_specs();
    specs.extend(formspec_event_type_specs());
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
    use trellis_server_ports::AdmissionEvent;
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
