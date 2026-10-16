// Rust guideline compliant 2026-02-21
//! Unit-test composition: the shipped adapters, via dev-dependencies only.
//!
//! Production wiring lives in `trellis-server-app`; `deny.toml` ignores
//! dev-dependencies, so this crate's tests can exercise the real adapters
//! without the generic server ever naming them.

use std::sync::Arc;

use stack_common_error::StackError;
use stack_common_http::tenant::HeaderConfig;
use trellis_admission_formspec::accepted_attachment::{
    FormspecAttachmentAdmission, accepted_attachment_event_type_spec,
};
use trellis_admission_formspec::{FormspecAppendAdmissionPolicy, formspec_event_type_specs};
use trellis_admission_wos::{WosEventAdmissionPolicy, WosNativeCloseout, wos_event_type_specs};
use trellis_export_profile_wos::WosExportProfile;
use trellis_server_ports::{EventAdmissionPolicy, NativeCloseout};

use crate::{AdmissionRouter, ServerAdapters, TenantHeaders};

pub(crate) use trellis_admission_formspec::{
    FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH, FORMSPEC_RESPONSE_SUBMITTED,
};

pub(crate) fn admission_policy() -> Arc<dyn EventAdmissionPolicy<Error = StackError>> {
    let literals = |specs: Vec<trellis_server_ports::EventTypeSpec>| {
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

pub(crate) fn adapters() -> ServerAdapters {
    let mut event_type_specs = wos_event_type_specs();
    event_type_specs.extend(formspec_event_type_specs());
    event_type_specs.push(accepted_attachment_event_type_spec());
    ServerAdapters {
        admission_policy: admission_policy(),
        event_type_specs,
        external_attachment_admission: Arc::new(FormspecAttachmentAdmission),
        export_profile: Arc::new(WosExportProfile),
        tenant_headers: TenantHeaders::new(HeaderConfig::wos()).or_else(HeaderConfig::formspec()),
    }
}

pub(crate) fn closeout() -> Arc<dyn NativeCloseout> {
    Arc::new(WosNativeCloseout)
}

/// Independent substrate verification of an export ZIP, through the shipped profile.
pub(crate) fn export_bundle_cryptographically_verified(zip: &[u8]) -> bool {
    adapters().export_profile.substrate_verified(zip)
}
