// Rust guideline compliant 2026-02-21
//! The completion seal request: the trigger and the facts the product selected for it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use utoipa::ToSchema;

/// Certificate event literal shared by the seal request and append receipt.
pub const COMPLETION_EVENT: &str = "trellis.certificate-of-completion.v2";

const MAX_TEXT: usize = 1024;

/// Disclosure label for one retained signing event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSignerLabel {
    pub signing_event: [u8; 32],
    pub display_name: String,
    pub display_role: Option<String>,
}

/// Public operator authority the owner requires to attest the certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionAttestor {
    pub authority: String,
    pub authority_class: String,
    pub public_key: [u8; 32],
}

/// Owning facts from one current, complete, consistently read case snapshot.
///
/// The product computes this under its own permission checks and sends it in the seal
/// body. `workflow_status` describes processing disposition and does not imply approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSelection {
    /// Hash of the owning service's case snapshot; informational for Trellis.
    pub selection_revision: [u8; 32],
    pub case_ref: String,
    pub workflow_ref: String,
    pub workflow_status: String,
    /// `[unix seconds, subsecond nanoseconds]`.
    #[schema(value_type = Vec<u64>)]
    pub completed_at: (u64, u32),
    pub impact_level: Option<String>,
    pub signer_labels: Vec<CompletionSignerLabel>,
    pub required_attestors: Vec<CompletionAttestor>,
}

/// Seal trigger for an exact prefix, carrying the product's selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionRequest {
    pub idempotency_key: String,
    pub certificate_id: String,
    pub expected_head: [u8; 32],
    pub signing_events: Vec<[u8; 32]>,
    pub selection: CompletionSelection,
}

fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

impl CompletionRequest {
    /// Validates finite trigger fields and the selection without asserting workflow completion.
    ///
    /// # Errors
    /// Refuses empty identifiers, overlong fields, repeated signing hashes, and a selection
    /// whose labels do not match `signing_events` one for one, in order.
    pub fn validate(&self) -> Result<(), StackError> {
        if !(1..=64).contains(&self.idempotency_key.len())
            || self.certificate_id.trim().is_empty()
            || self.certificate_id.len() > MAX_TEXT
            || self.signing_events.is_empty()
            || self.signing_events.len() > 64
            || self
                .signing_events
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.signing_events.len()
        {
            return Err(StackError::bad_request("completion trigger fields invalid"));
        }
        self.selection.validate_for(&self.signing_events)
    }
}

impl CompletionSelection {
    fn validate_for(&self, signing_events: &[[u8; 32]]) -> Result<(), StackError> {
        let fail = || StackError::bad_request("completion selection invalid");
        if !text(&self.case_ref)
            || !text(&self.workflow_ref)
            || !text(&self.workflow_status)
            || self.completed_at.1 >= 1_000_000_000
            || self.impact_level.as_deref().is_some_and(|v| !text(v))
            || self.signer_labels.len() != signing_events.len()
            || self.required_attestors.is_empty()
            || self.required_attestors.len() > 8
        {
            return Err(fail());
        }
        for (label, signing_event) in self.signer_labels.iter().zip(signing_events) {
            if &label.signing_event != signing_event
                || !text(&label.display_name)
                || label.display_role.as_deref().is_some_and(|v| !text(v))
            {
                return Err(fail());
            }
        }
        let mut authorities = BTreeSet::new();
        for row in &self.required_attestors {
            if !text(&row.authority)
                || !matches!(row.authority_class.as_str(), "prior" | "new")
                || !authorities.insert(&row.authority)
            {
                return Err(fail());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn request() -> CompletionRequest {
        CompletionRequest {
            idempotency_key: "seal-key".into(),
            certificate_id: "certificate".into(),
            expected_head: [1; 32],
            signing_events: vec![[2; 32], [3; 32]],
            selection: CompletionSelection {
                selection_revision: [4; 32],
                case_ref: "case-1".into(),
                workflow_ref: "urn:workflow".into(),
                workflow_status: "completed".into(),
                completed_at: (1_700_000_000, 5),
                impact_level: Some("low".into()),
                signer_labels: vec![
                    CompletionSignerLabel {
                        signing_event: [2; 32],
                        display_name: "First".into(),
                        display_role: None,
                    },
                    CompletionSignerLabel {
                        signing_event: [3; 32],
                        display_name: "Second".into(),
                        display_role: Some("Witness".into()),
                    },
                ],
                required_attestors: vec![CompletionAttestor {
                    authority: "operator".into(),
                    authority_class: "new".into(),
                    public_key: [5; 32],
                }],
            },
        }
    }

    #[test]
    fn wire_shape_is_camel_case_and_closed() {
        let value = serde_json::to_value(request()).unwrap();
        let selection = &value["selection"];
        assert_eq!(selection["completedAt"], serde_json::json!([1_700_000_000u64, 5]));
        assert_eq!(selection["signerLabels"][1]["displayRole"], "Witness");
        assert_eq!(selection["requiredAttestors"][0]["authorityClass"], "new");
        assert_eq!(selection["selectionRevision"].as_array().unwrap().len(), 32);
        assert_eq!(serde_json::from_value::<CompletionRequest>(value.clone()).unwrap(), request());
        let mut unknown = value.clone();
        unknown["selection"]["callerBearer"] = serde_json::json!("x");
        assert!(serde_json::from_value::<CompletionRequest>(unknown).is_err());
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("selection");
        assert!(serde_json::from_value::<CompletionRequest>(missing).is_err());
    }

    #[test]
    fn selection_checks_match_the_trigger_one_for_one() {
        assert!(request().validate().is_ok());
        let edits: [fn(&mut CompletionRequest); 11] = [
            |r| {
                r.selection.signer_labels.pop();
            },
            |r| r.selection.signer_labels.swap(0, 1),
            |r| r.selection.signer_labels[0].display_name = "  ".into(),
            |r| r.selection.signer_labels[0].display_role = Some(String::new()),
            |r| r.selection.signer_labels[0].display_name = "x".repeat(1025),
            |r| r.selection.required_attestors.clear(),
            |r| {
                let row = r.selection.required_attestors[0].clone();
                r.selection.required_attestors = vec![row; 9];
            },
            |r| {
                let mut row = r.selection.required_attestors[0].clone();
                row.authority_class = "prior".into();
                r.selection.required_attestors.push(row);
            },
            |r| r.selection.case_ref = " ".into(),
            |r| r.selection.completed_at.1 = 1_000_000_000,
            |r| r.selection.required_attestors[0].authority_class = "other".into(),
        ];
        for (index, edit) in edits.iter().enumerate() {
            let mut r = request();
            edit(&mut r);
            assert!(r.validate().is_err(), "edit {index}");
        }
    }
}
