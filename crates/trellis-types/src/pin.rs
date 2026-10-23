//! ADR 0071 CaseOpenPin and migration models.

use serde::{Deserialize, Serialize};

/// Four-dimensional version set pinned at case-open (ADR 0071 D-1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseOpenPin {
    pub formspec: FormspecPin,
    pub wos: WosPin,
    pub trellis: TrellisPin,
}

impl CaseOpenPin {
    pub fn new(
        definition_version: impl Into<String>,
        wos_workflow_version: impl Into<String>,
        envelope_version: impl Into<String>,
        conformance_class: impl Into<String>,
    ) -> Self {
        Self {
            formspec: FormspecPin {
                definition_version: definition_version.into(),
            },
            wos: WosPin {
                wos_workflow_version: wos_workflow_version.into(),
            },
            trellis: TrellisPin {
                envelope_version: envelope_version.into(),
                conformance_class: conformance_class.into(),
            },
        }
    }

    /// Validates that all required dimensions are non-empty and well-formed.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.formspec.definition_version.trim().is_empty() {
            return Err("formspec.definitionVersion is required and non-empty");
        }
        if self.wos.wos_workflow_version.trim().is_empty() {
            return Err("wos.$wosWorkflowVersion is required and non-empty");
        }
        if self.trellis.envelope_version.trim().is_empty() {
            return Err("trellis.envelopeVersion is required and non-empty");
        }
        if self.trellis.conformance_class.trim().is_empty() {
            return Err("trellis.conformanceClass is required and non-empty");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormspecPin {
    pub definition_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WosPin {
    #[serde(rename = "$wosWorkflowVersion", alias = "wosWorkflowVersion")]
    pub wos_workflow_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrellisPin {
    pub envelope_version: String,
    pub conformance_class: String,
}

/// Provenance payload for ADR 0071 D-4 migration transition (`MigrationPinChanged`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPinChangedPayload {
    pub case_id: String,
    #[serde(alias = "old_pin", alias = "priorPinSet")]
    pub prior_pin_set: CaseOpenPin,
    #[serde(alias = "new_pin", alias = "newPinSet")]
    pub new_pin_set: CaseOpenPin,
    #[serde(alias = "migration_policy_ref", alias = "authorityBasis")]
    pub migration_policy_ref: String,
    pub authorizing_actor_id: String,
    #[serde(alias = "rationale", alias = "migrationRationale")]
    pub rationale: String,
    pub timestamp: String,
}
