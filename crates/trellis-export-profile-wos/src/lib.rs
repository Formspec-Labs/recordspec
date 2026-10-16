// Rust guideline compliant 2026-02-21
#![allow(clippy::result_large_err)]
// `StackError` carries operational context callers rely on; boxing it would change every fallible
// signature in this crate. Follow-up: convert `StackError` to a `Box<...>` newtype workspace-wide.
//! WOS/Formspec signature export profile for the Trellis server.
//!
//! Implements the [`ExportProfile`] port: it derives the signed-acts and policy
//! closure members, resolves signing facts, and judges finished bundles with the
//! WOS verifier. The composition root installs it; generic server code never
//! names it (enforced by `deny.toml`).

#![forbid(unsafe_code)]

mod export_profile;
mod source_content;

pub use source_content::{check_source_content_batch, verify_source_content_export};

use integrity_cbor::sha256_bytes;
use stack_common_error::StackError;
use trellis_export_writer::{ExportEvidenceMember, TrellisTimestamp};
use trellis_server_ports::event_codec::{cbor_bad_request, event_summary, event_timestamp};
use trellis_server_ports::{ExportProfile, ExportProfileMembers, ExportVerdict, SigningFact};
use trellis_types::StoredEvent;
use wos_events::ProvenanceKind;

use crate::export_profile::PolicyClosureArtifact;

/// WOS/Formspec signature export profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct WosExportProfile;

impl ExportProfile for WosExportProfile {
    fn evidence_members(
        &self,
        scope: &[u8],
        events: &[&StoredEvent],
    ) -> Result<Vec<ExportEvidenceMember>, StackError> {
        signature_evidence_members(scope, events)
    }

    fn profile_members(
        &self,
        scope: &[u8],
        events: &[StoredEvent],
        generated_at: TrellisTimestamp,
    ) -> Result<ExportProfileMembers, StackError> {
        export_profile::build_export_profile_members(
            scope,
            events,
            generated_at,
            &default_signature_policy_artifacts(),
        )
    }

    /// Verifies with the product-owned signing-proof resolver in a single pass.
    ///
    /// V2 certificates require every indexed response proof; generic no-op resolution
    /// cannot establish that binding.
    fn verify(&self, zip: &[u8]) -> ExportVerdict {
        let report = trellis_verify_wos::verify_export_zip(zip);
        let substrate_verified =
            report.trellis.structure_verified && report.trellis.integrity_verified;
        #[cfg(test)]
        if !substrate_verified {
            eprintln!(
                "export verification failures: events={:?}; checkpoints={:?}; proofs={:?}; warnings={:?}",
                report.trellis.event_failures,
                report.trellis.checkpoint_failures,
                report.trellis.proof_failures,
                report.trellis.warnings
            );
        }
        ExportVerdict {
            substrate_verified,
            profile_verified: report.relying_party_valid(),
        }
    }

    fn signing_facts(
        &self,
        events: &[StoredEvent],
        selected: &[[u8; 32]],
    ) -> Result<Vec<SigningFact>, StackError> {
        completion_signing_facts(events, selected)
    }
}

/// Derives bounded062 and exact060 originals from actual admitted affirmations.
///
/// Preserves every prior affirmation. This pure operation grants no Source
/// access and does not establish original signed Response/proof custody.
///
/// # Errors
/// Refuses invalid actual prefixes, unreadable or unrepresentable affirmations,
/// hash conflicts and finite canonical-input/payload/catalog/member limits.
fn signature_evidence_members(
    scope: &[u8],
    events: &[&trellis_types::StoredEvent],
) -> Result<Vec<trellis_export_writer::ExportEvidenceMember>, StackError> {
    use integrity_cbor::{
        decode_cbor_value, domain_separated_sha256, map_lookup_bytes, map_lookup_map,
    };
    use std::collections::BTreeMap;
    use trellis_export_writer::ExportEvidenceMember;
    const MAX_BYTES: usize = 1024 * 1024;
    const MAX_MEMBERS: usize = 256;
    let mut affirmed = Vec::new();
    for event in events {
        if event_summary(event)?.event_type == wos_signature_affirmation_event_type() {
            if events.len() > MAX_MEMBERS {
                return Err(StackError::bad_request(
                    "signature prefix event count limit",
                ));
            }
            affirmed.push(*event);
        }
    }
    if affirmed.is_empty() {
        return Ok(Vec::new());
    }
    if events.first().is_none_or(|event| event.scope() != scope) {
        return Err(StackError::bad_request("signature export scope mismatch"));
    }
    let mut total = 0usize;
    for event in events {
        total = total
            .checked_add(event.canonical_event().len())
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(|| StackError::bad_request("signature evidence aggregate byte limit"))?;
    }
    let catalog =
        trellis_verify_wos::encode_signature_affirmations_v1(events, MAX_MEMBERS, MAX_BYTES)
            .map_err(|_| StackError::bad_request("actual signature affirmation inventory refused"))?
            .ok_or_else(|| StackError::internal("actual affirmation catalog absent"))?;
    total = total
        .checked_add(catalog.len())
        .filter(|bytes| *bytes <= MAX_BYTES)
        .ok_or_else(|| StackError::bad_request("signature evidence aggregate byte limit"))?;
    let mut originals = BTreeMap::<[u8; 32], Vec<u8>>::new();
    for event in affirmed {
        let canonical = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
        let map = canonical
            .as_map()
            .ok_or_else(|| StackError::bad_request("invalid actual signature event"))?;
        let reference = map_lookup_map(map, "payload_ref").map_err(cbor_bad_request)?;
        let bytes = map_lookup_bytes(reference, "ciphertext").map_err(cbor_bad_request)?;
        let hash = domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &bytes);
        if event_summary(event)?.content_hash != hash {
            return Err(StackError::bad_request(
                "signature payload content hash mismatch",
            ));
        }
        if let Some(existing) = originals.get(&hash) {
            if existing != &bytes {
                return Err(StackError::conflict(
                    "signature original payload hash collision",
                ));
            }
        } else {
            total = total
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(|| {
                    StackError::bad_request("signature evidence aggregate byte limit")
                })?;
            if originals.len() >= MAX_MEMBERS - 1 {
                return Err(StackError::bad_request("signature evidence member limit"));
            }
            originals.insert(hash, bytes);
        }
    }
    let mut members = originals
        .into_iter()
        .map(|(content_hash, bytes)| ExportEvidenceMember::Payload {
            content_hash,
            bytes,
        })
        .collect::<Vec<_>>();
    members.push(ExportEvidenceMember::SignatureAffirmations { bytes: catalog });
    Ok(members)
}

const POLICY_VALID_FROM: &str = "2026-05-16T00:00:00Z";

/// Resolves consumer-owned signing facts through the maintained readable adapter.
fn completion_signing_facts(
    events: &[trellis_types::StoredEvent],
    selected: &[[u8; 32]],
) -> Result<Vec<SigningFact>, StackError> {
    use integrity_cbor::{decode_cbor_value, map_lookup_bytes, map_lookup_map, map_lookup_text};
    use integrity_verify::trellis::certificate_proof::ResponseProofResolver;
    let invalid = || StackError::conflict("completion signing evidence unreadable or unqualified");
    let first = events.first().ok_or_else(invalid)?;
    signature_evidence_members(first.scope(), &events.iter().collect::<Vec<_>>())?;
    let resolver = trellis_verify_wos::WosFormspecResolver::new();
    selected
        .iter()
        .map(|hash| {
            let event = events
                .iter()
                .find(|event| event.canonical_event_hash() == Some(hash))
                .ok_or_else(invalid)?;
            if event_summary(event)?.event_type != wos_signature_affirmation_event_type() {
                return Err(invalid());
            }
            let value = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
            let reference = map_lookup_map(value.as_map().ok_or_else(invalid)?, "payload_ref")
                .map_err(cbor_bad_request)?;
            if map_lookup_text(reference, "ref_type").map_err(cbor_bad_request)? != "inline" {
                return Err(invalid());
            }
            let payload = map_lookup_bytes(reference, "ciphertext").map_err(cbor_bad_request)?;
            Ok(SigningFact {
                principal: resolver
                    .resolve_principal_ref(&payload)
                    .filter(|v| !v.trim().is_empty())
                    .ok_or_else(invalid)?,
                response_hash: resolver
                    .resolve(&payload)
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?
                    .response_hash,
                authored_at: event_timestamp(event)?,
            })
        })
        .collect()
}
const POLICY_VERSION: &str = "2026-05-16";
const FORMSPEC_RESPONSE_SCHEMA: &[u8] =
    include_bytes!("../../../../formspec/schemas/response.schema.json");
const FORMSPEC_SIGNATURE_METHOD_REGISTRY: &[u8] =
    include_bytes!("../../../../formspec/registries/signature-method-registry.json");
const WOS_SIGNATURE_PROFILE_SPEC: &[u8] =
    include_bytes!("../../../../work-spec/specs/profiles/signature.md");
const WOS_PROVENANCE_SCHEMA: &[u8] =
    include_bytes!("../../../../work-spec/schemas/wos-provenance-log.schema.json");

/// Canonical WOS `SignatureAffirmation` event literal for export-profile composition.
#[must_use]
pub fn wos_signature_affirmation_event_type() -> &'static str {
    ProvenanceKind::SignatureAffirmation
        .canonical_event_literal()
        .expect("SignatureAffirmation must carry a substrate canonical event literal")
}

/// Canonical WOS `SignatureAdmissionFailed` event literal for export-profile composition.
#[must_use]
pub fn wos_signature_admission_failed_event_type() -> &'static str {
    ProvenanceKind::SignatureAdmissionFailed
        .canonical_event_literal()
        .expect("SignatureAdmissionFailed must carry a substrate canonical event literal")
}

/// Returns the default public policy evidence rows for WOS/Formspec signature exports.
#[must_use]
fn default_signature_policy_artifacts() -> Vec<PolicyClosureArtifact> {
    vec![
        policy_artifact(
            "formspec",
            "formspec.signing-intent-registry.v1",
            "repo://formspec/schemas/response.schema.json",
            FORMSPEC_RESPONSE_SCHEMA,
        ),
        policy_artifact(
            "formspec",
            "formspec.signature-method-registry.v1",
            "repo://formspec/registries/signature-method-registry.json",
            FORMSPEC_SIGNATURE_METHOD_REGISTRY,
        ),
        policy_artifact(
            "wos",
            "wos.signature-posture-floors.v1",
            "repo://work-spec/specs/profiles/signature.md",
            WOS_SIGNATURE_PROFILE_SPEC,
        ),
        policy_artifact(
            "wos",
            "wos.signer-authority-shape.v1",
            "repo://work-spec/specs/profiles/signature.md",
            WOS_SIGNATURE_PROFILE_SPEC,
        ),
        policy_artifact(
            "wos",
            "wos.identity-proofing-primitives.v1",
            "repo://work-spec/specs/profiles/signature.md",
            WOS_SIGNATURE_PROFILE_SPEC,
        ),
        policy_artifact(
            "wos",
            "wos.signature-defaults.v1",
            "repo://work-spec/specs/profiles/signature.md",
            WOS_SIGNATURE_PROFILE_SPEC,
        ),
        policy_artifact(
            "wos",
            "wos.signature-deny-rules.v1",
            "repo://work-spec/specs/profiles/signature.md",
            WOS_SIGNATURE_PROFILE_SPEC,
        ),
        policy_artifact(
            "wos",
            "wos.signature-tombstones.v1",
            "repo://work-spec/schemas/wos-provenance-log.schema.json",
            WOS_PROVENANCE_SCHEMA,
        ),
    ]
}

fn policy_artifact(
    owner: &'static str,
    kind: &'static str,
    reference: &'static str,
    bytes: &[u8],
) -> PolicyClosureArtifact {
    PolicyClosureArtifact {
        owner,
        kind,
        version: POLICY_VERSION,
        reference,
        digest: sha256_bytes(bytes),
        valid_from: POLICY_VALID_FROM,
        valid_to: None,
    }
}
