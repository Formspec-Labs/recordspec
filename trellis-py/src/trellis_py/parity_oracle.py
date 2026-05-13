"""Stable JSON projection for cross-stack verifier parity checks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from trellis_py.verify_wos import verify_export_zip


def report_projection(export_zip: bytes) -> dict[str, Any]:
    report = verify_export_zip(export_zip)
    trellis = report.trellis
    correction_preservations = getattr(trellis, "correction_preservations", [])
    return {
        "structure_verified": trellis.structure_verified,
        "integrity_verified": trellis.integrity_verified,
        "readability_verified": trellis.readability_verified,
        "event_failures": [_failure_projection(item) for item in trellis.event_failures],
        "checkpoint_failures": [
            _failure_projection(item) for item in trellis.checkpoint_failures
        ],
        "proof_failures": [_failure_projection(item) for item in trellis.proof_failures],
        "posture_transition_count": len(trellis.posture_transitions),
        "erasure_evidence_count": len(trellis.erasure_evidence),
        "certificates_of_completion_count": len(trellis.certificates_of_completion),
        "user_content_attestation_count": len(trellis.user_content_attestations),
        "correction_preservation_count": len(correction_preservations),
        "interop_sidecar_count": len(trellis.interop_sidecars),
        "posture_transitions": [
            _posture_transition_projection(item) for item in trellis.posture_transitions
        ],
        "erasure_evidence": [
            _erasure_evidence_projection(item) for item in trellis.erasure_evidence
        ],
        "certificates_of_completion": [
            _certificate_projection(item) for item in trellis.certificates_of_completion
        ],
        "user_content_attestations": [
            _user_content_attestation_projection(item)
            for item in trellis.user_content_attestations
        ],
        "correction_preservations": [
            _correction_preservation_projection(item) for item in correction_preservations
        ],
        "interop_sidecars": [
            _interop_sidecar_projection(item) for item in trellis.interop_sidecars
        ],
        "domain_findings": [
            {
                "kind": item.kind,
                "severity": item.severity,
                "message": item.detail,
            }
            for item in report.wos_findings
        ],
        "warnings": trellis.warnings,
        "substrate_tier": None,
    }


def _failure_projection(item: Any) -> dict[str, Any]:
    return {"kind": item.kind, "location": item.location}


def _posture_transition_projection(item: Any) -> dict[str, Any]:
    return {
        "transition_id": item.transition_id,
        "kind": item.kind,
        "event_index": item.event_index,
        "from_state": item.from_state,
        "to_state": item.to_state,
        "continuity_verified": item.continuity_verified,
        "declaration_resolved": item.declaration_resolved,
        "attestations_verified": item.attestations_verified,
        "failures": item.failures,
    }


def _erasure_evidence_projection(item: Any) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "kid_destroyed_hex": item.kid_destroyed.hex(),
        "destroyed_at": _timestamp_projection(item.destroyed_at),
        "event_index": item.event_index,
        "signature_verified": item.signature_verified,
        "post_erasure_uses": item.post_erasure_uses,
        "post_erasure_wraps": item.post_erasure_wraps,
        "failures": item.failures,
    }


def _certificate_projection(item: Any) -> dict[str, Any]:
    return {
        "certificate_id": item.certificate_id,
        "event_index": item.event_index,
        "signer_count": item.signer_count,
        "attachment_resolved": item.attachment_resolved,
        "all_signing_events_resolved": item.all_signing_events_resolved,
        "chain_summary_consistent": item.chain_summary_consistent,
        "failures": item.failures,
    }


def _user_content_attestation_projection(item: Any) -> dict[str, Any]:
    return {
        "attestation_id": item.attestation_id,
        "attested_event_hash_hex": item.attested_event_hash.hex(),
        "attestor": item.attestor,
        "signing_intent": item.signing_intent,
        "event_index": item.event_index,
        "chain_position_resolved": item.chain_position_resolved,
        "identity_resolved": item.identity_resolved,
        "signature_verified": item.signature_verified,
        "key_active": item.key_active,
        "failures": item.failures,
    }


def _correction_preservation_projection(item: Any) -> dict[str, Any]:
    return {
        "event_index": item.event_index,
        "correction_event_hash_hex": item.correction_event_hash.hex(),
        "target_event_hash": item.target_event_hash,
        "corrected_field_set": item.corrected_field_set,
        "field_value_count": len(item.field_values),
    }


def _interop_sidecar_projection(item: Any) -> dict[str, Any]:
    return {
        "kind": item.kind,
        "path": item.path,
        "derivation_version": item.derivation_version,
        "content_digest_ok": item.content_digest_ok,
        "kind_registered": item.kind_registered,
        "phase_1_locked": item.phase_1_locked,
        "failures": item.failures,
    }


def _timestamp_projection(item: Any) -> str:
    return f"[{item.seconds}, {item.nanos}]"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m trellis_py.parity_oracle <export.zip>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    projection = report_projection(path.read_bytes())
    json.dump(projection, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
