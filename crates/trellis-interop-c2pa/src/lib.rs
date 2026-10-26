// Rust guideline compliant 2026-04-28
//! C2PA interop adapter (ADR 0008, Wave 25).
//!
//! This crate emits and parses the **Trellis assertion** that ADR 0008's
//! `c2pa-manifest` kind binds to a Certificate of Completion's presentation
//! artifact. The assertion is a five-field dCBOR map carrying:
//!
//! * `trellis.certificate_id` — ADR 0007 `certificate_id`
//! * `trellis.canonical_event_hash` — canonical hash of the certificate event
//! * `trellis.presentation_artifact.content_hash` — ADR 0007 PA `content_hash`
//! * `trellis.kid` — signer `kid` from the certificate event's COSE_Sign1
//! * `trellis.cose_sign1_ref` — SHA-256 (under `trellis-content-v1`) of the
//!   canonical COSE_Sign1 bytes of the certificate event
//!
//! ## Two verification paths
//!
//! ADR 0008 §"`c2pa-manifest`" defines two independent verification paths:
//!
//! * **Path-(a) — C2PA-tooling path.** A consumer opens the PDF (or JPEG /
//!   etc.) carrying the C2PA manifest, validates the manifest under C2PA
//!   conventions, then extracts the Trellis assertion bytes and calls
//!   [`extract_trellis_assertion`] + [`TrellisAssertion::verify_against_canonical_chain`]
//!   to check the five-field cross-binding. **This path is not exercised
//!   by the Phase-1 core verifier** — it lives in adopter / consumer code
//!   so the core verifier preserves Core §16 independence (ISC-05; no
//!   ecosystem deps in `trellis-core` / `integrity-verify` / `trellis-types`).
//!
//! * **Path-(b) — canonical bytes only.** The Phase-1 core verifier walks
//!   `manifest.interop_sidecars`, recomputes `content_digest` against the
//!   on-disk file under `trellis-content-v1`, and validates `kind` /
//!   `derivation_version` / `path` against the closed registry. It does
//!   NOT decode the assertion or resolve `source_ref`. Path-(b) catches
//!   sidecar-bytes tampering (a stranger walking only the export ZIP
//!   detects mutation by digest cross-check).
//!
//! Both paths are additive (ISC-01); neither replaces canonical bytes.
//!
//! ## Why hand-rolled CBOR
//!
//! The `c2pa-rs` crate pulls a 328-crate transitive dep tree (image
//! parsers, ASN.1 decoders, RDF infrastructure, network-capable
//! certificate-validation). That weight is appropriate for the
//! C2PA-tooling consumer — which already needs PDF/JPEG embedding and
//! C2PA-conventional signing — but inappropriate as a workspace base
//! dep. The Trellis *assertion* is a 5-field dCBOR map; the assertion
//! bytes are byte-exact under any conforming dCBOR encoder. This crate
//! emits + parses the assertion directly via `ciborium`, with
//! deterministic map-key ordering per Core §5.1; consumers feed the
//! assertion bytes into their preferred C2PA SDK (or read them out
//! after the SDK extracts the
//! `org.formspec.trellis.certificate-of-completion.v1` assertion from
//! the manifest store).
//!
//! ## Vendor-prefix label
//!
//! Per ADR 0008 Open Q3 resolution (Wave 25): the assertion ships under
//! the vendor-prefix label `org.formspec.trellis.certificate-of-completion.v1`.
//! This sidesteps C2PA coalition gating without forfeiting interop;
//! consumers parse the assertion identically regardless of label
//! namespace. A formal short-form registration is a follow-on ADR.

#![forbid(unsafe_code)]

use ciborium::Value;
use thiserror::Error;
use trellis_types::{CONTENT_DOMAIN, domain_separated_sha256, map_lookup_optional_value};

/// Vendor-prefix C2PA assertion label (ADR 0008 Open Q3 resolution,
/// Wave 25). Consumer C2PA SDKs look this label up in the manifest's
/// assertion store; the bytes are dCBOR(TrellisAssertion).
pub const ASSERTION_LABEL: &str = "org.formspec.trellis.certificate-of-completion.v1";

/// `c2pa-manifest` kind `derivation_version`. Bumping this is a wire
/// break per ISC-06.
pub const DERIVATION_VERSION: u8 = 1;

/// Trellis assertion fields (the five-field cross-binding). Names
/// match ADR 0008 §"`c2pa-manifest`" assertion-field table. Map-key
/// ordering on the wire is dCBOR-canonical per Core §5.1 / RFC 8949
/// §4.2.2 — sort the **encoded `tstr`** bytes lexicographically (which
/// is equivalent to "shorter length first, ties broken bytewise"
/// because the CBOR length prefix is monotonic in length). The five
/// field names span 11..42 bytes:
///
/// | len | field |
/// |----:|-------|
/// |  11 | `trellis.kid` |
/// |  22 | `trellis.certificate_id` |
/// |  22 | `trellis.cose_sign1_ref` |
/// |  28 | `trellis.canonical_event_hash` |
/// |  42 | `trellis.presentation_artifact.content_hash` |
///
/// Sorting on encoded `tstr` bytes (length-prefix first, then UTF-8
/// payload) yields the order above; the emitter inserts in that order
/// so `ciborium`'s insertion-order serializer produces canonical bytes.
/// This matches `cbor2.dumps(..., canonical=True)` and the on-disk
/// fixture at `fixtures/vectors/export/014-…/cert-wave25-001.c2pa`.
const FIELD_CANONICAL_EVENT_HASH: &str = "trellis.canonical_event_hash";
const FIELD_CERTIFICATE_ID: &str = "trellis.certificate_id";
const FIELD_COSE_SIGN1_REF: &str = "trellis.cose_sign1_ref";
const FIELD_KID: &str = "trellis.kid";
const FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH: &str = "trellis.presentation_artifact.content_hash";

/// Decoded Trellis assertion. Carries the five-field cross-binding
/// from a Certificate of Completion event to its presentation
/// artifact's C2PA manifest. Round-trip byte-exact: an emit/parse
/// pair under ISC-02 deterministic derivation MUST yield the same
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrellisAssertion {
    /// ADR 0007 `certificate_id`.
    pub certificate_id: String,
    /// SHA-256 (under `trellis-canonical-event-v1`) of the certificate event.
    pub canonical_event_hash: [u8; 32],
    /// ADR 0007 `PresentationArtifact.content_hash` (under
    /// `trellis-presentation-artifact-v1`).
    pub presentation_artifact_content_hash: [u8; 32],
    /// Signer `kid` from the certificate event's COSE_Sign1 protected
    /// header (16 bytes per ADR 0006 `KeyEntrySigning.kid`).
    pub kid: [u8; 16],
    /// SHA-256 (under `trellis-content-v1`) of the canonical
    /// COSE_Sign1 bytes of the certificate event.
    pub cose_sign1_ref: [u8; 32],
}

/// Canonical-chain context against which an assertion verifies. The
/// caller fills these from the verified Trellis chain (events,
/// registry, etc.) and passes them to
/// [`TrellisAssertion::verify_against_canonical_chain`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalChainContext {
    pub certificate_id: String,
    pub canonical_event_hash: [u8; 32],
    pub presentation_artifact_content_hash: [u8; 32],
    pub kid: [u8; 16],
    pub cose_sign1_ref: [u8; 32],
}

/// Crate error surface.
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("CBOR encode error: {0}")]
    CborEncode(String),
    #[error("CBOR decode error: {0}")]
    CborDecode(String),
    #[error("assertion field {field} is missing")]
    AssertionFieldMissing { field: &'static str },
    #[error("assertion field {field} has wrong type")]
    AssertionFieldType { field: &'static str },
    #[error("assertion field {field} has wrong length: expected {expected}, got {actual}")]
    AssertionFieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("assertion does not match canonical-chain context: field {field} disagrees")]
    AssertionCrossCheckFailed { field: &'static str },
}

/// Emits the Trellis assertion bytes for a Certificate of Completion
/// per ADR 0008 §"`c2pa-manifest`". The returned bytes are dCBOR-
/// canonical (map keys lex-sorted per Core §5.1) and ready to embed
/// in a C2PA manifest store under the assertion label
/// [`ASSERTION_LABEL`]. ISC-02 deterministic derivation: identical
/// inputs MUST yield byte-identical output.
///
/// # Errors
///
/// Returns [`AdapterError::CborEncode`] if the dCBOR serializer
/// rejects the structure (should not happen for valid 32-byte /
/// 16-byte digests + valid UTF-8 `certificate_id`).
pub fn emit_c2pa_manifest_for_certificate(
    certificate_id: &str,
    canonical_event_hash: &[u8; 32],
    presentation_artifact_content_hash: &[u8; 32],
    kid: &[u8; 16],
    cose_sign1_ref: &[u8; 32],
) -> Result<Vec<u8>, AdapterError> {
    // dCBOR canonical map-key order = lex sort on the **encoded `tstr`
    // bytes** (RFC 8949 §4.2.2), not on the decoded UTF-8 string.
    // `ciborium`'s `Value::Map` is a `Vec<(Value, Value)>` and
    // serializes in insertion order, so we sort the five entries on
    // their encoded-tstr key bytes before constructing the map.
    let mut entries: Vec<(Vec<u8>, Value, Value)> = vec![
        (
            encode_tstr_key(FIELD_CANONICAL_EVENT_HASH),
            Value::Text(FIELD_CANONICAL_EVENT_HASH.to_string()),
            Value::Bytes(canonical_event_hash.to_vec()),
        ),
        (
            encode_tstr_key(FIELD_CERTIFICATE_ID),
            Value::Text(FIELD_CERTIFICATE_ID.to_string()),
            Value::Text(certificate_id.to_string()),
        ),
        (
            encode_tstr_key(FIELD_COSE_SIGN1_REF),
            Value::Text(FIELD_COSE_SIGN1_REF.to_string()),
            Value::Bytes(cose_sign1_ref.to_vec()),
        ),
        (
            encode_tstr_key(FIELD_KID),
            Value::Text(FIELD_KID.to_string()),
            Value::Bytes(kid.to_vec()),
        ),
        (
            encode_tstr_key(FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH),
            Value::Text(FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH.to_string()),
            Value::Bytes(presentation_artifact_content_hash.to_vec()),
        ),
    ];
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let value = Value::Map(
        entries
            .into_iter()
            .map(|(_, k, v)| (k, v))
            .collect::<Vec<_>>(),
    );
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|error| AdapterError::CborEncode(error.to_string()))?;
    Ok(buf)
}

/// Encodes a CBOR `tstr` head + payload (RFC 8949 §3.1, major type 3)
/// for a Rust `&str`. Used by the canonical map-key sort so we compare
/// keys on their on-the-wire bytes rather than on the decoded UTF-8
/// string. The five assertion field names are all ≤ 255 bytes, so we
/// only need the 1-byte / 1+1-byte head forms.
fn encode_tstr_key(s: &str) -> Vec<u8> {
    let payload = s.as_bytes();
    let n = payload.len();
    let mut out = Vec::with_capacity(2 + n);
    if n < 24 {
        // 0b011_xxxxx — short form, length in low 5 bits.
        out.push(0x60 | n as u8);
    } else if n < 256 {
        // 0b011_11000 (0x78) — 1-byte length follows.
        out.push(0x78);
        out.push(n as u8);
    } else {
        // Unreachable for the Trellis assertion field set (max 42).
        // For completeness if a future field exceeds 255 bytes, the
        // 2-byte length form (0x79) would land here; the assertion
        // CDDL caps field-name length well below that.
        unreachable!("assertion field name {n} bytes exceeds 1-byte length form");
    }
    out.extend_from_slice(payload);
    out
}

/// Parses a Trellis assertion from C2PA-extracted bytes. The caller
/// is responsible for extracting the assertion bytes from the C2PA
/// manifest store (using their preferred C2PA SDK); this function
/// decodes the bytes as dCBOR and validates the five-field shape.
///
/// # Errors
///
/// Returns [`AdapterError::CborDecode`] if the bytes are not valid
/// CBOR; [`AdapterError::AssertionFieldMissing`] /
/// [`AdapterError::AssertionFieldType`] /
/// [`AdapterError::AssertionFieldLength`] if the structural shape
/// disagrees with the assertion CDDL.
pub fn extract_trellis_assertion(c2pa_bytes: &[u8]) -> Result<TrellisAssertion, AdapterError> {
    let value: Value = trellis_types::decode_cbor_value(c2pa_bytes)
        .map_err(|error| AdapterError::CborDecode(error.to_string()))?;
    let map = match value {
        Value::Map(entries) => entries,
        _ => {
            return Err(AdapterError::CborDecode(
                "assertion root is not a map".into(),
            ));
        }
    };

    let certificate_id = lookup_text(&map, FIELD_CERTIFICATE_ID)?;
    let canonical_event_hash = lookup_fixed_bytes(&map, FIELD_CANONICAL_EVENT_HASH, 32)?;
    let presentation_artifact_content_hash =
        lookup_fixed_bytes(&map, FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH, 32)?;
    let kid = lookup_fixed_bytes(&map, FIELD_KID, 16)?;
    let cose_sign1_ref = lookup_fixed_bytes(&map, FIELD_COSE_SIGN1_REF, 32)?;

    Ok(TrellisAssertion {
        certificate_id,
        canonical_event_hash: canonical_event_hash
            .as_slice()
            .try_into()
            .expect("verified 32 bytes"),
        presentation_artifact_content_hash: presentation_artifact_content_hash
            .as_slice()
            .try_into()
            .expect("verified 32 bytes"),
        kid: kid.as_slice().try_into().expect("verified 16 bytes"),
        cose_sign1_ref: cose_sign1_ref
            .as_slice()
            .try_into()
            .expect("verified 32 bytes"),
    })
}

impl TrellisAssertion {
    /// Five-field cross-check against the canonical chain. Each field
    /// is byte-equality checked; the first disagreement returns
    /// [`AdapterError::AssertionCrossCheckFailed`] naming the field.
    /// This is the C2PA-tooling-path verification layer (ADR 0008
    /// path-(a)); core verifier path-(b) does NOT call this.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::AssertionCrossCheckFailed`] on any
    /// field disagreement.
    pub fn verify_against_canonical_chain(
        &self,
        context: &CanonicalChainContext,
    ) -> Result<(), AdapterError> {
        if self.certificate_id != context.certificate_id {
            return Err(AdapterError::AssertionCrossCheckFailed {
                field: "certificate_id",
            });
        }
        if self.canonical_event_hash != context.canonical_event_hash {
            return Err(AdapterError::AssertionCrossCheckFailed {
                field: "canonical_event_hash",
            });
        }
        if self.presentation_artifact_content_hash != context.presentation_artifact_content_hash {
            return Err(AdapterError::AssertionCrossCheckFailed {
                field: "presentation_artifact.content_hash",
            });
        }
        if self.kid != context.kid {
            return Err(AdapterError::AssertionCrossCheckFailed { field: "kid" });
        }
        if self.cose_sign1_ref != context.cose_sign1_ref {
            return Err(AdapterError::AssertionCrossCheckFailed {
                field: "cose_sign1_ref",
            });
        }
        Ok(())
    }
}

/// Convenience: compute `cose_sign1_ref` from raw COSE_Sign1 bytes
/// per ADR 0008 §"`c2pa-manifest`" assertion-field table — SHA-256
/// under domain tag `trellis-content-v1`. Mirrors the verifier's
/// digest convention for sidecar bytes (Core §18.3a).
#[must_use]
pub fn compute_cose_sign1_ref(cose_sign1_bytes: &[u8]) -> [u8; 32] {
    domain_separated_sha256(CONTENT_DOMAIN, cose_sign1_bytes)
}

/// Convenience: SHA-256 over arbitrary bytes (no domain tag). Useful
/// for tests that need a quick digest; for canonical assertion
/// fields, use the appropriate domain tag instead.
#[must_use]
pub fn sha256_plain(bytes: &[u8]) -> [u8; 32] {
    trellis_types::sha256_bytes(bytes)
}

fn lookup_text(map: &[(Value, Value)], key: &'static str) -> Result<String, AdapterError> {
    match map_lookup_optional_value(map, key) {
        None => Err(AdapterError::AssertionFieldMissing { field: key }),
        Some(Value::Text(text)) => Ok(text.clone()),
        Some(_) => Err(AdapterError::AssertionFieldType { field: key }),
    }
}

fn lookup_fixed_bytes(
    map: &[(Value, Value)],
    key: &'static str,
    expected: usize,
) -> Result<Vec<u8>, AdapterError> {
    let bytes = match map_lookup_optional_value(map, key) {
        None => return Err(AdapterError::AssertionFieldMissing { field: key }),
        Some(Value::Bytes(bytes)) => bytes.clone(),
        Some(_) => return Err(AdapterError::AssertionFieldType { field: key }),
    };
    if bytes.len() != expected {
        return Err(AdapterError::AssertionFieldLength {
            field: key,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_inputs() -> ([u8; 32], [u8; 32], [u8; 16], [u8; 32]) {
        let canonical_event_hash = [0x11_u8; 32];
        let presentation_artifact_content_hash = [0x22_u8; 32];
        let kid = [0x33_u8; 16];
        let cose_sign1_ref = [0x44_u8; 32];
        (
            canonical_event_hash,
            presentation_artifact_content_hash,
            kid,
            cose_sign1_ref,
        )
    }

    #[test]
    fn assertion_refuses_duplicate_keys_and_trailing_bytes() {
        let (event, presentation, kid, sign1) = sample_inputs();
        let original =
            emit_c2pa_manifest_for_certificate("cert-001", &event, &presentation, &kid, &sign1)
                .unwrap();
        extract_trellis_assertion(&original).unwrap();
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(
            extract_trellis_assertion(&trailing)
                .unwrap_err()
                .to_string()
                .contains("trailing bytes")
        );
        let value: Value = ciborium::from_reader(original.as_slice()).unwrap();
        for nested in [false, true] {
            let mut value = value.clone();
            let Value::Map(fields) = &mut value else {
                panic!("map")
            };
            if nested {
                fields.push((
                    Value::Text("unknown".into()),
                    Value::Map(vec![
                        (Value::Text("key".into()), Value::Null),
                        (Value::Text("key".into()), Value::Null),
                    ]),
                ));
            } else {
                fields.push(fields[0].clone());
            }
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).unwrap();
            assert!(
                extract_trellis_assertion(&bytes)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate")
            );
        }
    }

    #[test]
    fn emit_then_extract_round_trip_byte_exact() {
        let (canonical_event_hash, pa_content_hash, kid, cose_sign1_ref) = sample_inputs();
        let bytes = emit_c2pa_manifest_for_certificate(
            "cert-001",
            &canonical_event_hash,
            &pa_content_hash,
            &kid,
            &cose_sign1_ref,
        )
        .expect("emit");
        let assertion = extract_trellis_assertion(&bytes).expect("extract");
        assert_eq!(assertion.certificate_id, "cert-001");
        assert_eq!(assertion.canonical_event_hash, canonical_event_hash);
        assert_eq!(
            assertion.presentation_artifact_content_hash,
            pa_content_hash
        );
        assert_eq!(assertion.kid, kid);
        assert_eq!(assertion.cose_sign1_ref, cose_sign1_ref);

        // ISC-02: identical inputs MUST yield byte-identical output.
        let bytes2 = emit_c2pa_manifest_for_certificate(
            "cert-001",
            &canonical_event_hash,
            &pa_content_hash,
            &kid,
            &cose_sign1_ref,
        )
        .expect("emit2");
        assert_eq!(bytes, bytes2, "deterministic derivation (ISC-02)");
    }

    #[test]
    fn cross_check_passes_for_matching_context() {
        let (canonical_event_hash, pa_content_hash, kid, cose_sign1_ref) = sample_inputs();
        let bytes = emit_c2pa_manifest_for_certificate(
            "cert-001",
            &canonical_event_hash,
            &pa_content_hash,
            &kid,
            &cose_sign1_ref,
        )
        .expect("emit");
        let assertion = extract_trellis_assertion(&bytes).expect("extract");
        let context = CanonicalChainContext {
            certificate_id: "cert-001".into(),
            canonical_event_hash,
            presentation_artifact_content_hash: pa_content_hash,
            kid,
            cose_sign1_ref,
        };
        assertion
            .verify_against_canonical_chain(&context)
            .expect("cross-check should pass");
    }

    #[test]
    fn cross_check_fails_when_any_field_disagrees() {
        let (canonical_event_hash, pa_content_hash, kid, cose_sign1_ref) = sample_inputs();
        let bytes = emit_c2pa_manifest_for_certificate(
            "cert-001",
            &canonical_event_hash,
            &pa_content_hash,
            &kid,
            &cose_sign1_ref,
        )
        .unwrap();
        let assertion = extract_trellis_assertion(&bytes).unwrap();

        // certificate_id mismatch
        let mut context = CanonicalChainContext {
            certificate_id: "cert-002".into(),
            canonical_event_hash,
            presentation_artifact_content_hash: pa_content_hash,
            kid,
            cose_sign1_ref,
        };
        assert!(matches!(
            assertion.verify_against_canonical_chain(&context),
            Err(AdapterError::AssertionCrossCheckFailed {
                field: "certificate_id"
            })
        ));

        // canonical_event_hash mismatch
        context.certificate_id = "cert-001".into();
        context.canonical_event_hash = [0xff; 32];
        assert!(matches!(
            assertion.verify_against_canonical_chain(&context),
            Err(AdapterError::AssertionCrossCheckFailed {
                field: "canonical_event_hash"
            })
        ));

        // presentation_artifact.content_hash mismatch
        context.canonical_event_hash = canonical_event_hash;
        context.presentation_artifact_content_hash = [0xee; 32];
        assert!(matches!(
            assertion.verify_against_canonical_chain(&context),
            Err(AdapterError::AssertionCrossCheckFailed {
                field: "presentation_artifact.content_hash"
            })
        ));

        // kid mismatch
        context.presentation_artifact_content_hash = pa_content_hash;
        context.kid = [0xdd; 16];
        assert!(matches!(
            assertion.verify_against_canonical_chain(&context),
            Err(AdapterError::AssertionCrossCheckFailed { field: "kid" })
        ));

        // cose_sign1_ref mismatch
        context.kid = kid;
        context.cose_sign1_ref = [0xcc; 32];
        assert!(matches!(
            assertion.verify_against_canonical_chain(&context),
            Err(AdapterError::AssertionCrossCheckFailed {
                field: "cose_sign1_ref"
            })
        ));
    }

    #[test]
    fn extract_rejects_non_map_root() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Text("not-a-map".into()), &mut buf).unwrap();
        let err = extract_trellis_assertion(&buf).unwrap_err();
        assert!(matches!(err, AdapterError::CborDecode(_)));
    }

    #[test]
    fn extract_rejects_missing_field() {
        // Build a 4-of-5 map missing certificate_id.
        let bad = Value::Map(vec![
            (
                Value::Text(FIELD_CANONICAL_EVENT_HASH.into()),
                Value::Bytes(vec![0; 32]),
            ),
            (
                Value::Text(FIELD_COSE_SIGN1_REF.into()),
                Value::Bytes(vec![0; 32]),
            ),
            (Value::Text(FIELD_KID.into()), Value::Bytes(vec![0; 16])),
            (
                Value::Text(FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH.into()),
                Value::Bytes(vec![0; 32]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&bad, &mut buf).unwrap();
        let err = extract_trellis_assertion(&buf).unwrap_err();
        assert!(matches!(
            err,
            AdapterError::AssertionFieldMissing {
                field: "trellis.certificate_id"
            }
        ));
    }

    #[test]
    fn extract_rejects_wrong_length_kid() {
        let bad = Value::Map(vec![
            (
                Value::Text(FIELD_CANONICAL_EVENT_HASH.into()),
                Value::Bytes(vec![0; 32]),
            ),
            (
                Value::Text(FIELD_CERTIFICATE_ID.into()),
                Value::Text("c".into()),
            ),
            (
                Value::Text(FIELD_COSE_SIGN1_REF.into()),
                Value::Bytes(vec![0; 32]),
            ),
            (
                Value::Text(FIELD_KID.into()),
                Value::Bytes(vec![0; 8]), // wrong: should be 16
            ),
            (
                Value::Text(FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH.into()),
                Value::Bytes(vec![0; 32]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&bad, &mut buf).unwrap();
        let err = extract_trellis_assertion(&buf).unwrap_err();
        assert!(matches!(
            err,
            AdapterError::AssertionFieldLength {
                field: "trellis.kid",
                expected: 16,
                actual: 8
            }
        ));
    }

    #[test]
    fn compute_cose_sign1_ref_uses_content_domain() {
        let bytes = b"fake cose sign1 bytes";
        let digest = compute_cose_sign1_ref(bytes);
        let expected = domain_separated_sha256(CONTENT_DOMAIN, bytes);
        assert_eq!(digest, expected);
    }

    /// ISC-02 byte-determinism oracle: emitter output MUST be
    /// byte-equal to the canonical on-disk fixture, which was
    /// generated by `cbor2.dumps(..., canonical=True)` in the
    /// `gen_interop_sidecar_c2pa_037_to_040.py` generator. This is the
    /// within-crate half of the cross-implementation oracle (the
    /// `trellis-py` half is `test_interop_c2pa_byte_oracle.py`).
    /// Two emitters reaching the same bytes for identical logical
    /// input is the load-bearing claim.
    #[test]
    fn emit_matches_canonical_dcbor_fixture_bytes() {
        // Inputs match `ASSERTION_FIELDS` in
        // `fixtures/vectors/_generator/gen_interop_sidecar_c2pa_037_to_040.py`.
        let canonical_event_hash = [0x11_u8; 32];
        let pa_content_hash = [0x22_u8; 32];
        let kid = [0x33_u8; 16];
        let cose_sign1_ref = [0x44_u8; 32];
        let bytes = emit_c2pa_manifest_for_certificate(
            "cert-wave25-001",
            &canonical_event_hash,
            &pa_content_hash,
            &kid,
            &cose_sign1_ref,
        )
        .expect("emit");

        // Workspace-relative: `crates/trellis-interop-c2pa/Cargo.toml`
        // lives at `<workspace>/crates/trellis-interop-c2pa/`, so the
        // fixture sits at `../../fixtures/...` relative to that.
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vectors")
            .join("export")
            .join("014-interop-sidecar-c2pa-manifest")
            .join("interop-sidecars")
            .join("c2pa-manifest")
            .join("cert-wave25-001.c2pa");
        let fixture_bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|err| panic!("read fixture {fixture_path:?}: {err}"));

        assert_eq!(
            bytes, fixture_bytes,
            "emit_c2pa_manifest_for_certificate must produce dCBOR-canonical bytes \
             byte-equal to the cbor2(canonical=True) fixture (Core §5.1, RFC 8949 §4.2.2)"
        );
    }

    /// Unit-level guard on the canonical key order. Locks the
    /// dCBOR-canonical sequence in by name so any future field
    /// rename / addition forces a deliberate canonical-order recheck
    /// (and a fixture regeneration) rather than silently regressing.
    #[test]
    fn emit_canonical_key_order_is_kid_then_cert_then_cose_then_canonical_then_pa() {
        let bytes =
            emit_c2pa_manifest_for_certificate("cert-test", &[0; 32], &[0; 32], &[0; 16], &[0; 32])
                .expect("emit");
        let value: Value = ciborium::de::from_reader(Cursor::new(&bytes)).expect("decode");
        let entries = match value {
            Value::Map(entries) => entries,
            _ => panic!("expected map"),
        };
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => panic!("non-text key"),
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                FIELD_KID,
                FIELD_CERTIFICATE_ID,
                FIELD_COSE_SIGN1_REF,
                FIELD_CANONICAL_EVENT_HASH,
                FIELD_PRESENTATION_ARTIFACT_CONTENT_HASH,
            ],
            "dCBOR canonical order is length-then-bytes; encoded-tstr lex sort \
             gives kid(11) < certificate_id(22) < cose_sign1_ref(22) < \
             canonical_event_hash(28) < presentation_artifact.content_hash(42)"
        );
    }

    #[test]
    fn encode_tstr_key_short_and_one_byte_length_forms() {
        // < 24 bytes — major type 3 short form.
        assert_eq!(encode_tstr_key("trellis.kid"), {
            let mut v = vec![0x60 | 11_u8];
            v.extend_from_slice(b"trellis.kid");
            v
        });
        // ≥ 24 bytes — 1-byte length follows the 0x78 head.
        let key_28 = "trellis.canonical_event_hash"; // length 28
        let mut want = vec![0x78, 28];
        want.extend_from_slice(key_28.as_bytes());
        assert_eq!(encode_tstr_key(key_28), want);
    }
}
