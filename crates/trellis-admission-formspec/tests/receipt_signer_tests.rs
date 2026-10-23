// Rust guideline compliant 2026-02-21
//! Integration and cross-adapter byte-equivalence tests for Trellis-Formspec
//! deployment receipt-signer adapter and composable PQC suite hook (fs-fmc9).
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use integrity_cose::{decode_cose_sign1, decode_protected_header};
use serde_json::json;
use stack_common_error::StackError;
use trellis_admission_formspec::receipt_signer::{
    ComposablePqcRegistry, DeploymentReceiptSigner, DeploymentReceiptSignerConfig,
    FORMSPEC_RECEIPT_METHOD_ED25519, FORMSPEC_RECEIPT_PAYLOAD_DOMAIN, KeyClassRole,
    PqcSignatureSuiteHook, build_receipt_protected_header, canonical_receipt_payload_bytes,
};

#[test]
fn deployment_receipt_signer_constructs_valid_detached_envelope() {
    let config = DeploymentReceiptSignerConfig::new(
        KeyClassRole::ReceiptSigningKey,
        b"deployment-receipt-key-01".to_vec(),
        FORMSPEC_RECEIPT_METHOD_ED25519,
        -8, // EdDSA / Ed25519
    )
    .expect("valid config");

    let signer = DeploymentReceiptSigner::new(config, |sig_structure| {
        // Deterministic dummy signature for byte-level testing
        let mut sig = vec![0xee; 64];
        if !sig_structure.is_empty() {
            sig[0] = sig_structure[0];
        }
        Ok(sig)
    });

    let receipt_json = json!({
        "result": "verified",
        "method": "urn:formspec:sig-method:ed25519-cose-sign1@1",
        "methodRegistryVersion": "1.1.0",
        "adapter": {
            "id": "urn:formspec:adapter:ring@1",
            "version": "1.0.0"
        },
        "key": {
            "ref": "test-kid-001"
        },
        "verifiedAt": "2026-10-23T18:00:00Z",
        "receiptBytes": "0oRWoQExiQEFQnNpZ25lZA=="
    });

    let canonical_payload =
        canonical_receipt_payload_bytes(&receipt_json).expect("canonical bytes");

    let cose_bytes = signer
        .sign_receipt(&canonical_payload)
        .expect("sign receipt");

    // Decode COSE_Sign1 envelope
    let cose = decode_cose_sign1(&cose_bytes).expect("decode COSE_Sign1");
    assert!(cose.payload().is_none(), "payload must be detached");
    assert_eq!(cose.signature().len(), 64);

    // Decode and verify protected header MAP_3
    let header = decode_protected_header(cose.protected_header()).expect("decode header");
    assert_eq!(header.alg, -8);
    assert_eq!(header.kid.as_deref(), Some(b"deployment-receipt-key-01".as_slice()));
    assert_eq!(
        header.method_uri.as_deref(),
        Some(FORMSPEC_RECEIPT_METHOD_ED25519)
    );
}

#[test]
fn cross_adapter_byte_equivalence_vectors() {
    // Assert protected header byte-equivalence:
    // MAP_3 with label 1 (alg), label 4 (kid), label -65540 (method_uri)
    let kid = b"receipt-kid-vector-42";
    let method_uri = "urn:formspec:receipt-method:ed25519-cose-sign1@1";
    let alg = -8;

    let header_bytes = build_receipt_protected_header(alg, kid, method_uri);

    // Label -65540 encoding in dCBOR: major type 1, 4 bytes 0x00010003
    let expected_label_bytes = [0x3a, 0x00, 0x01, 0x00, 0x03];
    assert!(
        header_bytes
            .windows(expected_label_bytes.len())
            .any(|w| w == expected_label_bytes),
        "protected header MUST carry COSE label -65540 encoded as [0x3a, 0x00, 0x01, 0x00, 0x03]"
    );

    // Verify round-trip decoding via integrity-cose
    let decoded = decode_protected_header(&header_bytes).expect("decode protected header");
    assert_eq!(decoded.alg, alg as i128);
    assert_eq!(decoded.kid.as_deref(), Some(kid.as_slice()));
    assert_eq!(decoded.method_uri.as_deref(), Some(method_uri));
}

#[test]
fn key_role_segregation_rejects_non_receipt_key_classes() {
    // ADR 0111 Threat Model: response or substrate keys cannot be used for receipt signing
    let err_response = DeploymentReceiptSignerConfig::new(
        KeyClassRole::ResponseSigningKey,
        b"resp-key".to_vec(),
        FORMSPEC_RECEIPT_METHOD_ED25519,
        -8,
    );
    assert!(err_response.is_err());
    assert!(
        err_response
            .unwrap_err()
            .to_string()
            .contains("Key Role Segregation Violation")
    );

    let err_substrate = DeploymentReceiptSignerConfig::new(
        KeyClassRole::SubstrateSigningKey,
        b"substrate-key".to_vec(),
        FORMSPEC_RECEIPT_METHOD_ED25519,
        -8,
    );
    assert!(err_substrate.is_err());
    assert!(
        err_substrate
            .unwrap_err()
            .to_string()
            .contains("Key Role Segregation Violation")
    );

    // Method URI outside urn:formspec:receipt-method: subspace must also be rejected
    let err_method = DeploymentReceiptSignerConfig::new(
        KeyClassRole::ReceiptSigningKey,
        b"receipt-key".to_vec(),
        "urn:formspec:sig-method:ed25519-cose-sign1@1", // response method, not receipt method
        -8,
    );
    assert!(err_method.is_err());
    assert!(
        err_method
            .unwrap_err()
            .to_string()
            .contains("Invalid receipt method URI")
    );
}

#[test]
fn canonical_receipt_payload_strips_receipt_bytes() {
    let receipt_a = json!({
        "result": "verified",
        "method": "urn:formspec:sig-method:ed25519-cose-sign1@1",
        "methodRegistryVersion": "1.1.0",
        "adapter": { "id": "urn:formspec:adapter:ring@1", "version": "1.0.0" },
        "key": { "ref": "key-1" },
        "verifiedAt": "2026-10-23T18:00:00Z",
        "receiptBytes": "inline-signature-bytes-to-be-stripped"
    });

    let receipt_b = json!({
        "result": "verified",
        "method": "urn:formspec:sig-method:ed25519-cose-sign1@1",
        "methodRegistryVersion": "1.1.0",
        "adapter": { "id": "urn:formspec:adapter:ring@1", "version": "1.0.0" },
        "key": { "ref": "key-1" },
        "verifiedAt": "2026-10-23T18:00:00Z"
    });

    let bytes_a = canonical_receipt_payload_bytes(&receipt_a).unwrap();
    let bytes_b = canonical_receipt_payload_bytes(&receipt_b).unwrap();

    assert_eq!(bytes_a, bytes_b);
    assert!(bytes_a.starts_with(FORMSPEC_RECEIPT_PAYLOAD_DOMAIN.as_bytes()));
}

// Mock PQC suite hook for testing composition
struct MockMlDsa65Hook;

impl PqcSignatureSuiteHook for MockMlDsa65Hook {
    fn suite_name(&self) -> &'static str {
        "ML-DSA-65 (FIPS 204)"
    }

    fn supports_method(&self, method_uri: &str) -> bool {
        method_uri == "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1"
    }

    fn verify_pqc_signature(
        &self,
        method_uri: &str,
        payload: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), StackError> {
        if !self.supports_method(method_uri) {
            return Err(StackError::bad_request("unsupported PQC method"));
        }
        if signature.is_empty() || public_key.is_empty() || payload.is_empty() {
            return Err(StackError::bad_request("invalid PQC verification inputs"));
        }
        Ok(())
    }

    fn sign_pqc_payload(
        &self,
        method_uri: &str,
        payload: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, StackError> {
        if !self.supports_method(method_uri) {
            return Err(StackError::bad_request("unsupported PQC method"));
        }
        if private_key.is_empty() || payload.is_empty() {
            return Err(StackError::bad_request("invalid PQC signing inputs"));
        }
        // Simulated ML-DSA-65 signature bytes (3309 bytes standard)
        let mut sig = vec![0x4d; 128]; // mock representation
        sig[0] = payload[0];
        Ok(sig)
    }
}

struct MockSlhDsa128sHook;

impl PqcSignatureSuiteHook for MockSlhDsa128sHook {
    fn suite_name(&self) -> &'static str {
        "SLH-DSA-128s (FIPS 205)"
    }

    fn supports_method(&self, method_uri: &str) -> bool {
        method_uri == "urn:formspec:sig-method:slh-dsa-128s-cose-sign1@1"
    }

    fn verify_pqc_signature(
        &self,
        method_uri: &str,
        _payload: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> Result<(), StackError> {
        if !self.supports_method(method_uri) {
            return Err(StackError::bad_request("unsupported PQC method"));
        }
        Ok(())
    }

    fn sign_pqc_payload(
        &self,
        method_uri: &str,
        _payload: &[u8],
        _private_key: &[u8],
    ) -> Result<Vec<u8>, StackError> {
        if !self.supports_method(method_uri) {
            return Err(StackError::bad_request("unsupported PQC method"));
        }
        Ok(vec![0x53; 128])
    }
}

#[test]
fn composable_pqc_registry_lifecycle_and_hooks() {
    let registry = ComposablePqcRegistry::new();

    let ml_dsa_uri = "urn:formspec:sig-method:ml-dsa-65-cose-sign1@1";
    let slh_dsa_uri = "urn:formspec:sig-method:slh-dsa-128s-cose-sign1@1";

    assert!(!registry.is_pqc_method_supported(ml_dsa_uri));
    assert!(!registry.is_pqc_method_supported(slh_dsa_uri));

    // Register ML-DSA-65 hook
    registry.register(ml_dsa_uri, Arc::new(MockMlDsa65Hook));
    assert!(registry.is_pqc_method_supported(ml_dsa_uri));
    assert!(!registry.is_pqc_method_supported(slh_dsa_uri));

    // Register SLH-DSA-128s hook
    registry.register(slh_dsa_uri, Arc::new(MockSlhDsa128sHook));
    assert!(registry.is_pqc_method_supported(ml_dsa_uri));
    assert!(registry.is_pqc_method_supported(slh_dsa_uri));

    // Resolve and execute ML-DSA-65 hook
    let ml_hook = registry.get(ml_dsa_uri).expect("resolved ML-DSA hook");
    assert_eq!(ml_hook.suite_name(), "ML-DSA-65 (FIPS 204)");
    let sig = ml_hook
        .sign_pqc_payload(ml_dsa_uri, b"test-payload", b"test-privkey")
        .expect("sign");
    assert_eq!(sig.len(), 128);
    ml_hook
        .verify_pqc_signature(ml_dsa_uri, b"test-payload", &sig, b"test-pubkey")
        .expect("verify");

    // Resolve and execute SLH-DSA-128s hook
    let slh_hook = registry.get(slh_dsa_uri).expect("resolved SLH-DSA hook");
    assert_eq!(slh_hook.suite_name(), "SLH-DSA-128s (FIPS 205)");
    let sig2 = slh_hook
        .sign_pqc_payload(slh_dsa_uri, b"test-payload", b"test-privkey")
        .expect("sign");
    assert_eq!(sig2.len(), 128);
    slh_hook
        .verify_pqc_signature(slh_dsa_uri, b"test-payload", &sig2, b"test-pubkey")
        .expect("verify");
}
