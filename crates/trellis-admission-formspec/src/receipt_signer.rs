// Rust guideline compliant 2026-02-21
//! Deployment-class receipt-signer adapter and composable PQC suite hook
//! for Trellis-Formspec signature admission (ADR 0109, ADR 0111, fs-fmc9).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use integrity_canonical::domain_separated_canonical_bytes;
use integrity_cose::{
    detached_signature_protected_header, encode_cose_sign1, sig_structure_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_common_error::StackError;

/// Domain separator for Formspec verification receipt signatures per ADR 0111.
pub const FORMSPEC_RECEIPT_PAYLOAD_DOMAIN: &str = "formspec.verification.receipt.v1";

/// Standard prefix for receipt-signing method URIs per ADR 0109 / ADR 0111.
pub const FORMSPEC_RECEIPT_METHOD_URI_PREFIX: &str = "urn:formspec:receipt-method:";

/// Default Formspec Ed25519 receipt-signing method URI from registry v1.1.0.
pub const FORMSPEC_RECEIPT_METHOD_ED25519: &str =
    "urn:formspec:receipt-method:ed25519-cose-sign1@1";

/// Key class taxonomy per ADR 0111 §Key class taxonomy.
///
/// Distinct key classes MUST NOT alias across roles:
/// - Response-signing: respondent signs formspec response
/// - Receipt-signing: deployment-class signer binds verification verdict
/// - Substrate-signing: Trellis service signs substrate ledger envelopes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyClassRole {
    /// Respondent-held or delegated response signing key.
    ResponseSigningKey,
    /// Deployment-class receipt signer key.
    ReceiptSigningKey,
    /// Trellis substrate envelope signing key.
    SubstrateSigningKey,
}

/// Configuration for the deployment-class receipt signer adapter.
#[derive(Debug, Clone)]
pub struct DeploymentReceiptSignerConfig {
    /// Key class role assigned to this key (enforces ADR 0111 segregation).
    pub key_role: KeyClassRole,
    /// Key identifier (COSE kid).
    pub key_id: Vec<u8>,
    /// Receipt-signing method URI.
    pub method_uri: String,
    /// COSE algorithm identifier (e.g. -8 for Ed25519 / EdDSA).
    pub alg: i32,
}

impl DeploymentReceiptSignerConfig {
    /// Constructs a valid configuration for deployment receipt signing.
    ///
    /// # Errors
    /// Returns `StackError::bad_request` if the key role is not `ReceiptSigningKey`
    /// or if `method_uri` does not start with [`FORMSPEC_RECEIPT_METHOD_URI_PREFIX`].
    pub fn new(
        key_role: KeyClassRole,
        key_id: Vec<u8>,
        method_uri: impl Into<String>,
        alg: i32,
    ) -> Result<Self, StackError> {
        let uri = method_uri.into();
        if key_role != KeyClassRole::ReceiptSigningKey {
            return Err(StackError::bad_request(format!(
                "ADR 0111 Key Role Segregation Violation: expected ReceiptSigningKey, got {key_role:?}"
            )));
        }
        if !uri.starts_with(FORMSPEC_RECEIPT_METHOD_URI_PREFIX) {
            return Err(StackError::bad_request(format!(
                "Invalid receipt method URI {uri:?}: must start with {FORMSPEC_RECEIPT_METHOD_URI_PREFIX}"
            )));
        }
        Ok(Self {
            key_role,
            key_id,
            method_uri: uri,
            alg,
        })
    }
}

/// Computes the canonical domain-separated payload bytes for a `VerificationReceipt` JSON object.
///
/// Per ADR 0111, `receiptBytes` is stripped before JSON Canonicalization (JCS),
/// so the signature does not recursively commit to itself. The signed preimage is:
/// `b"formspec.verification.receipt.v1" || 0x00 || JCS(receipt_without_receiptBytes)`.
///
/// # Errors
/// Returns `StackError::bad_request` if `receipt` is not a valid JSON object or JCS fails.
pub fn canonical_receipt_payload_bytes(receipt: &Value) -> Result<Vec<u8>, StackError> {
    let mut stripped = receipt.clone();
    let map = stripped.as_object_mut().ok_or_else(|| {
        StackError::bad_request("VerificationReceipt must be a JSON object")
    })?;
    map.remove("receiptBytes");

    domain_separated_canonical_bytes(FORMSPEC_RECEIPT_PAYLOAD_DOMAIN, &stripped).map_err(
        |error| StackError::internal(format!("failed to canonicalize receipt payload: {error}")),
    )
}

/// Builds the consumer detached-signature protected header for a receipt per ADR 0109 / ADR 0111.
///
/// Emits MAP_3:
/// - Label `1` => `alg`
/// - Label `4` => `kid`
/// - Label `-65540` => `method_uri`
#[must_use]
pub fn build_receipt_protected_header(alg: i32, kid: &[u8], method_uri: &str) -> Vec<u8> {
    detached_signature_protected_header(alg, kid, method_uri)
}

/// Signing closure handle for `DeploymentReceiptSigner`.
pub type ReceiptSignClosure = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, StackError> + Send + Sync>;

/// Deployment-class receipt signer adapter (ADR 0111).
///
/// Signs canonical receipt payloads using a deployment key, producing a detached COSE_Sign1 envelope.
#[derive(Clone)]
pub struct DeploymentReceiptSigner {
    config: DeploymentReceiptSignerConfig,
    sign_fn: ReceiptSignClosure,
}

impl DeploymentReceiptSigner {
    /// Constructs a deployment-class receipt signer with a backing sign closure.
    pub fn new<F>(config: DeploymentReceiptSignerConfig, sign_fn: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, StackError> + Send + Sync + 'static,
    {
        Self {
            config,
            sign_fn: Arc::new(sign_fn),
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &DeploymentReceiptSignerConfig {
        &self.config
    }

    /// Signs the canonical receipt payload, returning COSE_Sign1 envelope bytes.
    ///
    /// The detached envelope carries protected header MAP_3 (`alg`, `kid`, `method_uri`),
    /// empty payload, and the signature bytes over RFC 9052 `Sig_structure`.
    ///
    /// # Errors
    /// Returns `StackError` if signing fails or key role segregation is violated.
    pub fn sign_receipt(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, StackError> {
        if self.config.key_role != KeyClassRole::ReceiptSigningKey {
            return Err(StackError::bad_request(
                "ADR 0111 Key Role Segregation Violation: refusing to sign receipt with non-receipt key",
            ));
        }

        let protected_header = build_receipt_protected_header(
            self.config.alg,
            &self.config.key_id,
            &self.config.method_uri,
        );

        let sig_structure = sig_structure_bytes(&protected_header, canonical_payload);
        let signature = (self.sign_fn)(&sig_structure)?;

        Ok(encode_cose_sign1(&protected_header, None, &signature))
    }
}

// ---------------------------------------------------------------------------
// Composable PQC Suite Hook Interface
// ---------------------------------------------------------------------------

/// Composable Post-Quantum Cryptography (PQC) suite hook trait.
///
/// Enables future-proof composition of PQC signing algorithms (e.g., ML-DSA-65,
/// SLH-DSA-128s from signature-method-registry.json) into Trellis admission
/// and signature verification without modifying core admission logic.
pub trait PqcSignatureSuiteHook: Send + Sync {
    /// Returns the name / identifier of the PQC suite.
    fn suite_name(&self) -> &'static str;

    /// Returns `true` if this hook supports the given signature method URI.
    fn supports_method(&self, method_uri: &str) -> bool;

    /// Verifies a PQC detached signature over `payload` with `public_key`.
    fn verify_pqc_signature(
        &self,
        method_uri: &str,
        payload: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), StackError>;

    /// Signs `payload` with `private_key` under this PQC method.
    fn sign_pqc_payload(
        &self,
        method_uri: &str,
        payload: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, StackError>;
}

/// Thread-safe registry for composable PQC suite hooks.
#[derive(Default, Clone)]
pub struct ComposablePqcRegistry {
    hooks: Arc<RwLock<HashMap<String, Arc<dyn PqcSignatureSuiteHook>>>>,
}

impl ComposablePqcRegistry {
    /// Creates a new empty PQC hook registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a PQC suite hook for a specific method URI.
    pub fn register(&self, method_uri: impl Into<String>, hook: Arc<dyn PqcSignatureSuiteHook>) {
        if let Ok(mut lock) = self.hooks.write() {
            lock.insert(method_uri.into(), hook);
        }
    }

    /// Resolves a PQC suite hook for a method URI if registered.
    #[must_use]
    pub fn get(&self, method_uri: &str) -> Option<Arc<dyn PqcSignatureSuiteHook>> {
        self.hooks
            .read()
            .ok()
            .and_then(|lock| lock.get(method_uri).cloned())
    }

    /// Returns `true` if a registered PQC suite hook supports `method_uri`.
    #[must_use]
    pub fn is_pqc_method_supported(&self, method_uri: &str) -> bool {
        self.hooks
            .read()
            .ok()
            .is_some_and(|lock| lock.contains_key(method_uri))
    }
}
