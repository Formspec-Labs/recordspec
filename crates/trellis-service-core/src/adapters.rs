// Rust guideline compliant 2026-02-21
//! Domain adapters the composition root injects into the generic server.
//!
//! This crate contains no producer-specific code: admission, event-type
//! vocabulary, attachment descriptors and the export profile all arrive through
//! [`ServerAdapters`]. `trellis-server` assembles the
//! shipped set; `deny.toml` keeps the adapter crates out of this crate's graph.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_server_ports::{
    AdmissionEvent, AdmittedEvent, EventAdmissionPolicy, EventType, EventTypeRef,
    EventTypeRegistry, EventTypeSpec, ExportProfile, ExternalAttachmentAdmission, NativeCloseout,
    ReviewGateEventTypeRegistry,
};

use crate::source_content::SourceContentFactory;

/// Everything domain-specific the generic server needs, supplied at construction.
#[derive(Clone)]
pub struct ServerAdapters {
    /// Decides which event types are admitted and how they are classified.
    pub admission_policy: AdmissionRouter,
    /// Event-type vocabulary projected by the registry route and export registry.
    pub event_type_specs: Vec<EventTypeSpec>,
    /// Protected-attachment descriptor admission.
    pub external_attachment_admission: Arc<dyn ExternalAttachmentAdmission>,
    /// Export-profile members, the append-time fold and signing facts.
    pub export_profile: Arc<dyn ExportProfile>,
    /// Native closeout records for Source-content selection.
    pub native_closeout: Arc<dyn NativeCloseout>,
    /// The owner adapter behind configured Source-content composition.
    pub source_content: SourceContentFactory,
}

/// Register-style admission router: each adapter declares which literals it
/// owns, and the router dispatches by literal lookup.
///
/// Adding an ecosystem overlay is one `register_for_literals(...)` call at the
/// composition root. The router fails admission for unregistered literals so
/// unknown event types reject before append.
#[derive(Default, Clone)]
pub struct AdmissionRouter {
    by_literal: HashMap<EventType, Arc<dyn EventAdmissionPolicy<Error = StackError>>>,
    reserved_ledgers: HashMap<&'static str, Vec<&'static str>>,
    payload_policy: Option<Arc<dyn EventAdmissionPolicy<Error = StackError>>>,
}

impl std::fmt::Debug for AdmissionRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionRouter")
            .field("registered_literals", &self.by_literal.len())
            .finish()
    }
}

impl AdmissionRouter {
    /// Creates an empty router. Add adapters with [`Self::register_for_literals`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an adapter as the admission policy for every literal in `literals`.
    ///
    /// Later registrations for the same literal overwrite earlier ones, which
    /// gives composition the final word when a test substitutes a counting
    /// wrapper around an existing adapter.
    #[must_use]
    pub fn register_for_literals<I, S>(
        mut self,
        adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        literals: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for literal in literals {
            self.by_literal.insert(literal.into(), Arc::clone(&adapter));
        }
        self
    }

    /// Reserves an exact ledger id for the listed event literals.
    ///
    /// Events reserved for a ledger are rejected on every other ledger, and the
    /// reserved ledger admits no other event literals.
    #[must_use]
    pub fn reserve_ledger(
        mut self,
        ledger_id: &'static str,
        adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        literals: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        let literals: Vec<_> = literals.into_iter().collect();
        self.reserved_ledgers.insert(ledger_id, literals.clone());
        self.register_for_literals(adapter, literals)
    }

    fn reserved_ledger(&self, scope: &[u8]) -> Option<&[&'static str]> {
        let (key, id) = std::str::from_utf8(scope).ok()?.split_once('.')?;
        if key.len() != 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return None;
        }
        self.reserved_ledgers.get(id).map(Vec::as_slice)
    }

    pub(crate) fn is_contract_event(&self, event_type: &str) -> bool {
        self.reserved_ledgers
            .values()
            .any(|literals| literals.contains(&event_type))
    }

    pub(crate) fn replace_payload_policy(
        &mut self,
        policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    ) {
        self.payload_policy = Some(policy);
    }

    /// Returns true when a literal is registered.
    #[must_use]
    pub fn handles(&self, event_type: &str) -> bool {
        self.by_literal.contains_key(event_type)
    }

    pub(crate) fn check_ledger_event(
        &self,
        scope: &[u8],
        event_type: &str,
    ) -> Result<(), StackError> {
        let allowed = match self.reserved_ledger(scope) {
            Some(literals) => literals.contains(&event_type),
            None => !self.is_contract_event(event_type),
        };
        if !allowed {
            return Err(StackError::bad_request(
                "event type is not allowed on this ledger",
            ));
        }
        Ok(())
    }

    pub(crate) fn uses_canonical_append_replay(&self, scope: &[u8]) -> bool {
        self.reserved_ledger(scope).is_some()
    }
}

#[async_trait]
impl EventAdmissionPolicy for AdmissionRouter {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        self.check_ledger_event(event.scope, event.event_type)?;
        let Some(adapter) = self
            .payload_policy
            .as_ref()
            .or_else(|| self.by_literal.get(event.event_type))
        else {
            return Err(StackError::bad_request(format!(
                "event type `{}` is not registered for admission",
                event.event_type
            )));
        };
        let admitted = adapter.admit(event).await?;
        if admitted.event_type != event.event_type {
            return Err(StackError::internal(
                "admission policy changed the event type",
            ));
        }
        Ok(admitted)
    }
}

/// Read-side snapshot of the event-type catalog after every admission spec has
/// registered through the budget-review gate.
///
/// Generic Trellis service code (catalog projection, export registry) reads from
/// this snapshot, so the registry trait is the single source of truth.
#[derive(Clone, Debug)]
pub struct EventTypeCatalog {
    entries: Vec<EventTypeRef>,
}

impl EventTypeCatalog {
    /// Builds the catalog from the injected specs plus the server's own completion event.
    ///
    /// # Panics
    /// Panics if a spec fails the budget gate; adapter specs satisfy the gate by
    /// construction, so a failure is a composition bug that must stop startup.
    #[must_use]
    pub fn from_specs(specs: impl IntoIterator<Item = EventTypeSpec>) -> Self {
        let mut registry = ReviewGateEventTypeRegistry::default();
        for spec in specs
            .into_iter()
            .chain(std::iter::once(crate::completion::event_type_spec()))
        {
            registry
                .register(spec)
                .expect("admission specs satisfy the budget gate by construction");
        }
        Self {
            entries: registry.entries().cloned().collect(),
        }
    }

    /// Iterates registered event-type entries in event-type lexicographic order.
    pub fn entries(&self) -> impl Iterator<Item = &EventTypeRef> + '_ {
        self.entries.iter()
    }

    /// Looks up the registered entry for an event-type literal.
    #[must_use]
    pub fn get(&self, event_type: &str) -> Option<&EventTypeRef> {
        self.entries
            .iter()
            .find(|entry| entry.event_type == event_type)
    }

    /// Number of registered entries (for sizing tests + projection).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no admission specs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ConstantAdapter(AdmittedEvent);

    #[async_trait]
    impl EventAdmissionPolicy for ConstantAdapter {
        type Error = StackError;
        async fn admit(&self, _event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
            Ok(self.0.clone())
        }
    }

    fn router() -> AdmissionRouter {
        let adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
            Arc::new(ConstantAdapter(AdmittedEvent {
                event_type: "x-test.overlay.synthetic".to_string(),
                event_family: trellis_server_ports::EventFamilyId::new("x-test.overlay").unwrap(),
                schema_ref: trellis_server_ports::SchemaRef::new(
                    "x-test://x-test.overlay.synthetic",
                )
                .unwrap(),
                artifact_type: trellis_types::ArtifactType::Event,
                direct_submit: trellis_server_ports::DirectSubmitPolicy::ServiceOnly,
                max_scope_events: None,
            }));
        AdmissionRouter::new().register_for_literals(adapter, ["x-test.overlay.synthetic"])
    }

    #[tokio::test]
    async fn registered_adapter_dispatches_without_editing_core() {
        let router = router();
        assert!(router.handles("x-test.overlay.synthetic"));
        let admitted = router
            .admit(&AdmissionEvent {
                scope: b"x-test",
                event_type: "x-test.overlay.synthetic",
                payload: b"",
            })
            .await
            .expect("registered overlay admits");
        assert_eq!(admitted.artifact_type, trellis_types::ArtifactType::Event);
    }

    #[tokio::test]
    async fn unregistered_literal_rejects_before_append() {
        let err = router()
            .admit(&AdmissionEvent {
                scope: b"unknown",
                event_type: "c2pa.assertion.created",
                payload: b"{}",
            })
            .await
            .expect_err("unregistered must reject");
        assert!(
            err.to_string().contains("not registered for admission"),
            "router must surface the registration gap; got: {err}"
        );
    }

    #[tokio::test]
    async fn reserved_ledger_binds_events_bidirectionally_without_suffix_coupling() {
        let adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
            Arc::new(ConstantAdapter(AdmittedEvent {
                event_type: "trellis.authority.grant.v1".to_string(),
                event_family: trellis_server_ports::EventFamilyId::new("trellis.authority").unwrap(),
                schema_ref: trellis_server_ports::SchemaRef::new(
                    "https://formspec.org/schemas/trellis/authority-events.schema.json#/$defs/tupleChange",
                )
                .unwrap(),
                artifact_type: trellis_types::ArtifactType::Event,
                direct_submit: trellis_server_ports::DirectSubmitPolicy::ServiceOnly,
                max_scope_events: None,
            }));
        let decision_adapter: Arc<dyn EventAdmissionPolicy<Error = StackError>> =
            Arc::new(ConstantAdapter(AdmittedEvent {
                event_type: "trellis.authority.decision.v1".to_string(),
                event_family: trellis_server_ports::EventFamilyId::new("trellis.authority").unwrap(),
                schema_ref: trellis_server_ports::SchemaRef::new(
                    "https://formspec.org/schemas/trellis/authority-events.schema.json#/$defs/decision",
                )
                .unwrap(),
                artifact_type: trellis_types::ArtifactType::Event,
                direct_submit: trellis_server_ports::DirectSubmitPolicy::ServiceOnly,
                max_scope_events: None,
            }));
        let router = router()
            .reserve_ledger("authority", adapter, ["trellis.authority.grant.v1"])
            .reserve_ledger(
                "authority-decisions",
                decision_adapter,
                ["trellis.authority.decision.v1"],
            );
        let key = "a".repeat(64);
        let auth_scope = format!("{key}.authority");
        let dec_scope = format!("{key}.authority-decisions");
        let legacy_scope = format!("{key}.authority-wos");

        assert!(router.uses_canonical_append_replay(auth_scope.as_bytes()));
        assert!(router.uses_canonical_append_replay(dec_scope.as_bytes()));
        assert!(!router.uses_canonical_append_replay(legacy_scope.as_bytes()));
        assert!(!router.uses_canonical_append_replay(b"authority"));
        assert!(router.is_contract_event("trellis.authority.grant.v1"));
        assert!(router.is_contract_event("trellis.authority.decision.v1"));
        assert!(!router.is_contract_event("x-test.overlay.synthetic"));

        assert!(
            router
                .admit(&AdmissionEvent {
                    scope: auth_scope.as_bytes(),
                    event_type: "trellis.authority.grant.v1",
                    payload: br#"{"contract":"genesis"}"#,
                })
                .await
                .is_ok()
        );
        assert!(
            router
                .admit(&AdmissionEvent {
                    scope: dec_scope.as_bytes(),
                    event_type: "trellis.authority.decision.v1",
                    payload: br#"{"contract":"wos"}"#,
                })
                .await
                .is_ok()
        );
        assert!(
            router
                .check_ledger_event(auth_scope.as_bytes(), "trellis.authority.decision.v1")
                .is_err()
        );
        assert!(
            router
                .check_ledger_event(auth_scope.as_bytes(), "x-test.overlay.synthetic")
                .is_err()
        );
        assert!(
            router
                .check_ledger_event(legacy_scope.as_bytes(), "trellis.authority.grant.v1")
                .is_err()
        );
    }
}
