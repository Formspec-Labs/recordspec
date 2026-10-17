// Rust guideline compliant 2026-02-21
//! Domain adapters the composition root injects into the generic server.
//!
//! This crate contains no producer-specific code: admission, event-type
//! vocabulary, attachment descriptors, export profile and tenant headers all
//! arrive through [`ServerAdapters`]. `trellis-server` assembles the
//! shipped set; `deny.toml` keeps the adapter crates out of this crate's graph.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::HeaderMap;
use stack_common_error::StackError;
use stack_common_http::tenant::{HeaderConfig, TenantScope, extract_tenant};
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
    pub admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
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
    /// Tenant header sets accepted on requests.
    pub tenant_headers: TenantHeaders,
}

/// Tenant header sets, tried in order; the first names the response/outbound set.
#[derive(Clone, Debug)]
pub struct TenantHeaders {
    primary: HeaderConfig,
    fallbacks: Vec<HeaderConfig>,
}

impl TenantHeaders {
    #[must_use]
    pub fn new(primary: HeaderConfig) -> Self {
        Self {
            primary,
            fallbacks: Vec::new(),
        }
    }

    /// Also accepts `fallback` when the earlier sets are incomplete.
    #[must_use]
    pub fn or_else(mut self, fallback: HeaderConfig) -> Self {
        self.fallbacks.push(fallback);
        self
    }

    pub(crate) fn primary(&self) -> HeaderConfig {
        self.primary
    }

    pub(crate) fn extract(&self, headers: &HeaderMap) -> Result<TenantScope, StackError> {
        let mut last = extract_tenant(&self.primary, headers);
        for fallback in &self.fallbacks {
            if last.is_ok() {
                break;
            }
            last = extract_tenant(fallback, headers);
        }
        last
    }
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

    /// Returns true when a literal is registered.
    #[must_use]
    pub fn handles(&self, event_type: &str) -> bool {
        self.by_literal.contains_key(event_type)
    }
}

#[async_trait]
impl EventAdmissionPolicy for AdmissionRouter {
    type Error = StackError;

    async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, Self::Error> {
        let Some(adapter) = self.by_literal.get(event.event_type) else {
            return Err(StackError::bad_request(format!(
                "event type `{}` is not registered for admission",
                event.event_type
            )));
        };
        adapter.admit(event).await
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

    fn insert(headers: &mut HeaderMap, prefix: &str, tenant: &str, workspace: bool) {
        headers.insert(
            format!("x-{prefix}-tenant-id")
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            tenant.parse().unwrap(),
        );
        if workspace {
            for part in ["workspace", "environment", "cell"] {
                headers.insert(
                    format!("x-{prefix}-{part}-id")
                        .parse::<axum::http::HeaderName>()
                        .unwrap(),
                    "v".parse().unwrap(),
                );
            }
        }
    }

    #[test]
    fn tenant_headers_try_each_set_in_order() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "formspec", "t", true);
        let wos_only = TenantHeaders::new(HeaderConfig::wos());
        assert!(wos_only.extract(&headers).is_err());
        let mixed = wos_only.or_else(HeaderConfig::formspec());
        assert_eq!(mixed.extract(&headers).unwrap().tenant, "t");
    }

    /// A partial first set never wins over a complete later set, so the replay tenant and
    /// the authorised tenant are the same one.
    #[test]
    fn partial_first_set_falls_through_to_the_complete_set() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "wos", "wos-only", false);
        insert(&mut headers, "formspec", "tenant-b", true);
        let mixed = TenantHeaders::new(HeaderConfig::wos()).or_else(HeaderConfig::formspec());
        assert_eq!(mixed.extract(&headers).unwrap().tenant, "tenant-b");
    }
}
