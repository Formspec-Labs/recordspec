// Rust guideline compliant 2026-02-21
//! The deployment's store and the scoped handle every Trellis request reaches data through.
//!
//! ADR 0168 §1.1. [`TrellisStore`] is the server's `Store`: the deployment's [`Ledgers`] and its
//! buckets, which the composition root opens and moves into `Deployment::new`. The deployment
//! hands each admitted request a [`TrellisScoped`], one scope's ledgers and objects; handlers
//! extract it with `Scoped<TrellisScoped>` and have no other way to rows or objects.

use std::sync::Arc;

use stack_common_object_store::{ScopedBucket, ScopedObjects};
use stack_common_scope::{Scope, ScopeBound, Store};
use trellis_server_ports::{Ledgers, ScopedLedgers};

/// The deployment's ledgers and buckets. Only the deployment holds it.
pub struct TrellisStore {
    ledgers: Arc<dyn Ledgers>,
    artifacts: ScopedBucket,
    source_content: Option<ScopedBucket>,
}

impl TrellisStore {
    /// The deployment's ledgers and the bucket Trellis keeps its own objects in (completion
    /// certificates, retained Source batches), both opened by the composition root.
    #[must_use]
    pub fn new(ledgers: Arc<dyn Ledgers>, artifacts: ScopedBucket) -> Self {
        Self {
            ledgers,
            artifacts,
            source_content: None,
        }
    }

    /// Adds the bucket WOS prepares Source batches in, which Trellis only reads.
    #[must_use]
    pub fn with_source_content(mut self, bucket: ScopedBucket) -> Self {
        self.source_content = Some(bucket);
        self
    }
}

impl Store for TrellisStore {
    type Scoped = TrellisScoped;

    fn scoped(&self, scope: &Scope) -> TrellisScoped {
        TrellisScoped {
            scope: scope.clone(),
            ledgers: self.ledgers.scoped(scope),
            artifacts: self.artifacts.scoped(scope),
            source_content: self
                .source_content
                .as_ref()
                .map(|bucket| bucket.scoped(scope)),
        }
    }
}

/// One scope's ledgers and objects: what an admitted request reaches data through.
#[derive(Clone)]
pub struct TrellisScoped {
    scope: Scope,
    ledgers: Arc<dyn ScopedLedgers>,
    artifacts: ScopedObjects,
    source_content: Option<ScopedObjects>,
}

impl TrellisScoped {
    /// The scope's ledgers.
    #[must_use]
    pub fn ledgers(&self) -> &dyn ScopedLedgers {
        self.ledgers.as_ref()
    }

    /// Trellis's own objects under the scope's key.
    #[must_use]
    pub const fn artifacts(&self) -> &ScopedObjects {
        &self.artifacts
    }

    /// The Source batches WOS prepared under the scope's key, when Source content is composed.
    #[must_use]
    pub const fn source_content(&self) -> Option<&ScopedObjects> {
        self.source_content.as_ref()
    }
}

impl ScopeBound for TrellisScoped {
    fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl std::fmt::Debug for TrellisScoped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrellisScoped")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
