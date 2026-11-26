// Rust guideline compliant 2026-02-21
//! Shared [`AuthorityLedger`] adapter over [`TrellisServiceClient`].
//!
//! Implements [`stack_common_authz::ports::AuthorityLedger`] against the two shared
//! RecordsSpec ledgers per admitted scope (ADR 0176 Q5; `CONSISTENCY-AND-EFFECTS.md` §1–§2;
//! `AUTHORIZATION-CONTRACT.md` §4.5, §7, §8; Operational Companion §25):
//!
//! - `<scope key hex>.authority` ([`Ledger::Authority`]) for grants, revocations and activations.
//! - `<scope key hex>.authority-decisions` ([`Ledger::Decisions`]) for canonical decision records.
//!
//! Ledger scopes are constructed exclusively from the admitted [`Scope`] and [`Ledger`] enum,
//! never from raw caller strings or per-contract suffixes. Composition roots construct
//! [`TrellisAuthorityLedger`] under the `composition-root` Cargo feature (ADR 0168 §1.2).
//!
//! # Outer actor vs. payload actor
//!
//! Every append sends the calling server's configured service actor as the outer HTTP
//! [`AppendActor::service`] and [`ComputeContext::no_delegated_compute`] (required for Trellis
//! caller-grant attribution on the shared ledgers). The payload is transmitted unchanged and
//! retains the acting principal (or deterministic canonical genesis actor for `"genesis"` grants).
//!
//! # Deadlines, pagination and retries
//!
//! - The adapter performs **no internal retries** and maintains no cache or second HTTP client.
//! - Every call inherits the wrapped [`TrellisServiceClient`]'s timeout and the caller's async
//!   cancellation / deadline wrapper (`tokio::time::timeout_at`).
//! - [`AuthorityLedger::read_after`] loops across pages requesting at most
//!   [`MAX_ORDERED_EVENTS`] (`32`) events per RPC call, verifying starting tree head
//!   hashes, sequence contiguity, event hash chaining and checkpoint scope on every page.
//!
//! # Error mapping
//!
//! Closed RecordsSpec problem codes (`INFRA-4000`, `INFRA-4010`, `INFRA-4030`, `INFRA-4040`,
//! `INFRA-4090`, `INFRA-4094`, `INFRA-4130`, `INFRA-4150`, `INFRA-4220`, `INFRA-5000`,
//! `INFRA-5030`) are preserved without exposing raw provider response text:
//!
//! | Condition | `head` / `read_after` | `reconcile` | `append` |
//! |---|---|---|---|
//! | Local invalid key (`0` or `> 64` bytes, whitespace/control) or unencodable payload | `Rejected` | `Err(Rejected)` | `Err(Rejected)` |
//! | HTTP `409` with `INFRA-4094` (expected tree size moved) | `Rejected` | `Err(Rejected)` | `Err(HeadMoved)` |
//! | HTTP `409` with `INFRA-4090` (idempotency key content/type conflict) | `Rejected` | `Err(Rejected)` | `Err(KeyConflict)` |
//! | HTTP `401` / `403` (unauthenticated or missing RecordsSpec grant) | `Rejected` | `Err(Rejected)` | `Err(Rejected)` |
//! | HTTP `404` (foreign / unadmitted scope) | `Rejected` (`read_after` disambiguates absent nonzero prefix -> `HeadMoved`) | `Err(Rejected)` | `Err(Rejected)` |
//! | HTTP `400` / `413` / `415` / `422` / other `4xx` admission refusal | `Rejected` | `Err(Rejected)` | `Err(Rejected)` |
//! | Unreachable, timeout, `408`, `429`, `5xx`, or malformed response | `Unavailable` | `Ok(Reconcile::Unknown)` | `Err(OutcomeUnknown)` |

#![forbid(unsafe_code)]

use async_trait::async_trait;
use http::StatusCode;
use serde_json::Value;
use stack_common_authz::ports::{
    AuthorityLedger, Head, Ledger, LedgerEntry, LedgerFailure, OrderedRead, Reconcile,
};
use stack_common_error::StackError;
use stack_common_scope::Scope;
use trellis_service_client::endpoints::{MAX_ORDERED_EVENTS, OrderedEvent, OrderedEventsPage};
use trellis_service_client::{
    AUTHORITY_HEAD_MOVED_CODE, AppendActor, AppendReconciliation, AppendReconciliationRequest,
    ComputeContext, LedgerScope, SubstrateAppendBody, SubstrateAppendRequest,
    SubstrateAppendResult, SubstrateClient, TrellisServiceClient, canonical_append_content,
    public_code,
};

#[cfg(any(feature = "composition-root", test))]
const MAX_SERVICE_ACTOR_BYTES: usize = 256;
const MAX_PAGE_SIZE: usize = MAX_ORDERED_EVENTS as usize;

/// Shared [`AuthorityLedger`] adapter over [`TrellisServiceClient`].
///
/// Cloneable and cheap to share across tasks; wraps one [`TrellisServiceClient`] without
/// opening a second client, deriving keys, caching, or retrying internally.
#[derive(Clone, Debug)]
pub struct TrellisAuthorityLedger {
    client: TrellisServiceClient,
    service_actor: String,
}

impl TrellisAuthorityLedger {
    /// Constructs the shared authority-ledger adapter over an existing [`TrellisServiceClient`].
    ///
    /// `service_actor` is sent as the outer HTTP [`AppendActor::service`] subject and
    /// [`ComputeContext::no_delegated_compute`] actor (for example `"wos-server"` or
    /// `"formspec-server"`).
    ///
    /// # Errors
    /// Returns [`LedgerFailure::Rejected`] when `service_actor` is empty, exceeds 256 bytes,
    /// or contains whitespace or control characters.
    #[cfg(any(feature = "composition-root", test))]
    pub fn new(
        client: TrellisServiceClient,
        service_actor: impl Into<String>,
    ) -> Result<Self, LedgerFailure> {
        let service_actor = service_actor.into();
        validate_service_actor(&service_actor)?;
        Ok(Self {
            client,
            service_actor,
        })
    }

    /// Returns the outer HTTP service actor subject configured for this adapter.
    #[must_use]
    pub fn service_actor(&self) -> &str {
        &self.service_actor
    }

    /// Resolves the shared Trellis [`LedgerScope`] for `scope` and `ledger`
    /// (`<scope key hex>.authority` or `<scope key hex>.authority-decisions`).
    #[must_use]
    pub fn ledger_scope(scope: &Scope, ledger: Ledger) -> LedgerScope {
        LedgerScope::of(scope, ledger.id())
            .expect("shared authority ledger id satisfies RecordsSpec grammar")
    }

    fn build_append_request(
        &self,
        ledger_scope: LedgerScope,
        key: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<SubstrateAppendRequest, LedgerFailure> {
        validate_key(key)?;
        validate_event_type(event_type)?;
        SubstrateAppendRequest::new_json(
            ledger_scope,
            event_type,
            key,
            AppendActor::service(self.service_actor.clone()),
            payload.clone(),
            ComputeContext::no_delegated_compute(self.service_actor.clone()),
        )
        .map_err(|error| {
            LedgerFailure::Rejected(format!("invalid append request: {}", error.title()))
        })
    }

    /// Resolves the full [`Head`] (including `tree_head_hash`) for a committed receipt returned
    /// by `append` or `reconcile`.
    ///
    /// Queries `GET /events/ordered?after={tree_size}&limit=1` so the server returns
    /// `startTreeHeadHash` from the checkpoint at `tree_size` without reading or decoding the
    /// committed event's own payload (which may be a large activation or an OC-124 erased entry).
    async fn resolve_receipt_head(
        &self,
        ledger_scope: &LedgerScope,
        receipt: SubstrateAppendResult,
    ) -> Result<Head, Result<StackError, &'static str>> {
        let tree_size = receipt
            .sequence
            .checked_add(1)
            .ok_or(Err("trellis receipt sequence overflow"))?;
        let checkpoint_digest = extract_checkpoint_digest(ledger_scope, &receipt.checkpoint_ref)
            .ok_or(Err("trellis receipt checkpoint reference invalid"))?;
        if !is_sha256_digest(&receipt.canonical_event_hash) {
            return Err(Err("trellis receipt canonical event hash invalid"));
        }

        let page = self
            .client
            .events_after(ledger_scope, tree_size, 1)
            .await
            .map_err(Ok)?;
        if !is_sha256_digest(&page.start_tree_head_hash) {
            return Err(Err("trellis ordered page starting tree head hash invalid"));
        }
        if let Some(next) = page.events.first()
            && (next.sequence != tree_size
                || next.prior_event_hash.as_deref() != Some(receipt.canonical_event_hash.as_str()))
        {
            return Err(Err(
                "trellis successor event disagrees with committed receipt",
            ));
        }

        Ok(Head {
            tree_size,
            tree_head_hash: page.start_tree_head_hash,
            checkpoint_ref: Some(checkpoint_digest),
            last_event_hash: Some(receipt.canonical_event_hash),
        })
    }

    /// Fetches one bounded ordered page (`1 <= page_limit <= 32`) and disambiguates HTTP `404`
    /// between an absent nonzero prefix (`HeadMoved`) and a foreign/unadmitted scope (`Rejected`).
    async fn fetch_ordered_page(
        &self,
        ledger_scope: &LedgerScope,
        after: u64,
        page_limit: u32,
        required_tree_size: u64,
    ) -> Result<OrderedEventsPage, LedgerFailure> {
        debug_assert!((1..=MAX_ORDERED_EVENTS).contains(&page_limit));
        match self
            .client
            .events_after(ledger_scope, after, page_limit)
            .await
        {
            Ok(page) => Ok(page),
            Err(error) if error.status() == StatusCode::NOT_FOUND && required_tree_size > 0 => {
                // `GET /head` returns 200 (even on an empty ledger) for any admitted scope and
                // 404 only for a foreign or unadmitted scope.
                match self.client.ledger_head(ledger_scope).await {
                    Ok(None) => Err(LedgerFailure::HeadMoved),
                    Ok(Some(head)) if head.tree_size < required_tree_size => {
                        Err(LedgerFailure::HeadMoved)
                    }
                    Ok(Some(_)) => Err(LedgerFailure::Unavailable(
                        "ordered read prefix raced with ledger state".into(),
                    )),
                    Err(head_error) => Err(map_read_error(head_error)),
                }
            }
            Err(error) => Err(map_read_error(error)),
        }
    }
}

#[async_trait]
impl AuthorityLedger for TrellisAuthorityLedger {
    async fn head(&self, scope: &Scope, ledger: Ledger) -> Result<Head, LedgerFailure> {
        let ledger_scope = Self::ledger_scope(scope, ledger);
        let Some(head) = self
            .client
            .ledger_head(&ledger_scope)
            .await
            .map_err(map_read_error)?
        else {
            return Ok(Head::empty());
        };
        if head.tree_size == 0
            || !is_sha256_digest(&head.tree_head_hash)
            || !is_sha256_digest(&head.checkpoint_digest)
            || !is_sha256_digest(&head.last_event_hash)
        {
            return Err(LedgerFailure::Unavailable(
                "trellis ledger head response malformed".into(),
            ));
        }
        Ok(Head {
            tree_size: head.tree_size,
            tree_head_hash: head.tree_head_hash,
            checkpoint_ref: Some(head.checkpoint_digest),
            last_event_hash: Some(head.last_event_hash),
        })
    }

    async fn read_after(
        &self,
        scope: &Scope,
        ledger: Ledger,
        tree_size: u64,
        limit: usize,
    ) -> Result<OrderedRead, LedgerFailure> {
        let ledger_scope = Self::ledger_scope(scope, ledger);

        // Zero-limit prefix-only reads:
        if limit == 0 {
            if tree_size == 0 {
                // Constant-cost head probe checks auth, scope admission and reachability without
                // transferring any event payload.
                let _ = self
                    .client
                    .ledger_head(&ledger_scope)
                    .await
                    .map_err(map_read_error)?;
                return Ok(OrderedRead {
                    start: Head::empty(),
                    entries: Vec::new(),
                });
            }
            let anchor_sequence = tree_size - 1;
            let page = self
                .fetch_ordered_page(&ledger_scope, anchor_sequence, 1, tree_size)
                .await?;
            let Some(anchor) = page.events.into_iter().next() else {
                return Err(LedgerFailure::HeadMoved);
            };
            let start = ordered_event_to_head(&ledger_scope, &anchor, anchor_sequence)?;
            return Ok(OrderedRead {
                start,
                entries: Vec::new(),
            });
        }

        let mut entries = Vec::with_capacity(limit.min(MAX_PAGE_SIZE));
        let (start, mut cursor, mut reached_end) = if tree_size == 0 {
            let empty = Head::empty();
            (empty.clone(), empty, false)
        } else {
            // Fetch the anchor event at `tree_size - 1` (providing the complete starting Head)
            // together with up to 31 succeeding entries in one atomic RPC (`<= 32` total).
            let anchor_sequence = tree_size - 1;
            let first_entries = limit.min(MAX_PAGE_SIZE - 1);
            let rpc_limit = u32::try_from(first_entries + 1).expect("<= MAX_ORDERED_EVENTS");
            let page = self
                .fetch_ordered_page(&ledger_scope, anchor_sequence, rpc_limit, tree_size)
                .await?;
            let received = page.events.len();
            let mut iter = page.events.into_iter();
            let Some(anchor) = iter.next() else {
                return Err(LedgerFailure::HeadMoved);
            };
            let start = ordered_event_to_head(&ledger_scope, &anchor, anchor_sequence)?;
            let mut cursor = start.clone();
            for event in iter {
                let entry = ordered_event_to_entry(&ledger_scope, event, &cursor)?;
                cursor = entry.head.clone();
                entries.push(entry);
            }
            (start, cursor, received < rpc_limit as usize)
        };

        // Continue paging in chunks of at most `MAX_ORDERED_EVENTS` (32) until either `limit`
        // entries are collected or a short page confirms the current ledger head.
        while !reached_end && entries.len() < limit {
            let remaining = limit - entries.len();
            let page_limit =
                u32::try_from(remaining.min(MAX_PAGE_SIZE)).expect("<= MAX_ORDERED_EVENTS");
            let page = self
                .fetch_ordered_page(
                    &ledger_scope,
                    cursor.tree_size,
                    page_limit,
                    cursor.tree_size,
                )
                .await?;
            if page.start_tree_head_hash != cursor.tree_head_hash {
                return Err(LedgerFailure::Unavailable(
                    "trellis ordered read starting tree head hash diverged across pages".into(),
                ));
            }
            let received = page.events.len();
            for event in page.events {
                let entry = ordered_event_to_entry(&ledger_scope, event, &cursor)?;
                cursor = entry.head.clone();
                entries.push(entry);
            }
            if received < page_limit as usize {
                reached_end = true;
            }
        }

        Ok(OrderedRead { start, entries })
    }

    async fn reconcile(
        &self,
        scope: &Scope,
        ledger: Ledger,
        key: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<Reconcile, LedgerFailure> {
        validate_key(key)?;
        validate_event_type(event_type)?;
        let ledger_scope = Self::ledger_scope(scope, ledger);
        let content = canonical_append_content(payload).map_err(|_| {
            LedgerFailure::Rejected("payload cannot be encoded as canonical dCBOR".into())
        })?;
        let request = AppendReconciliationRequest {
            event_type: event_type.to_owned(),
            idempotency_key: key.to_owned(),
            content_hash: Some(content.content_hash),
            certificate_id: None,
        };
        request
            .validate()
            .map_err(|error| LedgerFailure::Rejected(error.title().to_owned()))?;

        match self.client.reconcile_event(&ledger_scope, &request).await {
            Ok(AppendReconciliation::Committed { receipt }) => {
                match self.resolve_receipt_head(&ledger_scope, receipt).await {
                    Ok(head) => Ok(Reconcile::Committed(head)),
                    Err(Ok(http_err)) => map_reconcile_error(http_err),
                    Err(Err(_)) => Ok(Reconcile::Unknown),
                }
            }
            Ok(AppendReconciliation::Conflict) => Ok(Reconcile::Conflict),
            Ok(AppendReconciliation::Absent { .. }) => Ok(Reconcile::Absent),
            Ok(AppendReconciliation::Unknown { .. }) => Ok(Reconcile::Unknown),
            Err(error) => map_reconcile_error(error),
        }
    }

    fn encoded_append_size(
        &self,
        scope: &Scope,
        ledger: Ledger,
        key: &str,
        event_type: &str,
        payload: &Value,
        expected_size: Option<u64>,
    ) -> Result<usize, LedgerFailure> {
        let ledger_scope = Self::ledger_scope(scope, ledger);
        let request = self.build_append_request(ledger_scope, key, event_type, payload)?;
        let body = SubstrateAppendBody {
            expected_tree_size: expected_size,
            ..request.body()
        };
        body.validate()
            .map_err(|error| LedgerFailure::Rejected(error.title().to_owned()))?;
        serde_json::to_vec(&body)
            .map(|bytes| bytes.len())
            .map_err(|error| LedgerFailure::Rejected(error.to_string()))
    }

    async fn append(
        &self,
        scope: &Scope,
        ledger: Ledger,
        key: &str,
        event_type: &str,
        payload: &Value,
        expected_size: Option<u64>,
    ) -> Result<Head, LedgerFailure> {
        let ledger_scope = Self::ledger_scope(scope, ledger);
        let request = self.build_append_request(ledger_scope.clone(), key, event_type, payload)?;
        let receipt = match expected_size {
            Some(expected) => self
                .client
                .append_event_if_tree_size(request, expected)
                .await
                .map_err(map_append_error)?,
            None => self
                .client
                .append_event(request)
                .await
                .map_err(map_append_error)?,
        };
        self.resolve_receipt_head(&ledger_scope, receipt)
            .await
            .map_err(|cause| match cause {
                Ok(error) => {
                    let code = extract_problem_code(&error);
                    LedgerFailure::OutcomeUnknown(format!(
                        "trellis append committed but head resolution failed (HTTP {}, code {code})",
                        error.status().as_u16()
                    ))
                }
                Err(reason) => LedgerFailure::OutcomeUnknown(reason.to_owned()),
            })
    }
}

#[cfg(any(feature = "composition-root", test))]
fn validate_service_actor(actor: &str) -> Result<(), LedgerFailure> {
    if actor.is_empty()
        || actor.len() > MAX_SERVICE_ACTOR_BYTES
        || actor
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(LedgerFailure::Rejected(
            "service actor must be a non-empty identifier without whitespace or control characters"
                .into(),
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), LedgerFailure> {
    if key.trim().is_empty()
        || !trellis_types::idempotency_key_length_in_bound(key.as_bytes())
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(LedgerFailure::Rejected(
            "idempotency key outside RecordsSpec byte bound".into(),
        ));
    }
    Ok(())
}

fn validate_event_type(event_type: &str) -> Result<(), LedgerFailure> {
    if event_type.trim().is_empty() {
        return Err(LedgerFailure::Rejected("event type is required".into()));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn extract_checkpoint_digest(ledger_scope: &LedgerScope, checkpoint_ref: &str) -> Option<String> {
    let prefix = format!("trellis://{ledger_scope}/checkpoints/");
    let digest = checkpoint_ref.strip_prefix(&prefix)?;
    is_sha256_digest(digest).then(|| digest.to_owned())
}

fn ordered_event_to_head(
    ledger_scope: &LedgerScope,
    event: &OrderedEvent,
    expected_sequence: u64,
) -> Result<Head, LedgerFailure> {
    if event.sequence != expected_sequence {
        return Err(LedgerFailure::Unavailable(
            "trellis ordered event sequence mismatch".into(),
        ));
    }
    let tree_size = event
        .sequence
        .checked_add(1)
        .ok_or_else(|| LedgerFailure::Unavailable("trellis sequence overflow".into()))?;
    if !is_sha256_digest(&event.tree_head_hash) || !is_sha256_digest(&event.canonical_event_hash) {
        return Err(LedgerFailure::Unavailable(
            "trellis ordered event hash malformed".into(),
        ));
    }
    let checkpoint_digest = extract_checkpoint_digest(ledger_scope, &event.checkpoint_ref)
        .ok_or_else(|| {
            LedgerFailure::Unavailable(
                "trellis ordered event checkpoint reference invalid or out of scope".into(),
            )
        })?;
    Ok(Head {
        tree_size,
        tree_head_hash: event.tree_head_hash.clone(),
        checkpoint_ref: Some(checkpoint_digest),
        last_event_hash: Some(event.canonical_event_hash.clone()),
    })
}

fn ordered_event_to_entry(
    ledger_scope: &LedgerScope,
    event: OrderedEvent,
    prior: &Head,
) -> Result<LedgerEntry, LedgerFailure> {
    if event.prior_event_hash != prior.last_event_hash {
        return Err(LedgerFailure::Unavailable(
            "trellis ordered event hash chain break".into(),
        ));
    }
    let head = ordered_event_to_head(ledger_scope, &event, prior.tree_size)?;
    Ok(LedgerEntry {
        head,
        prior_event_hash: event.prior_event_hash,
        event_type: event.event_type,
        payload: event.payload,
    })
}

fn extract_problem_code(error: &StackError) -> &'static str {
    if error.code().as_str() == AUTHORITY_HEAD_MOVED_CODE {
        return AUTHORITY_HEAD_MOVED_CODE;
    }
    if let Some((_, json_part)) = error.title().rsplit_once(": ") {
        let trimmed = json_part.trim();
        if trimmed.starts_with('{') {
            return public_code(trimmed);
        }
    }
    match error.code().as_str() {
        "INFRA-4000" => "INFRA-4000",
        "INFRA-4010" => "INFRA-4010",
        "INFRA-4030" => "INFRA-4030",
        "INFRA-4040" => "INFRA-4040",
        "INFRA-4090" => "INFRA-4090",
        "INFRA-4130" => "INFRA-4130",
        "INFRA-4150" => "INFRA-4150",
        "INFRA-4220" => "INFRA-4220",
        "INFRA-5000" => "INFRA-5000",
        "INFRA-5030" => "INFRA-5030",
        _ => "other",
    }
}

fn rejected_for_status(status: StatusCode, code: &str) -> LedgerFailure {
    match status {
        StatusCode::UNAUTHORIZED => LedgerFailure::Rejected(format!(
            "unauthorized: service authentication rejected (HTTP 401, code {code})"
        )),
        StatusCode::FORBIDDEN => LedgerFailure::Rejected(format!(
            "unauthorized: missing RecordsSpec grant (HTTP 403, code {code})"
        )),
        StatusCode::NOT_FOUND => LedgerFailure::Rejected(format!(
            "foreign or unadmitted scope (HTTP 404, code {code})"
        )),
        _ => LedgerFailure::Rejected(format!(
            "admission refused (HTTP {}, code {code})",
            status.as_u16()
        )),
    }
}

fn is_transient_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn map_read_error(error: StackError) -> LedgerFailure {
    let status = error.status();
    let code = extract_problem_code(&error);
    if is_transient_status(status) {
        return LedgerFailure::Unavailable(format!(
            "trellis read unavailable (HTTP {}, code {code})",
            status.as_u16()
        ));
    }
    if status.is_client_error() {
        return rejected_for_status(status, code);
    }
    LedgerFailure::Unavailable(format!(
        "trellis read failed (HTTP {}, code {code})",
        status.as_u16()
    ))
}

fn map_append_error(error: StackError) -> LedgerFailure {
    let status = error.status();
    let code = extract_problem_code(&error);
    if status == StatusCode::CONFLICT {
        if error.code().as_str() == AUTHORITY_HEAD_MOVED_CODE {
            return LedgerFailure::HeadMoved;
        }
        if code == "INFRA-4090" {
            return LedgerFailure::KeyConflict;
        }
        return rejected_for_status(status, code);
    }
    if is_transient_status(status) {
        return LedgerFailure::OutcomeUnknown(format!(
            "trellis append outcome unknown (HTTP {}, code {code})",
            status.as_u16()
        ));
    }
    if status.is_client_error() {
        return rejected_for_status(status, code);
    }
    LedgerFailure::OutcomeUnknown(format!(
        "trellis append outcome unknown (HTTP {}, code {code})",
        status.as_u16()
    ))
}

fn map_reconcile_error(error: StackError) -> Result<Reconcile, LedgerFailure> {
    let status = error.status();
    let code = extract_problem_code(&error);
    if is_transient_status(status) {
        return Ok(Reconcile::Unknown);
    }
    if status.is_client_error() {
        return Err(rejected_for_status(status, code));
    }
    Ok(Reconcile::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scope() -> Scope {
        Scope::fixture("acme", "benefits", Some("prod"))
    }

    #[test]
    fn shared_ledger_scopes_use_fixed_q5_ids_never_contract_suffixes() {
        let scope = test_scope();
        let auth = TrellisAuthorityLedger::ledger_scope(&scope, Ledger::Authority);
        let dec = TrellisAuthorityLedger::ledger_scope(&scope, Ledger::Decisions);
        assert_eq!(auth.as_str(), format!("{}.authority", scope.key()));
        assert_eq!(auth.ledger_id(), "authority");
        assert_eq!(dec.as_str(), format!("{}.authority-decisions", scope.key()));
        assert_eq!(dec.ledger_id(), "authority-decisions");
    }

    #[test]
    fn checkpoint_digest_extraction_enforces_exact_scope_and_sha256_format() {
        let scope = test_scope();
        let other = Scope::fixture("globex", "benefits", Some("prod"));
        let ledger_scope = TrellisAuthorityLedger::ledger_scope(&scope, Ledger::Authority);
        let other_scope = TrellisAuthorityLedger::ledger_scope(&other, Ledger::Authority);
        let valid_digest = format!("sha256:{}", "a".repeat(64));

        assert_eq!(
            extract_checkpoint_digest(
                &ledger_scope,
                &format!("trellis://{ledger_scope}/checkpoints/{valid_digest}")
            ),
            Some(valid_digest.clone())
        );
        // Foreign scope checkpoint refused.
        assert_eq!(
            extract_checkpoint_digest(
                &ledger_scope,
                &format!("trellis://{other_scope}/checkpoints/{valid_digest}")
            ),
            None
        );
        // Uppercase or truncated digest refused.
        assert_eq!(
            extract_checkpoint_digest(
                &ledger_scope,
                &format!(
                    "trellis://{ledger_scope}/checkpoints/sha256:{}",
                    "A".repeat(64)
                )
            ),
            None
        );
        assert_eq!(
            extract_checkpoint_digest(
                &ledger_scope,
                &format!("trellis://{ledger_scope}/checkpoints/sha256:abc")
            ),
            None
        );
    }

    #[test]
    fn key_validation_enforces_bounds_and_rejects_control_characters() {
        assert!(validate_key("k").is_ok());
        assert!(validate_key(&"a".repeat(64)).is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("   ").is_err());
        assert!(validate_key(&"a".repeat(65)).is_err());
        assert!(validate_key("key\r\ninjected").is_err());
        assert!(validate_key("key\0null").is_err());
    }

    #[test]
    fn append_error_mapping_maps_only_infra_4094_to_head_moved() {
        let moved = StackError::conflict_with_code(
            AUTHORITY_HEAD_MOVED_CODE,
            "authority ledger tree size changed",
        );
        assert_eq!(map_append_error(moved), LedgerFailure::HeadMoved);

        let key_conflict = StackError::new(
            stack_common_error::ErrorCode::new("INFRA-4090").unwrap(),
            StatusCode::CONFLICT,
            r#"trellis append returned HTTP 409 Conflict: {"error_code":"INFRA-4090"}"#,
        );
        assert_eq!(map_append_error(key_conflict), LedgerFailure::KeyConflict);

        let unknown_conflict = StackError::new(
            stack_common_error::ErrorCode::new("INFRA-4090").unwrap(),
            StatusCode::CONFLICT,
            r#"trellis append returned HTTP 409 Conflict: {"error_code":"other"}"#,
        );
        assert!(matches!(
            map_append_error(unknown_conflict),
            LedgerFailure::Rejected(msg) if msg.contains("HTTP 409") && msg.contains("other")
        ));

        let payload_too_large = StackError::new(
            stack_common_error::ErrorCode::new("INFRA-4130").unwrap(),
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"trellis append returned HTTP 413 Payload Too Large: {"error_code":"INFRA-4130"}"#,
        );
        assert!(matches!(
            map_append_error(payload_too_large),
            LedgerFailure::Rejected(msg) if msg.contains("INFRA-4130")
        ));

        let unavailable = StackError::unavailable("transport failed");
        assert!(matches!(
            map_append_error(unavailable),
            LedgerFailure::OutcomeUnknown(_)
        ));
    }

    #[test]
    fn reconcile_error_mapping_maps_transient_to_unknown_and_auth_to_rejected() {
        assert_eq!(
            map_reconcile_error(StackError::unavailable("stopped")),
            Ok(Reconcile::Unknown)
        );
        assert_eq!(
            map_reconcile_error(StackError::internal("db failure")),
            Ok(Reconcile::Unknown)
        );
        let forbidden = StackError::new(
            stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
            StatusCode::FORBIDDEN,
            r#"trellis reconcile returned HTTP 403 Forbidden: {"error_code":"INFRA-4030"}"#,
        );
        assert!(matches!(
            map_reconcile_error(forbidden),
            Err(LedgerFailure::Rejected(msg)) if msg.contains("INFRA-4030")
        ));
    }
}
