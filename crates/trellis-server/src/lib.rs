// Rust guideline compliant 2026-02-21
#![allow(clippy::result_large_err)]
//! Trellis server composition root.
//!
//! The only crate that names both the generic [`trellis_service_core`] and the shipped
//! domain adapters (`trellis-admission-wos`, `trellis-admission-formspec`,
//! `trellis-export-profile-wos`); `deny.toml` keeps every other crate from
//! depending on them. Consumers that embed a composed server in-process (tests,
//! fixtures) depend on this crate and see the generic server's API re-exported.
//!
//! It opens no store: `trellis-main`, the binary, opens the pool and buckets and builds the
//! deployment (ADR 0168 §1.2), and in-process consumers build theirs from [`test_harness`].

#![forbid(unsafe_code)]

pub mod composition;
mod source_content;
#[cfg(feature = "test-harness")]
pub mod test_harness;

pub use trellis_service_core::*;
