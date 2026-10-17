//! Signing-key history: the public rows that let exports verify ledgers written
//! under keys that have since rotated (Core §8.4 retired rows stay, §8.5 completeness).

use serde::Deserialize;
use stack_common_error::StackError;
use trellis_export_writer::{SigningKeyRegistryEntry, SigningKeyStatus, TrellisTimestamp};

use crate::ServerSigningKey;

/// One public key of the history file. No private material is ever read from it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRow {
    /// Hex Ed25519 public key.
    public_key: String,
    valid_from_unix_secs: u64,
    /// Required on every row except the last (the current key).
    valid_to_unix_secs: Option<u64>,
}

impl ServerSigningKey {
    /// Applies a signing-key history file: a JSON array of public keys, oldest first,
    /// ending at this key. Earlier rows become `Retired`; each key supersedes the one
    /// before it.
    ///
    /// # Errors
    /// Refuses an empty history, one whose last key is not this key, or rows that are
    /// malformed, repeated, or retired without a `valid_to`.
    pub fn with_history_json(mut self, json: &[u8]) -> Result<Self, StackError> {
        let rows: Vec<HistoryRow> = serde_json::from_slice(json).map_err(|error| {
            StackError::bad_request(format!("invalid signing-key history: {error}"))
        })?;
        let Some((last, retired)) = rows.split_last() else {
            return Err(StackError::bad_request("signing-key history is empty"));
        };
        let current = self.export_key.public_key;
        if decode_public_key(&last.public_key)? != current {
            return Err(StackError::bad_request(
                "signing-key history must end at the configured signing key",
            ));
        }
        let mut history: Vec<SigningKeyRegistryEntry> = Vec::with_capacity(retired.len());
        for row in retired {
            let public_key = decode_public_key(&row.public_key)?;
            let valid_to = row.valid_to_unix_secs.ok_or_else(|| {
                StackError::bad_request(
                    "a retired signing key in the history needs valid_to_unix_secs",
                )
            })?;
            let kid = trellis_export_writer::SigningKeyMaterial {
                private_seed: [0; 32],
                public_key,
                valid_from: TrellisTimestamp::new(0, 0)?,
                valid_to: None,
            }
            .kid();
            if public_key == current || history.iter().any(|entry| entry.kid == kid) {
                return Err(StackError::bad_request("signing-key history repeats a key"));
            }
            history.push(SigningKeyRegistryEntry {
                kid,
                public_key,
                status: SigningKeyStatus::Retired,
                valid_from: TrellisTimestamp::new(row.valid_from_unix_secs, 0)?,
                valid_to: Some(TrellisTimestamp::new(valid_to, 0)?),
                supersedes: history.last().map(|previous| previous.kid),
            });
        }
        self.export_key.valid_from = TrellisTimestamp::new(last.valid_from_unix_secs, 0)?;
        if let Some(valid_to) = last.valid_to_unix_secs {
            self = self.with_valid_to(Some(TrellisTimestamp::new(valid_to, 0)?));
        }
        self.history = history;
        Ok(self)
    }
}

fn decode_public_key(hex_key: &str) -> Result<[u8; 32], StackError> {
    hex::decode(hex_key)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            StackError::bad_request("signing-key history public_key must be 64 hex characters")
        })
}
