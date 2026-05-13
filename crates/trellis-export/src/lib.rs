// Rust guideline compliant 2026-02-21
//! Deterministic ZIP export support for Trellis Phase 1.

#![forbid(unsafe_code)]

use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};

use crc32fast::Hasher;

const ZIP_VERSION_NEEDED: u16 = 20;
const ZIP_VERSION_MADE_BY: u16 = 20;
const ZIP_GENERAL_PURPOSE_BITS: u16 = 0;
const ZIP_COMPRESSION_STORED: u16 = 0;
const ZIP_FIXED_TIME: u16 = 0;
const ZIP_FIXED_DATE: u16 = (1 << 5) | 1;
const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;

/// Archive member that carries the optional witness-key history registry.
pub const WITNESS_KEY_REGISTRY_MEMBER: &str = "031-witness-key-registry.cbor";

/// One file entry in a logical export package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportEntry {
    path: String,
    bytes: Vec<u8>,
}

impl ExportEntry {
    /// Creates a logical export entry.
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes,
        }
    }

    /// Returns the archive path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Error returned when deterministic ZIP serialization fails.
#[derive(Debug)]
pub struct ExportError {
    message: String,
    backtrace: Backtrace,
}

impl ExportError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the captured backtrace for this export failure.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl Display for ExportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ExportError {}

/// Logical export package with deterministic ZIP serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportPackage {
    entries: Vec<ExportEntry>,
}

impl ExportPackage {
    /// Creates an empty export package.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry to the logical package.
    pub fn add_entry(&mut self, entry: ExportEntry) {
        self.entries.push(entry);
    }

    /// Adds the optional witness-key registry member under the export root.
    pub fn add_witness_key_registry(&mut self, root_dir: &str, bytes: Vec<u8>) {
        self.add_entry(ExportEntry::new(
            format!("{root_dir}/{WITNESS_KEY_REGISTRY_MEMBER}"),
            bytes,
        ));
    }

    /// Returns the logical entries.
    pub fn entries(&self) -> &[ExportEntry] {
        &self.entries
    }

    /// Serializes the logical package to deterministic ZIP bytes.
    ///
    /// Entries are emitted in lexicographic path order with stored compression,
    /// fixed DOS timestamps, zero extra fields, and zero external attributes so
    /// identical logical packages yield byte-identical archives across runs.
    ///
    /// # Errors
    /// Returns an error when duplicate or non-ASCII paths are present, or when
    /// the archive exceeds classic ZIP field bounds.
    pub fn to_zip_bytes(&self) -> Result<Vec<u8>, ExportError> {
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        for pair in entries.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(ExportError::new(format!(
                    "duplicate export path `{}`",
                    pair[0].path
                )));
            }
        }

        let mut local_sections = Vec::new();
        let mut central_sections = Vec::new();
        let mut offset = 0usize;

        for entry in &entries {
            if !entry.path.is_ascii() {
                return Err(ExportError::new(format!(
                    "export path `{}` is not ASCII",
                    entry.path
                )));
            }

            let path_bytes = entry.path.as_bytes();
            let crc32 = crc32(entry.bytes());
            let compressed_size = u32::try_from(entry.bytes.len()).map_err(|_| {
                ExportError::new(format!("entry `{}` exceeds ZIP32 size bounds", entry.path))
            })?;
            let path_len = u16::try_from(path_bytes.len()).map_err(|_| {
                ExportError::new(format!(
                    "entry path `{}` exceeds ZIP32 name bounds",
                    entry.path
                ))
            })?;
            let local_offset = u32::try_from(offset)
                .map_err(|_| ExportError::new("archive offset exceeds ZIP32 bounds"))?;

            let mut local = Vec::new();
            push_u32_le(&mut local, ZIP_LOCAL_FILE_HEADER_SIGNATURE);
            push_u16_le(&mut local, ZIP_VERSION_NEEDED);
            push_u16_le(&mut local, ZIP_GENERAL_PURPOSE_BITS);
            push_u16_le(&mut local, ZIP_COMPRESSION_STORED);
            push_u16_le(&mut local, ZIP_FIXED_TIME);
            push_u16_le(&mut local, ZIP_FIXED_DATE);
            push_u32_le(&mut local, crc32);
            push_u32_le(&mut local, compressed_size);
            push_u32_le(&mut local, compressed_size);
            push_u16_le(&mut local, path_len);
            push_u16_le(&mut local, 0);
            local.extend_from_slice(path_bytes);
            local.extend_from_slice(&entry.bytes);

            let mut central = Vec::new();
            push_u32_le(&mut central, ZIP_CENTRAL_DIRECTORY_SIGNATURE);
            push_u16_le(&mut central, ZIP_VERSION_MADE_BY);
            push_u16_le(&mut central, ZIP_VERSION_NEEDED);
            push_u16_le(&mut central, ZIP_GENERAL_PURPOSE_BITS);
            push_u16_le(&mut central, ZIP_COMPRESSION_STORED);
            push_u16_le(&mut central, ZIP_FIXED_TIME);
            push_u16_le(&mut central, ZIP_FIXED_DATE);
            push_u32_le(&mut central, crc32);
            push_u32_le(&mut central, compressed_size);
            push_u32_le(&mut central, compressed_size);
            push_u16_le(&mut central, path_len);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u16_le(&mut central, 0);
            push_u32_le(&mut central, 0);
            push_u32_le(&mut central, local_offset);
            central.extend_from_slice(path_bytes);

            offset += local.len();
            local_sections.push(local);
            central_sections.push(central);
        }

        let central_directory_offset = offset;
        let central_directory_size = central_sections.iter().map(Vec::len).sum::<usize>();
        let entry_count = u16::try_from(entries.len())
            .map_err(|_| ExportError::new("archive exceeds ZIP32 entry-count bounds"))?;

        let mut archive = Vec::with_capacity(
            local_sections.iter().map(Vec::len).sum::<usize>() + central_directory_size + 22,
        );
        for section in local_sections {
            archive.extend_from_slice(&section);
        }
        for section in central_sections {
            archive.extend_from_slice(&section);
        }

        push_u32_le(&mut archive, ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE);
        push_u16_le(&mut archive, 0);
        push_u16_le(&mut archive, 0);
        push_u16_le(&mut archive, entry_count);
        push_u16_le(&mut archive, entry_count);
        push_u32_le(
            &mut archive,
            u32::try_from(central_directory_size)
                .map_err(|_| ExportError::new("central directory exceeds ZIP32 bounds"))?,
        );
        push_u32_le(
            &mut archive,
            u32::try_from(central_directory_offset)
                .map_err(|_| ExportError::new("central directory offset exceeds ZIP32 bounds"))?,
        );
        push_u16_le(&mut archive, 0);

        Ok(archive)
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn push_u16_le(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{ExportEntry, ExportPackage};

    #[test]
    fn deterministic_zip_bytes_are_reproducible() {
        let mut package = ExportPackage::new();
        package.add_entry(ExportEntry::new("020-head.cbor", vec![0x02, 0x03]));
        package.add_entry(ExportEntry::new("010-event.cbor", vec![0x00, 0x01]));

        let first = package.to_zip_bytes().unwrap();
        let second = package.to_zip_bytes().unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn witness_key_registry_member_sorts_after_signing_registry() {
        let mut package = ExportPackage::new();
        package.add_entry(ExportEntry::new(
            "root/030-signing-key-registry.cbor",
            vec![0x30],
        ));
        package.add_witness_key_registry("root", vec![0x31]);

        let mut paths: Vec<&str> = package.entries().iter().map(ExportEntry::path).collect();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                "root/030-signing-key-registry.cbor",
                "root/031-witness-key-registry.cbor"
            ]
        );
    }

    #[test]
    fn export_001_fixture_matches_byte_for_byte() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/export/001-two-event-chain");
        let ledger_state: ciborium::Value = ciborium::from_reader(
            fs::read(root.join("input-ledger-state.cbor"))
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let state_map = ledger_state.as_map().unwrap();
        let root_dir = state_map
            .iter()
            .find(|(key, _)| key.as_text().is_some_and(|text| text == "root_dir"))
            .and_then(|(_, value)| value.as_text())
            .unwrap();
        let members = state_map
            .iter()
            .find(|(key, _)| key.as_text().is_some_and(|text| text == "members"))
            .and_then(|(_, value)| value.as_array())
            .unwrap();

        let mut package = ExportPackage::new();
        for member in members {
            let member_name = member.as_text().unwrap();
            package.add_entry(ExportEntry::new(
                format!("{root_dir}/{member_name}"),
                fs::read(root.join(member_name)).unwrap(),
            ));
        }

        let actual = package.to_zip_bytes().unwrap();
        let expected = fs::read(root.join("expected-export.zip")).unwrap();
        assert_eq!(actual, expected);
    }
}
