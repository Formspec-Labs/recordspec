//! Test support: writes a service-assembled export as a committed `export/` vector's files.

use integrity_cbor::Value;

/// Writes the members of `zip` under `directory` plus `input-ledger-state.cbor`, the layout the
/// conformance corpus replays byte for byte. `directory` must not exist yet.
pub(crate) fn write_export_vector(directory: &std::path::Path, zip: &[u8]) {
    assert!(directory.is_absolute());
    std::fs::create_dir_all(directory).unwrap();
    let entries = integrity_bundle::read_stored_zip(zip).unwrap();
    let root = entries
        .iter()
        .find_map(|entry| entry.path().strip_suffix("/010-events.cbor"))
        .unwrap();
    let prefix = format!("{root}/");
    let mut members = Vec::new();
    for entry in &entries {
        let member = entry.path().strip_prefix(&prefix).unwrap();
        let path = directory.join(member);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, entry.bytes()).unwrap();
        members.push(Value::Text(member.into()));
    }
    let ledger = crate::text_map(vec![
        ("root_dir", Value::Text(root.into())),
        ("members", Value::Array(members)),
    ])
    .unwrap();
    std::fs::write(
        directory.join("input-ledger-state.cbor"),
        integrity_cbor::encode_cbor_value(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(directory.join("expected-export.zip"), zip).unwrap();
}
