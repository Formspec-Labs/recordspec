use std::collections::HashSet;

use trellis_store_postgres_shared::migrations::MIGRATIONS;

#[test]
fn versions_strictly_ascending() {
    let mut previous = 0;
    for migration in MIGRATIONS {
        assert!(migration.version > previous);
        previous = migration.version;
    }
}

#[test]
fn names_unique() {
    let mut names = HashSet::new();
    for migration in MIGRATIONS {
        assert!(
            names.insert(migration.name),
            "duplicate: {}",
            migration.name
        );
    }
}

#[test]
fn snapshot_names() {
    let names: Vec<_> = MIGRATIONS.iter().map(|migration| migration.name).collect();

    assert_eq!(
        names,
        vec!["initial_events", "idempotency_key", "canonical_event_hash"]
    );
}
