use trellis_store_postgres_shared::collision::{CollisionDecision, resolve_collision};

#[test]
fn identical_is_replay() {
    assert!(matches!(
        resolve_collision(b"a", b"a"),
        CollisionDecision::Replay(_)
    ));
}

#[test]
fn different_is_conflict() {
    assert!(matches!(
        resolve_collision(b"a", b"b"),
        CollisionDecision::Conflict { .. }
    ));
}

#[test]
fn empty_inputs_replay() {
    assert!(matches!(
        resolve_collision(b"", b""),
        CollisionDecision::Replay(_)
    ));
}

#[test]
fn one_empty_one_not_conflict() {
    assert!(matches!(
        resolve_collision(b"", b"a"),
        CollisionDecision::Conflict { .. }
    ));
}
