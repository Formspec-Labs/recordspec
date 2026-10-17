//! The fold against the whole-prefix judgement it replaces.

use integrity_cbor::{
    Value, domain_separated_sha256, encode_canonical_cbor_value, json_to_dcbor_bytes,
};
use proptest::prelude::*;
use serde_json::json;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_types::{CONTENT_DOMAIN, EVENT_DOMAIN, StoredEvent};

use super::*;
use crate::signature_evidence_members;

const SCOPE: &[u8] = b"fold-scope";

#[derive(Clone, Debug)]
enum Kind {
    /// An event that is not a signature affirmation, with `pad` extra payload bytes.
    Note { pad: usize },
    /// A well-formed affirmation of signing act `act` (same act, same original payload).
    Affirm { act: u8, pad: usize },
    /// An affirmation the catalog parser refuses (no signing act id).
    NoSigningAct,
    /// An affirmation whose `content_hash` is not the hash of its payload.
    WrongContentHash,
}

fn payload(kind: &Kind) -> (String, Vec<u8>) {
    let affirmation = wos_signature_affirmation_event_type();
    let data = |act: &str, pad: usize, with_act: bool| {
        let mut data = json!({
            "signerId": "person", "roleId": "selected-role", "role": "selected",
            "documentId": "original-document", "documentHash": "retained-document-digest",
            "documentHashAlgorithm": "selected-algorithm", "signedAt": "2026-10-10T00:00:00Z",
            "identityBinding": {"nested": [{"exact": true}, null, 3]},
            "consentReference": {"text": "x".repeat(pad)},
            "signatureProvider": "controlled-provider", "ceremonyId": act,
            "formspecResponseRef": "urn:controlled:response",
            "presentationHash": "retained-presentation-digest",
            "sourceSignatureId": null, "profileKey": "exact-profile",
        });
        if with_act {
            data["signingActId"] = json!(act);
        }
        data
    };
    let (event_type, value) = match kind {
        Kind::Note { pad } => (
            "wos.kernel.note_added".to_owned(),
            json!({"event": "wos.kernel.note_added", "data": {"pad": "x".repeat(*pad)}}),
        ),
        Kind::Affirm { act, pad } => (
            affirmation.to_owned(),
            json!({"event": affirmation, "data": data(&format!("act-{act}"), *pad, true)}),
        ),
        Kind::NoSigningAct => (
            affirmation.to_owned(),
            json!({"event": affirmation, "data": data("act-none", 0, false)}),
        ),
        Kind::WrongContentHash => (
            affirmation.to_owned(),
            json!({"event": affirmation, "data": data("act-wrong", 0, true)}),
        ),
    };
    (event_type, json_to_dcbor_bytes(&value, &[]).unwrap())
}

fn event(sequence: u64, kind: &Kind) -> StoredEvent {
    let (event_type, bytes) = payload(kind);
    let content = match kind {
        Kind::WrongContentHash => domain_separated_sha256(CONTENT_DOMAIN, b"another payload"),
        _ => domain_separated_sha256(CONTENT_DOMAIN, &bytes),
    };
    let text = |s: &str| Value::Text(s.into());
    let canonical = encode_canonical_cbor_value(&Value::Map(vec![
        (text("ledger_scope"), Value::Bytes(SCOPE.to_vec())),
        (text("sequence"), Value::Integer(sequence.into())),
        (
            text("header"),
            Value::Map(vec![
                (text("event_type"), Value::Bytes(event_type.into_bytes())),
                (
                    text("authored_at"),
                    Value::Array(vec![
                        Value::Integer((1_700_000_000 + sequence).into()),
                        Value::Integer(0.into()),
                    ]),
                ),
            ]),
        ),
        (text("content_hash"), Value::Bytes(content.to_vec())),
        (
            text("payload_ref"),
            Value::Map(vec![
                (text("ref_type"), text("inline")),
                (text("ciphertext"), Value::Bytes(bytes)),
            ]),
        ),
    ]))
    .unwrap();
    let hash = domain_separated_sha256(
        EVENT_DOMAIN,
        &canonical_event_hash_preimage(SCOPE, &canonical),
    );
    StoredEvent::new(SCOPE.to_vec(), sequence, canonical, vec![])
        .with_canonical_event_hash(Some(hash))
}

/// Folds `kinds` one event at a time and compares each step with the whole-prefix judgement.
/// Stops at the first refusal, as an append would.
fn assert_fold_agrees_with_the_whole_prefix(kinds: &[Kind]) -> Vec<bool> {
    let mut verdicts = Vec::new();
    let mut state: Option<Vec<u8>> = None;
    let mut prefix = Vec::new();
    for (index, kind) in kinds.iter().enumerate() {
        prefix.push(event(index as u64, kind));
        let refs = prefix.iter().collect::<Vec<_>>();
        let whole = signature_evidence_members(SCOPE, &refs);
        let folded = fold_append(SCOPE, state.as_deref(), &prefix[index], index as u64 + 1);
        assert_eq!(
            folded.is_ok(),
            whole.is_ok(),
            "event {index} ({kind:?}): fold {:?}, whole prefix {:?}",
            folded.as_ref().err().map(StackError::to_string),
            whole.as_ref().err().map(StackError::to_string),
        );
        verdicts.push(folded.is_ok());
        match folded {
            Ok(next) => state = Some(next),
            Err(_) => return verdicts,
        }
    }
    verdicts
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        6 => (prop_oneof![Just(0usize), Just(40), Just(60_000), Just(200_000)]).prop_map(|pad| Kind::Note { pad }),
        6 => (0u8..4, prop_oneof![Just(0usize), Just(10), Just(120_000), Just(350_000)])
            .prop_map(|(act, pad)| Kind::Affirm { act, pad }),
        1 => Just(Kind::NoSigningAct),
        1 => Just(Kind::WrongContentHash),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn the_fold_accepts_exactly_the_prefixes_the_whole_prefix_judgement_accepts(
        kinds in proptest::collection::vec(kind(), 1..14)
    ) {
        assert_fold_agrees_with_the_whole_prefix(&kinds);
    }
}

#[test]
fn a_ledger_of_notes_may_pass_the_event_limit_but_the_first_affirmation_past_it_is_refused() {
    let mut kinds = vec![Kind::Note { pad: 0 }; MAX_MEMBERS];
    kinds.push(Kind::Note { pad: 0 });
    kinds.push(Kind::Affirm { act: 1, pad: 0 });
    assert_fold_agrees_with_the_whole_prefix(&kinds);

    let mut state = None;
    for index in 0..kinds.len() - 1 {
        state = Some(
            fold_append(
                SCOPE,
                state.as_deref(),
                &event(index as u64, &kinds[index]),
                index as u64 + 1,
            )
            .expect("notes alone are never refused"),
        );
    }
    let refused = fold_append(
        SCOPE,
        state.as_deref(),
        &event(kinds.len() as u64 - 1, &kinds[kinds.len() - 1]),
        kinds.len() as u64,
    );
    assert!(
        refused.is_err(),
        "257 events with an affirmation exceed the member bound"
    );
}

#[test]
fn the_last_affirmation_that_fits_the_event_limit_is_accepted() {
    let mut kinds = vec![Kind::Note { pad: 0 }; MAX_MEMBERS - 1];
    kinds.push(Kind::Affirm { act: 1, pad: 0 });
    assert_fold_agrees_with_the_whole_prefix(&kinds);
    let mut state = None;
    for (index, kind) in kinds.iter().enumerate() {
        state = Some(
            fold_append(
                SCOPE,
                state.as_deref(),
                &event(index as u64, kind),
                index as u64 + 1,
            )
            .expect("exactly 256 events fit"),
        );
    }
    assert!(state.is_some());
}

#[test]
fn identical_original_payloads_count_once_towards_the_byte_limit() {
    // One 100 KB affirmation costs its event, its 062 catalog row and its original payload. The
    // same act repeated adds the first two each time but the original once; distinct acts add all
    // three each time.
    let affirm = |act, count| vec![Kind::Affirm { act, pad: 100_000 }; count];
    let accepted = |verdicts: Vec<bool>| verdicts.iter().all(|ok| *ok);

    assert!(accepted(assert_fold_agrees_with_the_whole_prefix(&affirm(
        1, 4
    ))));
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&affirm(1, 5)),
        [true, true, true, true, false],
        "a fifth affirmation of the same act crosses 1 MiB"
    );
    let distinct = |count: u8| {
        (0..count)
            .map(|act| Kind::Affirm { act, pad: 100_000 })
            .collect::<Vec<_>>()
    };
    assert!(accepted(assert_fold_agrees_with_the_whole_prefix(
        &distinct(3)
    )));
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&distinct(4)),
        [true, true, true, false],
        "a fourth distinct original crosses 1 MiB"
    );
}

/// What the fold charges against [`MAX_BYTES`] after `kinds`.
fn charged_bytes(kinds: &[Kind]) -> u64 {
    let mut state = None;
    for (index, kind) in kinds.iter().enumerate() {
        state = Some(
            fold_append(
                SCOPE,
                state.as_deref(),
                &event(index as u64, kind),
                index as u64 + 1,
            )
            .expect("under the limit while measuring"),
        );
    }
    let state = SignatureExportState::decode(&state.unwrap()).unwrap();
    array_header_len(state.affirmations)
        + state.catalog_row_bytes
        + state.event_bytes
        + state.original_bytes
}

#[test]
fn evidence_of_exactly_the_byte_limit_is_accepted_and_one_byte_more_is_refused() {
    // One affirmation, then a note whose padding is tuned until the charge is exactly the limit.
    let ledger = |pad: usize| vec![Kind::Affirm { act: 1, pad: 1000 }, Kind::Note { pad }];
    let mut pad = 600_000;
    loop {
        let charged = charged_bytes(&ledger(pad));
        if charged == MAX_BYTES as u64 {
            break;
        }
        pad = (pad as i64 + MAX_BYTES as i64 - charged as i64) as usize;
    }
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&ledger(pad)),
        [true, true],
        "evidence of exactly 1 MiB fits"
    );
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&ledger(pad + 1)),
        [true, false],
        "one byte more does not"
    );
}

#[test]
fn a_malformed_affirmation_is_refused_by_both() {
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&[Kind::NoSigningAct]),
        [false]
    );
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&[Kind::WrongContentHash]),
        [false]
    );
    assert_eq!(
        assert_fold_agrees_with_the_whole_prefix(&[
            Kind::Note { pad: 0 },
            Kind::Affirm { act: 0, pad: 0 }
        ]),
        [true, true]
    );
}

#[test]
fn a_corrupt_prior_state_is_refused() {
    let note = event(0, &Kind::Note { pad: 0 });
    for bad in [vec![], vec![9u8; 37], vec![1u8; 10]] {
        assert!(fold_append(SCOPE, Some(&bad), &note, 1).is_err());
    }
}

#[test]
fn the_state_stays_small_and_independent_of_the_ledger_length() {
    let mut state: Option<Vec<u8>> = None;
    for index in 0..200u64 {
        state = Some(
            fold_append(
                SCOPE,
                state.as_deref(),
                &event(index, &Kind::Note { pad: 0 }),
                index + 1,
            )
            .unwrap(),
        );
    }
    assert_eq!(state.unwrap().len(), FIXED_LEN, "notes add no originals");
}
