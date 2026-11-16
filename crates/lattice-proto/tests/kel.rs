use lattice_crypto::{KEY_EVENT_CONTEXT, generate_seed, hash, sign, signing_preimage};
use lattice_proto::cbor::encode;
use lattice_proto::kel::{KelRelation, KeyEvent, ValidatedKel, classify, identifier};
use lattice_types::{Commitment, Identifier, SigningSeed};

fn commitment_of(seed: &SigningSeed) -> Commitment {
    Commitment::from_bytes(hash(lattice_crypto::public_key(seed).as_ref()).into_bytes())
}

fn chain(n: usize) -> Vec<KeyEvent> {
    let seed0 = generate_seed();
    let seed1 = generate_seed();
    let mut events = vec![KeyEvent::inception(&seed0, commitment_of(&seed1))];
    let mut current = seed1;
    for i in 1..n {
        let next_seed = generate_seed();
        let abandon = i == n - 1;
        let next_hash = (!abandon).then(|| commitment_of(&next_seed));
        events.push(KeyEvent::rotation(
            events.last().unwrap(),
            &current,
            next_hash,
        ));
        current = next_seed;
    }
    events
}

#[test]
fn inception_validates_and_id_stable() {
    let events = chain(1);
    let head = KeyEvent::validate_chain(&events).unwrap();
    assert_eq!(head.seq, 0);
    assert!(!head.is_abandoned());
    assert_eq!(identifier(&events).unwrap(), identifier(&events).unwrap());
    assert_ne!(
        identifier(&events).unwrap(),
        Identifier::from_bytes([0u8; 32])
    );
}

#[test]
fn rotation_chain_validates_and_abandonment_terminates() {
    let events = chain(3);
    let head = KeyEvent::validate_chain(&events).unwrap();
    assert_eq!(head.seq, 2);
    assert!(head.is_abandoned());

    // Nothing may follow an abandonment.
    let extra = KeyEvent::rotation(events.last().unwrap(), &generate_seed(), None);
    let mut extended = events.clone();
    extended.push(extra);
    assert!(KeyEvent::validate_chain(&extended).is_err());
}

#[test]
fn rotation_by_uncommitted_key_fails() {
    let events = chain(1);
    let attacker = generate_seed();
    let forged = KeyEvent::rotation(&events[0], &attacker, None);
    let mut bad = events.clone();
    bad.push(forged);
    assert!(KeyEvent::validate_chain(&bad).is_err());
}

#[test]
fn tampered_prev_fails() {
    let seed0 = generate_seed();
    let seed1 = generate_seed();
    let e0 = KeyEvent::inception(&seed0, commitment_of(&seed1));
    let mut e1 = KeyEvent::rotation(&e0, &seed1, None);
    // Re-sign with the correct key but a doctored prev commitment.
    e1.prev = Some(Commitment::from_bytes([7u8; 32]));
    e1.sig = sign(
        &seed1,
        &signing_preimage(KEY_EVENT_CONTEXT, &encode(&e1.unsigned_value())),
    );
    assert!(KeyEvent::validate_chain(&[e0, e1]).is_err());
}

#[test]
fn tampered_signature_fails() {
    let events = chain(2);
    let mut bad = events.clone();
    let mut sig = bad[1].sig.into_bytes();
    sig[10] ^= 1;
    bad[1].sig = lattice_types::Signature::from_bytes(sig);
    assert!(KeyEvent::validate_chain(&bad).is_err());
}

#[test]
fn classify_against_known_head() {
    let events = chain(3);
    let head_two = KeyEvent::validate_chain(&events[..2]).unwrap();
    assert_eq!(
        classify(head_two.seq, &head_two.commitment, &events),
        KelRelation::Extends
    );
    let head_full = KeyEvent::validate_chain(&events).unwrap();
    assert_eq!(
        classify(head_full.seq, &head_full.commitment, &events),
        KelRelation::Same
    );
    assert_eq!(
        classify(head_full.seq, &head_full.commitment, &events[..1]),
        KelRelation::Behind
    );
}

#[test]
fn serialization_roundtrip() {
    let events = chain(2);
    for ev in &events {
        let bytes = ev.encode();
        let back = KeyEvent::from_bytes(&bytes).unwrap();
        assert_eq!(&back, ev);
    }
}

#[test]
fn kel_object_roundtrip() {
    let events = chain(3);
    let kel = ValidatedKel::validate(events).unwrap();
    let bytes = kel.to_object_bytes().unwrap();
    assert!(bytes.len() <= lattice_proto::kel::MAX_KEL_BYTES);
    let back = ValidatedKel::from_object_bytes(&bytes).unwrap();
    assert_eq!(back, kel);
    assert_eq!(back.head().seq, 2);
    assert!(back.is_abandoned());
}

#[test]
fn kel_object_rejects_wrong_id() {
    let events = chain(2);
    let kel = ValidatedKel::validate(events).unwrap();
    let bytes = kel.to_object_bytes().unwrap();
    // Decode, swap in a different id, re-encode, expect rejection.
    let value = lattice_proto::decode(&bytes).unwrap();
    let mut pairs: Vec<(lattice_proto::Value, lattice_proto::Value)> =
        value.as_map().unwrap().to_vec();
    for (k, v) in pairs.iter_mut() {
        if k.as_uint() == Some(2) {
            *v = lattice_proto::Value::Bytes(vec![0xAA; 32]);
        }
    }
    let tampered = lattice_proto::encode(&lattice_proto::Value::map(pairs));
    assert!(ValidatedKel::from_object_bytes(&tampered).is_err());
}

#[test]
fn kel_object_rejects_wrong_type() {
    let events = chain(1);
    let kel = ValidatedKel::validate(events).unwrap();
    let bytes = kel.to_object_bytes().unwrap();
    let value = lattice_proto::decode(&bytes).unwrap();
    let mut pairs: Vec<(lattice_proto::Value, lattice_proto::Value)> =
        value.as_map().unwrap().to_vec();
    for (k, v) in pairs.iter_mut() {
        if k.as_uint() == Some(1) {
            *v = lattice_proto::Value::UInt(10); // a record, not a KEL
        }
    }
    let tampered = lattice_proto::encode(&lattice_proto::Value::map(pairs));
    assert!(ValidatedKel::from_object_bytes(&tampered).is_err());
}

#[test]
fn kel_object_rejects_oversize() {
    let bytes = vec![0u8; lattice_proto::kel::MAX_KEL_BYTES + 1];
    assert!(ValidatedKel::from_object_bytes(&bytes).is_err());
}

#[test]
fn kel_object_rejects_non_contiguous_events() {
    // A hand-built rotation with seq 2 after an inception (seq 0): the
    // signature is valid for the event, but the chain is not contiguous.
    let seed0 = generate_seed();
    let seed1 = generate_seed();
    let seed2 = generate_seed();
    let inception = KeyEvent::inception(&seed0, commitment_of(&seed1));
    let mut gap = KeyEvent::rotation(&inception, &seed1, Some(commitment_of(&seed2)));
    gap.seq = 2; // skip sn 1
    gap.sig = sign(
        &seed1,
        &signing_preimage(KEY_EVENT_CONTEXT, &encode(&gap.unsigned_value())),
    );
    let object = lattice_proto::Value::map(vec![
        (lattice_proto::Value::UInt(0), lattice_proto::Value::UInt(1)),
        (
            lattice_proto::Value::UInt(1),
            lattice_proto::Value::UInt(11),
        ),
        (
            lattice_proto::Value::UInt(2),
            lattice_proto::Value::Bytes(
                identifier(std::slice::from_ref(&inception))
                    .unwrap()
                    .to_vec(),
            ),
        ),
        (
            lattice_proto::Value::UInt(3),
            lattice_proto::Value::Array(vec![inception.to_value(), gap.to_value()]),
        ),
    ]);
    let bytes = lattice_proto::encode(&object);
    assert!(ValidatedKel::from_object_bytes(&bytes).is_err());
}

#[test]
fn kel_object_rejects_truncated_chain() {
    // An object whose events do not start at sn 0 is rejected.
    let events = chain(2);
    let object = lattice_proto::Value::map(vec![
        (lattice_proto::Value::UInt(0), lattice_proto::Value::UInt(1)),
        (
            lattice_proto::Value::UInt(1),
            lattice_proto::Value::UInt(11),
        ),
        (
            lattice_proto::Value::UInt(2),
            lattice_proto::Value::Bytes(identifier(&events[..1]).unwrap().to_vec()),
        ),
        (
            lattice_proto::Value::UInt(3),
            lattice_proto::Value::Array(vec![events[1].to_value()]),
        ),
    ]);
    let bytes = lattice_proto::encode(&object);
    assert!(ValidatedKel::from_object_bytes(&bytes).is_err());
}
