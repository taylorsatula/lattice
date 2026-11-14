use lattice_crypto::{generate_seed, hash, sign};
use lattice_proto::cbor::encode;
use lattice_proto::kel::{KelRelation, KeyEvent, classify, identifier};

fn public_of(seed: &[u8; 32]) -> [u8; 32] {
    lattice_crypto::public_key(seed)
}

fn chain(n: usize) -> Vec<KeyEvent> {
    let seed0 = generate_seed();
    let seed1 = generate_seed();
    let mut events = vec![KeyEvent::inception(&seed0, hash(&public_of(&seed1)))];
    let mut current = seed1;
    for i in 1..n {
        let next_seed = generate_seed();
        let abandon = i == n - 1;
        let next_hash = (!abandon).then(|| hash(&public_of(&next_seed)));
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
    assert!(!head.abandoned);
    assert_eq!(identifier(&events).unwrap(), identifier(&events).unwrap());
    assert_ne!(identifier(&events).unwrap(), [0u8; 32]);
}

#[test]
fn rotation_chain_validates_and_abandonment_terminates() {
    let events = chain(3);
    let head = KeyEvent::validate_chain(&events).unwrap();
    assert_eq!(head.seq, 2);
    assert!(head.abandoned);

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
    let e0 = KeyEvent::inception(&seed0, hash(&public_of(&seed1)));
    let mut e1 = KeyEvent::rotation(&e0, &seed1, None);
    // Re-sign with the correct key but a doctored prev commitment.
    e1.prev = Some([7u8; 32]);
    e1.sig = sign(&seed1, &encode(&e1.unsigned_value()));
    assert!(KeyEvent::validate_chain(&[e0, e1]).is_err());
}

#[test]
fn tampered_signature_fails() {
    let events = chain(2);
    let mut bad = events.clone();
    bad[1].sig[10] ^= 1;
    assert!(KeyEvent::validate_chain(&bad).is_err());
}

#[test]
fn classify_against_known_head() {
    let events = chain(3);
    let head_two = KeyEvent::validate_chain(&events[..2]).unwrap();
    assert_eq!(classify(&head_two, &events), KelRelation::Extends);
    let head_full = KeyEvent::validate_chain(&events).unwrap();
    assert_eq!(classify(&head_full, &events), KelRelation::Same);
    assert_eq!(classify(&head_full, &events[..1]), KelRelation::Behind);
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
