//! Ed25519 behavior at the boundaries lattice-proto depends on.

use lattice_crypto::{generate_seed, public_key, sign, verify};

#[test]
fn sign_verify_roundtrip() {
    let seed = generate_seed();
    let pk = public_key(&seed);
    let msg = b"exact bytes being signed";
    let sig = sign(&seed, msg);
    assert!(verify(&pk, msg, &sig));
    assert!(!verify(&pk, b"exact bytes being signedf", &sig));
    let mut bad = sig.into_bytes();
    bad[10] ^= 1;
    assert!(!verify(
        &pk,
        msg,
        &lattice_types::Signature::from_bytes(bad)
    ));
}

#[test]
fn tampered_public_key_fails() {
    let seed = generate_seed();
    let pk = public_key(&seed);
    let sig = sign(&seed, b"m");
    let mut wrong = pk.into_bytes();
    wrong[0] ^= 1;
    assert!(!verify(
        &lattice_types::SigningPublicKey::from_bytes(wrong),
        b"m",
        &sig
    ));
}

#[test]
fn signing_is_deterministic() {
    let seed = generate_seed();
    assert_eq!(sign(&seed, b"abc"), sign(&seed, b"abc"));
}
