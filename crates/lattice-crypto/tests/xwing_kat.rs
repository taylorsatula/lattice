//! X-Wing known-answer test anchored to the CFRG X-Wing draft vectors.
//!
//! The catalog lives in vectors/xwing-kat.json, copied from the `x-wing`
//! crate's published draft vectors. This test pins lattice-crypto's usage
//! path (key reconstruction from seed, public key derivation, seal/open
//! round trip) to those vectors.

use lattice_crypto::{ENVELOPE_CONTEXT, XWingSecretKey, open, seal};

#[test]
fn draft_vectors() {
    use x_wing::{DecapsulationKeyRejectNonContrib, TryDecapsulate, kem};

    let raw = include_str!("../../../vectors/xwing-kat.json");
    let vectors: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
    assert!(vectors.len() >= 3);
    for (i, v) in vectors.iter().enumerate() {
        let seed: [u8; 32] = hex::decode(v["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sk: [u8; 32] = hex::decode(v["sk"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let pk = hex::decode(v["pk"].as_str().unwrap()).unwrap();
        let ct = hex::decode(v["ct"].as_str().unwrap()).unwrap();
        let ss = hex::decode(v["ss"].as_str().unwrap()).unwrap();

        // Key derivation: seed -> same decapsulation key, same public key.
        let secret = XWingSecretKey::from_bytes(sk);
        assert_eq!(
            secret.public_key().as_slice(),
            pk.as_slice(),
            "vector {i}: public key mismatch"
        );
        let derived = XWingSecretKey::from_bytes(seed);
        assert_eq!(
            derived.public_key(),
            secret.public_key(),
            "vector {i}: seed/sk mismatch"
        );

        // Decapsulation known answer: ct from the draft must yield ss.
        let ct_arr: kem::Ciphertext<x_wing::XWingKem> = ct.as_slice().try_into().unwrap();
        let dk = DecapsulationKeyRejectNonContrib::from(sk);
        let recovered = dk
            .try_decapsulate(&ct_arr)
            .expect("decapsulation rejected draft vector");
        assert_eq!(
            recovered.as_slice(),
            ss.as_slice(),
            "vector {i}: shared secret mismatch"
        );
    }
}

#[test]
fn seal_roundtrip_and_tamper() {
    let kp = lattice_crypto::generate_keypair();
    let aad = b"routing header bytes";
    let msg = b"hello mesh";
    let sealed = seal(ENVELOPE_CONTEXT, &kp.public, aad, msg).unwrap();

    let opened = open(
        ENVELOPE_CONTEXT,
        &kp.secret,
        aad,
        &sealed.kem_ciphertext,
        &sealed.ciphertext,
    )
    .unwrap();
    assert_eq!(opened, msg);

    // Wrong AAD fails.
    assert!(
        open(
            ENVELOPE_CONTEXT,
            &kp.secret,
            b"other aad",
            &sealed.kem_ciphertext,
            &sealed.ciphertext
        )
        .is_err()
    );
    // Wrong context fails.
    assert!(
        open(
            "lattice v1 hop",
            &kp.secret,
            aad,
            &sealed.kem_ciphertext,
            &sealed.ciphertext
        )
        .is_err()
    );
    // Wrong key fails.
    let other = lattice_crypto::generate_keypair();
    assert!(
        open(
            ENVELOPE_CONTEXT,
            &other.secret,
            aad,
            &sealed.kem_ciphertext,
            &sealed.ciphertext
        )
        .is_err()
    );
    // Flip a ciphertext byte.
    let mut bad = sealed.ciphertext.clone();
    bad[0] ^= 1;
    assert!(
        open(
            ENVELOPE_CONTEXT,
            &kp.secret,
            aad,
            &sealed.kem_ciphertext,
            &bad
        )
        .is_err()
    );
    // Flip a KEM ciphertext byte.
    let mut bad_kem = sealed.kem_ciphertext;
    bad_kem[100] ^= 1;
    assert!(
        open(
            ENVELOPE_CONTEXT,
            &kp.secret,
            aad,
            &bad_kem,
            &sealed.ciphertext
        )
        .is_err()
    );
}
