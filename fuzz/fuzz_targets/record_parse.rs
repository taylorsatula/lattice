#![no_main]
use libfuzzer_sys::fuzz_target;
use lattice_crypto::{hash, public_key};
use lattice_proto::kel::{KeyEvent, ValidatedKel};
use lattice_types::{Commitment, SigningSeed};

// A fixed, valid inception KEL to validate candidate records against.
// The record's own KEL head will almost never match it, so most inputs
// are rejected at the head-binding check — which is what a fuzzer wants:
// it exercises the parser and the validator, not a happy path.
fn fixed_kel() -> ValidatedKel {
    let seed0 = SigningSeed::from_bytes([0x11; 32]);
    let seed1 = SigningSeed::from_bytes([0x22; 32]);
    let commitment = Commitment::from_bytes(hash(public_key(&seed1).as_ref()).into_bytes());
    let event = KeyEvent::inception(&seed0, commitment);
    ValidatedKel::validate(vec![event]).expect("fixed KEL must validate")
}

fuzz_target!(|data: &[u8]| {
    let kel = fixed_kel();
    let _ = lattice_proto::record::PeerRecord::from_bytes(data, 1_800_000_000, &kel);
});
