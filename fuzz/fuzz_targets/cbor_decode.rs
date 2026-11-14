#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoder must never panic, only accept or reject.
    let _ = lattice_proto::decode(data);
});
