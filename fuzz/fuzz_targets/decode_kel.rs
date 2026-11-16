#![no_main]
use libfuzzer_sys::fuzz_target;

// decode_kel walks the length-prefixed event list, decodes each event, and
// validates the whole chain (linkage, commitments, per-event signatures).
// The count prefix is attacker-controlled; the decoder caps pre-allocation
// (count.min(1024)) and the walk is bounded by the input length.
fuzz_target!(|data: &[u8]| {
    let _ = lattice_proto::kel::decode_kel(data);
});
