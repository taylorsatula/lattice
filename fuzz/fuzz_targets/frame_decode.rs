#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_proto::frames::Frame::from_bytes(data);
});
