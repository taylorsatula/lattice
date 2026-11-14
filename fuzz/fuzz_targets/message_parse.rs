#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_proto::Message::parse(data, 1_800_000_000);
});
