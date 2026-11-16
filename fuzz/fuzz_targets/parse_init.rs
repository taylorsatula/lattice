#![no_main]
use libfuzzer_sys::fuzz_target;
use lattice_proto::frames::Frame;

// lattice-net's `parse_init` (server.rs) is private, so this target drives
// the identical decode path through the public API: lattice_proto::decode,
// then Frame::from_value, then the Init match. Inputs parse_init would
// reject, this rejects the same way; only the NetError mapping is not
// exercised.
fuzz_target!(|data: &[u8]| {
    let Ok(v) = lattice_proto::decode(data) else {
        return;
    };
    let Ok(frame) = Frame::from_value(&v) else {
        return;
    };
    if let Frame::Init(init) = frame {
        let _ = (init.noise_msg, init.mac1, init.mac2, init.padding);
    }
});
