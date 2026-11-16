#![no_main]
use libfuzzer_sys::fuzz_target;

use lattice_crypto::XWingSecretKey;

// Fixed key material; goal is exercising the sealed-layer and envelope
// parsing paths, not recovering anything.
fn fixed_secret() -> XWingSecretKey {
    XWingSecretKey::from_bytes([0x42; 32])
}

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = lattice_proto::Message::parse(data, 1_800_000_000) {
        let _ = msg.open_envelope(&fixed_secret());
        let _ = msg.open_hop_layer(&fixed_secret());
    }
});
