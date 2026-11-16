#![no_main]
use libfuzzer_sys::fuzz_target;
use lattice_proto::local::{self, Request};

// The local API is length-prefixed CBOR on a Unix socket. Split one frame
// off the front of the buffer exactly as the daemon does, then decode the
// payload as a request — the full untrusted-input path from socket bytes
// to a Request value.
fuzz_target!(|data: &[u8]| {
    let Ok(Some(frame)) = local::deframe_local(data) else {
        return;
    };
    if let Ok(v) = lattice_proto::decode(frame.payload) {
        let _ = Request::from_value(&v);
    }
});
