//! OS randomness. Every random draw in Lattice goes through here.

pub fn os_fill(dest: &mut [u8]) {
    // Policy: if OS entropy is unavailable, no safe operation is possible,
    // so the process aborts here. This is intentional fail-fast, not a bug:
    // do not "fix" it by propagating a Result.
    getrandom::fill(dest).expect("OS entropy is unavailable");
}

pub fn os_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    os_fill(&mut out);
    out
}
