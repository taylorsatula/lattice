//! Minimal unsigned 256-bit arithmetic for range arithmetic and
//! fingerprint sums. Little-endian limb order internally; byte conversion
//! uses big-endian, matching the network byte order of ids and hashes.

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct U256([u64; 4]); // limbs little-endian, limb 0 = least significant

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl U256 {
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = 24 - i * 8;
            *limb = u64::from_be_bytes(b[start..start + 8].try_into().unwrap());
        }
        U256(limbs)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            let start = 24 - i * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Wrapping add (mod 2^256).
    pub fn add(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in out.iter_mut().enumerate() {
            let sum = self.0[i] as u128 + rhs.0[i] as u128 + carry;
            *limb = sum as u64;
            carry = sum >> 64;
        }
        U256(out)
    }

    /// Wrapping subtract (mod 2^256).
    pub fn sub(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for (i, limb) in out.iter_mut().enumerate() {
            let (d1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *limb = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        U256(out)
    }

    /// Right shift by `bits`.
    pub fn shr(self, bits: u32) -> Self {
        let word = (bits / 64) as usize;
        let rem = bits % 64;
        let mut out = [0u64; 4];
        for (i, limb) in out.iter_mut().enumerate() {
            let lo = self.0.get(i + word).copied().unwrap_or(0);
            let hi = if rem == 0 {
                0
            } else {
                self.0.get(i + word + 1).copied().unwrap_or(0)
            };
            *limb = if rem == 0 {
                lo
            } else {
                (lo >> rem) | (hi << (64 - rem))
            };
        }
        U256(out)
    }

    /// Multiply by a small scalar.
    pub fn mul_small(self, k: u64) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in out.iter_mut().enumerate() {
            let p = self.0[i] as u128 * k as u128 + carry;
            *limb = p as u64;
            carry = p >> 64;
        }
        U256(out)
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }
}

impl core::ops::Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip() {
        let b = [0xabu8; 32];
        assert_eq!(U256::from_bytes(&b).to_bytes(), b);
    }

    #[test]
    fn ordering_is_numeric() {
        let a = U256::default();
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 1;
        let b = U256::from_bytes(&b_bytes);
        let mut c_bytes = [0xffu8; 32];
        c_bytes[31] = 0x00;
        assert!(a < b);
        assert!(b > a);
        assert!(U256::from_bytes(&c_bytes) < U256([u64::MAX; 4]));
    }

    #[test]
    fn add_wraps() {
        let max = U256([u64::MAX; 4]);
        let one = U256([1, 0, 0, 0]);
        assert_eq!(max.add(one), U256::default());
    }

    #[test]
    fn shr_works() {
        let mut b = [0u8; 32];
        b[0] = 0x10; // 2^252
        let v = U256::from_bytes(&b);
        let shifted = v.shr(4);
        let mut expect = [0u8; 32];
        expect[0] = 0x01;
        assert_eq!(shifted.to_bytes(), expect);
    }
}
