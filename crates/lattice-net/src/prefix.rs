//! Per-source-prefix handshake budgets.
//!
//! A token bucket per source prefix (/24 for IPv4, /48 for IPv6;
//! IPv4-mapped IPv6 is treated as IPv4), checked at accept time before any
//! handshake work happens. Over-budget connections are dropped without a
//! response. The number of tracked prefixes is bounded by an LRU cap so the
//! table itself cannot be exhausted by an attacker rotating source
//! prefixes.

use std::collections::HashMap;
use std::net::SocketAddr;

/// Bursts allowed per prefix before the refill rate applies. Sized so a
/// hive behind one NAT can reconnect en masse after a network blip without
/// being locked out, while a single prefix cannot sustain more than
/// [`BUDGET_REFILL_PER_SEC`] new handshakes per second.
pub const BUDGET_BURST: f64 = 32.0;
/// Sustained handshakes per second allowed per prefix.
pub const BUDGET_REFILL_PER_SEC: f64 = 4.0;
/// Maximum number of prefixes tracked at once. When full, the
/// least-recently-seen prefix is evicted to make room.
pub const MAX_TRACKED_PREFIXES: usize = 1024;

/// A source prefix: /24 for IPv4, /48 for IPv6.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SourcePrefix {
    V4([u8; 3]),
    V6([u8; 6]),
}

impl std::fmt::Display for SourcePrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourcePrefix::V4(o) => write!(f, "{}.{}.{}.0/24", o[0], o[1], o[2]),
            SourcePrefix::V6(o) => write!(
                f,
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                o[0], o[1], o[2], o[3], o[4], o[5]
            ),
        }
    }
}

/// The prefix a source address counts against. IPv4-mapped IPv6 addresses
/// are treated as IPv4 so a dual-stack peer cannot dodge the v4 budget.
pub fn prefix_of(addr: &SocketAddr) -> SourcePrefix {
    match addr {
        SocketAddr::V4(a) => {
            let o = a.ip().octets();
            SourcePrefix::V4([o[0], o[1], o[2]])
        }
        SocketAddr::V6(a) => {
            if let Some(v4) = a.ip().to_ipv4_mapped() {
                let o = v4.octets();
                return SourcePrefix::V4([o[0], o[1], o[2]]);
            }
            let o = a.ip().octets();
            let mut p = [0u8; 6];
            p.copy_from_slice(&o[..6]);
            SourcePrefix::V6(p)
        }
    }
}

struct Bucket {
    tokens: f64,
    last_refill: u64,
    last_seen: u64,
}

/// Token buckets keyed by source prefix, with an LRU bound on the number
/// of tracked prefixes.
pub struct PrefixBudget {
    map: HashMap<SourcePrefix, Bucket>,
    capacity: usize,
    burst: f64,
    refill_per_sec: f64,
    evictions: u64,
}

impl PrefixBudget {
    pub fn new() -> Self {
        Self::with_params(MAX_TRACKED_PREFIXES, BUDGET_BURST, BUDGET_REFILL_PER_SEC)
    }

    fn with_params(capacity: usize, burst: f64, refill_per_sec: f64) -> Self {
        Self {
            map: HashMap::new(),
            capacity,
            burst,
            refill_per_sec,
            evictions: 0,
        }
    }

    /// Take one token for `prefix`. Returns false when the prefix is over
    /// budget and the connection should be dropped.
    pub fn allow(&mut self, prefix: SourcePrefix, now: u64) -> bool {
        if let Some(b) = self.map.get_mut(&prefix) {
            let elapsed = now.saturating_sub(b.last_refill);
            if elapsed > 0 {
                b.tokens = (b.tokens + elapsed as f64 * self.refill_per_sec).min(self.burst);
                b.last_refill = now;
            }
            b.last_seen = now;
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                return true;
            }
            return false;
        }
        if self.map.len() >= self.capacity {
            // Evict the least-recently-seen prefix. O(n) on a bounded table;
            // only reached when the table is full.
            if let Some(victim) = self
                .map
                .iter()
                .min_by_key(|(_, b)| b.last_seen)
                .map(|(k, _)| *k)
            {
                self.map.remove(&victim);
                self.evictions += 1;
            }
        }
        self.map.insert(
            prefix,
            Bucket {
                tokens: self.burst - 1.0,
                last_refill: now,
                last_seen: now,
            },
        );
        true
    }

    /// Number of prefixes evicted to make room for new ones.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.map.len()
    }
}

impl Default for PrefixBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(a, b, c, d).into(), 1234)
    }

    #[test]
    fn prefix_of_v4_is_slash_24() {
        assert_eq!(prefix_of(&v4(192, 0, 2, 1)), prefix_of(&v4(192, 0, 2, 254)));
        assert_ne!(prefix_of(&v4(192, 0, 2, 1)), prefix_of(&v4(192, 0, 3, 1)));
    }

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), 1234)
    }

    #[test]
    fn prefix_of_v6_is_slash_48() {
        let a = v6("2001:db8:aaaa:1::1:1");
        let b = v6("2001:db8:aaaa:2::2:2");
        let c = v6("2001:db8:bbbb:1::1:1");
        assert_eq!(prefix_of(&a), prefix_of(&b));
        assert_ne!(prefix_of(&a), prefix_of(&c));
    }

    #[test]
    fn prefix_of_v4_mapped_v6_folds_to_v4() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:1234".parse().unwrap();
        assert_eq!(prefix_of(&mapped), prefix_of(&v4(192, 0, 2, 99)));
    }

    #[test]
    fn budget_allows_burst_then_denies() {
        let mut b = PrefixBudget::with_params(16, 4.0, 1.0);
        let p = prefix_of(&v4(10, 0, 0, 1));
        for _ in 0..4 {
            assert!(b.allow(p, 1000));
        }
        assert!(!b.allow(p, 1000));
        // One second later exactly one token has refilled.
        assert!(b.allow(p, 1001));
        assert!(!b.allow(p, 1001));
    }

    #[test]
    fn budget_refill_is_capped_at_burst() {
        let mut b = PrefixBudget::with_params(16, 2.0, 10.0);
        let p = prefix_of(&v4(10, 0, 0, 1));
        assert!(b.allow(p, 0));
        // Long idle: refill must not exceed burst.
        assert!(b.allow(p, 10_000));
        assert!(b.allow(p, 10_000));
        assert!(!b.allow(p, 10_000));
    }

    #[test]
    fn budget_table_is_bounded_and_evicts_lru() {
        let mut b = PrefixBudget::with_params(2, 1.0, 0.0);
        let p0 = SourcePrefix::V4([10, 0, 0]);
        let p1 = SourcePrefix::V4([10, 0, 1]);
        let p2 = SourcePrefix::V4([10, 0, 2]);
        assert!(b.allow(p0, 100));
        assert!(b.allow(p1, 100));
        // A denied attempt still marks the prefix as recently seen.
        assert!(!b.allow(p0, 200));
        // Inserting a third prefix evicts the least-recently-seen one (p1).
        assert!(b.allow(p2, 300));
        assert_eq!(b.tracked(), 2);
        assert_eq!(b.evictions(), 1);
        // p0 kept its (spent) state; p1 was evicted and re-enters fresh.
        assert!(!b.allow(p0, 300));
        assert!(b.allow(p1, 300));
    }

    #[test]
    fn budget_denial_does_not_consume_tokens() {
        let mut b = PrefixBudget::with_params(16, 1.0, 0.0);
        let p = prefix_of(&v4(10, 0, 0, 1));
        assert!(b.allow(p, 100));
        assert!(!b.allow(p, 100));
        assert!(!b.allow(p, 100));
        // Still denied; denial did not go negative.
        assert!(!b.allow(p, 100));
    }

    #[test]
    fn v6_prefixes_are_tracked_independently() {
        let mut b = PrefixBudget::with_params(16, 1.0, 0.0);
        let a = v6("2001:db8:1::1");
        let c = v6("2001:db8:2::1");
        assert!(b.allow(prefix_of(&a), 0));
        assert!(b.allow(prefix_of(&c), 0));
        assert!(!b.allow(prefix_of(&a), 0));
    }
}
