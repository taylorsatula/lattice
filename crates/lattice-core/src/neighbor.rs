//! Neighbor selection (design §5, Heilman et al. 2015; Brahms 2008).
//!
//! Candidates are the validated records that carry endpoints. They are
//! grouped by network range (/24 for IPv4, /48 for IPv6, hostname for
//! hostname-only endpoints) and ranked by a hash salted with a per-node
//! secret, so an attacker cannot predict or aim at the slots a node
//! fills. Selection is greedy in hash order with per-range sub-caps and a
//! per-scope total cap. A few anchor peers are persisted and never
//! evicted; a peer is dialed before its incumbent is evicted
//! (test-before-evict).
//!
//! The salt is derived from the node's channel seed with a domain
//! separator (`lattice/neighbor-selection/v1`), so it is stable across
//! restarts (saved anchors stay meaningful) and unpredictable to anyone
//! who does not hold the seed. It is never published.

use std::net::IpAddr;

use lattice_proto::record::{Endpoint, Scope};
use lattice_types::{ChannelPublicKey, Identifier};

/// Outbound (core-dialed) WAN link cap. The daemon enforces a separate,
/// higher hard cap on all links (32); this is the selection target.
pub(crate) const MAX_OUTBOUND_WAN: usize = 16;
/// Outbound hive link cap. A gateway can serve a large hive and still
/// hold its WAN backbone links.
pub(crate) const MAX_OUTBOUND_HIVE: usize = 128;
/// Per-range-group sub-caps: at most this many selected candidates from
/// one /24 (IPv4), one /48 (IPv6), or one hostname.
pub(crate) const MAX_PER_GROUP_V4: usize = 2;
pub(crate) const MAX_PER_GROUP_V6: usize = 4;
pub(crate) const MAX_PER_GROUP_HOST: usize = 2;
/// Anchors: the best-hashed linked candidates, persisted and never
/// evicted by the selection algorithm.
pub(crate) const ANCHOR_COUNT: usize = 3;
/// Bound on the persisted saved-peer table; the oldest non-anchor entry
/// is evicted past this.
pub(crate) const MAX_SAVED_PEERS: usize = 128;
/// Backoff after a failed dial: base delay, doubled per consecutive
/// failure, capped.
pub(crate) const DIAL_BACKOFF_BASE_MS: u64 = 5_000;
pub(crate) const DIAL_BACKOFF_MAX_MS: u64 = 300_000;
/// Backoff after a link drops, so a flapping peer is not redialed in a
/// tight loop.
pub(crate) const LINK_DOWN_BACKOFF_MS: u64 = 5_000;

pub(crate) fn scope_cap(scope: Scope) -> usize {
    match scope {
        Scope::Wan => MAX_OUTBOUND_WAN,
        Scope::Hive => MAX_OUTBOUND_HIVE,
    }
}

pub(crate) fn scope_byte(scope: Scope) -> u8 {
    match scope {
        Scope::Wan => 0,
        Scope::Hive => 1,
    }
}

/// The network range a candidate is grouped by. IPv4-mapped IPv6
/// addresses group as IPv4.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub(crate) enum RangeKey {
    V4([u8; 3]),
    V6([u8; 6]),
    /// Hostname-only endpoint (no literal IPs anywhere in the record).
    Host(String),
}

impl RangeKey {
    pub(crate) fn sub_cap(&self) -> usize {
        match self {
            RangeKey::V4(_) => MAX_PER_GROUP_V4,
            RangeKey::V6(_) => MAX_PER_GROUP_V6,
            RangeKey::Host(_) => MAX_PER_GROUP_HOST,
        }
    }
}

fn range_of_ip(ip: &IpAddr) -> RangeKey {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            RangeKey::V4([o[0], o[1], o[2]])
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return range_of_ip(&IpAddr::V4(v4));
            }
            let o = v6.octets();
            let mut p = [0u8; 6];
            p.copy_from_slice(&o[..6]);
            RangeKey::V6(p)
        }
    }
}

/// The range group for a record's endpoints: the first literal IP across
/// the endpoints (in order, matching the dialer's preference), else the
/// host part of the first endpoint if it parses as an IP, else the
/// lowercased hostname.
pub(crate) fn range_key(endpoints: &[Endpoint]) -> RangeKey {
    for ep in endpoints {
        if let Some(ip) = ep.ips.first() {
            return range_of_ip(ip);
        }
    }
    if let Some(ep) = endpoints.first() {
        let host = host_of(&ep.url);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return range_of_ip(&ip);
        }
        return RangeKey::Host(host.to_ascii_lowercase());
    }
    // Unreachable for candidates (they require at least one endpoint).
    RangeKey::Host(String::new())
}

/// The range group for a single endpoint plus its literal IPs (the saved
/// peer case, where the endpoint is stored as a single URL).
pub(crate) fn range_key_of(url: &str, ips: &[IpAddr]) -> RangeKey {
    if let Some(ip) = ips.first() {
        return range_of_ip(ip);
    }
    let host = host_of(url);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return range_of_ip(&ip);
    }
    RangeKey::Host(host.to_ascii_lowercase())
}

/// The host part of a `ws://`/`wss://` URL, without brackets or port.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

/// A dialable candidate derived from a validated record.
pub(crate) struct Candidate {
    pub id: Identifier,
    pub scope: Scope,
    /// First endpoint's URL, as published.
    pub endpoint: String,
    /// All literal IPs across the record's endpoints, in order.
    pub ips: Vec<IpAddr>,
    pub channel_key: ChannelPublicKey,
    pub range: RangeKey,
    /// Salted selection hash; lower is better.
    pub hash: u64,
}

/// Derive the per-node selection salt from the channel seed. Stable
/// across restarts; unpredictable without the seed.
pub(crate) fn selection_salt(channel_seed: &[u8; 32]) -> [u8; 32] {
    lattice_crypto::derive_key("lattice/neighbor-selection/v1", channel_seed)
}

/// The salted selection hash of a candidate. Lower wins.
pub(crate) fn candidate_hash(salt: &[u8; 32], scope: Scope, id: &Identifier) -> u64 {
    let mut buf = [0u8; 33];
    buf[0] = scope_byte(scope);
    buf[1..].copy_from_slice(id.as_bytes());
    let h = lattice_crypto::keyed_hash(salt, &buf);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_proto::record::Endpoint;

    fn ep(url: &str, ips: &[&str]) -> Endpoint {
        Endpoint {
            url: url.into(),
            ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn range_key_prefers_first_literal_ip() {
        let eps = vec![ep("ws://a.example.com/", &["203.0.113.7", "198.51.100.9"])];
        assert_eq!(range_key(&eps), RangeKey::V4([203, 0, 113]));
    }

    #[test]
    fn range_key_uses_host_when_no_ips() {
        let eps = vec![ep("ws://203.0.113.7:8080/", &[])];
        assert_eq!(range_key(&eps), RangeKey::V4([203, 0, 113]));
        let eps = vec![ep("ws://[2001:db8:aaaa::1]/", &[])];
        assert_eq!(
            range_key(&eps),
            RangeKey::V6([0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xaa])
        );
        let eps = vec![ep("ws://Example.COM/", &[])];
        assert_eq!(range_key(&eps), RangeKey::Host("example.com".into()));
    }

    #[test]
    fn range_key_folds_v4_mapped_v6() {
        let eps = vec![ep("ws://x/", &["::ffff:203.0.113.9"])];
        assert_eq!(range_key(&eps), RangeKey::V4([203, 0, 113]));
    }
}
