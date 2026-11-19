//! Minimal CIDR matching for the configured hive ranges. Used to classify
//! links as hive-scope vs WAN-scope (established-link caps, gossip scope)
//! and to decide hive membership from a node's own addresses. Kept in one
//! place so the daemon and the core agree on what "in the hive" means.

use std::net::IpAddr;

/// A parsed `addr/prefix` range. IPv4-mapped IPv6 addresses match IPv4
/// ranges, so a dual-stack peer cannot dodge hive classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| "expected CIDR notation `<ip>/<prefix>`".to_string())?;
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("{addr:?} is not an IP address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("{prefix:?} is not a valid prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix length {prefix} exceeds {max} for {ip}"));
        }
        // Mask off the host bits so containment tests are exact even if the
        // config carries a non-canonical network address.
        let network = mask(ip, prefix);
        Ok(Cidr { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let bits = u32::from(net);
                let m = mask_u32(self.prefix);
                (u32::from(a) & m) == (bits & m)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let m = mask_u128(self.prefix);
                (u128::from(a) & m) == (u128::from(net) & m)
            }
            // An IPv4 range never contains an IPv6 address and vice versa.
            _ => false,
        }
    }
}

fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(std::net::Ipv4Addr::from(u32::from(a) & mask_u32(prefix))),
        IpAddr::V6(a) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(a) & mask_u128(prefix))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_containment() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        // Non-canonical network address is masked off.
        let c2 = Cidr::parse("10.1.2.3/16").unwrap();
        assert!(c2.contains("10.1.9.9".parse().unwrap()));
    }

    #[test]
    fn v6_containment() {
        let c = Cidr::parse("fd00::/8").unwrap();
        assert!(c.contains("fd12:3456::1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn v4_mapped_v6_matches_v4_range() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn cross_family_never_matches() {
        // A native v6 address is not in a v4 range.
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c.contains("fd00::1".parse().unwrap()));
        // A v4 address is not in a v6 range.
        let c6 = Cidr::parse("::/0").unwrap();
        assert!(!c6.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Cidr::parse("10.0.0.0").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("not-an-ip/8").is_err());
    }
}
