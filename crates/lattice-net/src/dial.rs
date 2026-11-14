//! Connect-time scope enforcement (V2_SPEC §2 endpoint scope rule).
//!
//! A WAN record whose addresses are not globally routable is never dialed,
//! and a hostname that resolves to one is never dialed either. Hive records
//! may use private/ULA addresses. DNS is resolved through the operating
//! system's resolver here; encrypted DNS (DoH/DoT) is a configuration item
//! for the daemon, not the library.

#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};

use lattice_proto::record::{Scope, is_globally_routable};

use crate::client::{PeerContact, connect};
use crate::errors::NetError;
use crate::peer::PeerIo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointUrl {
    pub host: String,
    pub port: u16,
}

pub fn parse_endpoint(url: &str) -> Result<EndpointUrl, NetError> {
    let (scheme, rest) = url.split_once("://").ok_or(NetError::Io)?;
    match scheme {
        // Lattice speaks plain WebSocket; confidentiality comes from Noise.
        // wss is rejected rather than silently downgraded.
        "ws" => {}
        _ => return Err(NetError::Io),
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(NetError::Io);
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // [v6]:port
        let end = rest.find(']').ok_or(NetError::Io)?;
        let h = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| NetError::Io)?,
            None => 80,
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|_| NetError::Io)?;
        if p.bytes().any(|b| !b.is_ascii_digit()) {
            return Err(NetError::Io);
        }
        (h.to_string(), port)
    } else {
        (authority.to_string(), 80)
    };
    if host.is_empty() {
        return Err(NetError::Io);
    }
    Ok(EndpointUrl { host, port })
}

/// Addresses worth dialing for an endpoint, after scope enforcement.
/// Preference: literal IPs from the record, then hostname resolution.
pub async fn scoped_addresses(
    endpoint: &EndpointUrl,
    record_ips: &[IpAddr],
    scope: Scope,
) -> Result<Vec<SocketAddr>, NetError> {
    let mut candidates: Vec<IpAddr> = Vec::new();
    if !record_ips.is_empty() {
        // IP addresses listed in the record are preferred over DNS.
        candidates.extend_from_slice(record_ips);
    } else if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        candidates.push(ip);
    } else {
        // Resolution uses the system resolver. To move to DoH/DoT later,
        // swap this lookup for a DoH client (e.g. hickory-resolver) behind
        // the same signature; nothing else in the dial path cares how the
        // addresses were obtained. The resolved addresses still pass through
        // the scope filter below, so a hostile resolver cannot smuggle a
        // private address into a WAN dial.
        let resolved = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
            .await
            .map_err(|_| NetError::Io)?;
        candidates.extend(resolved.map(|a| a.ip()));
    }
    let allowed: Vec<IpAddr> = candidates
        .into_iter()
        .filter(|ip| match scope {
            Scope::Wan => is_globally_routable(*ip),
            Scope::Hive => true, // hives own their address policy
        })
        .collect();
    if allowed.is_empty() {
        // Everything resolved to a disallowed address: do not dial anything.
        return Err(NetError::Io);
    }
    Ok(allowed
        .into_iter()
        .map(|ip| SocketAddr::new(ip, endpoint.port))
        .collect())
}

/// Connect to an endpoint honoring the record's scope. `expected_ik` is the
/// record's channel key for IK peers; `xx_path` for an XX root contact.
pub async fn connect_scoped(
    channel_seed: &[u8; 32],
    endpoint: &EndpointUrl,
    record_ips: &[IpAddr],
    scope: Scope,
    ik_channel_key: Option<[u8; 32]>,
    xx_path: Option<String>,
) -> Result<PeerIo, NetError> {
    let addrs = scoped_addresses(endpoint, record_ips, scope).await?;
    let mut last_err = NetError::Io;
    for addr in addrs {
        let contact = match (ik_channel_key, &xx_path) {
            (Some(ck), _) => PeerContact::Ik {
                addr,
                channel_key: ck,
            },
            (None, Some(path)) => PeerContact::Xx {
                addr,
                path: path.clone(),
            },
            (None, None) => {
                return Err(NetError::Io); // caller must supply either a key or a path
            }
        };
        match connect(contact, channel_seed).await {
            Ok(peer) => return Ok(peer),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wan_record_with_private_ips_is_never_dialed() {
        let ep = parse_endpoint("ws://mesh.example.com:443/").unwrap();
        let private = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ];
        let out = scoped_addresses(&ep, &private, Scope::Wan).await;
        assert!(
            out.is_err(),
            "private addresses must not be dialable from a WAN record"
        );
        // Classifier agrees on the public/private boundary.
        assert!(!is_globally_routable("100.64.0.1".parse().unwrap()));
        assert!(!is_globally_routable("169.254.1.1".parse().unwrap()));
        assert!(is_globally_routable("1.1.1.1".parse().unwrap()));
        // IPv4-embedding transition ranges are not WAN-routable.
        for embedded in [
            "::1.2.3.4",        // deprecated compatible ::/96
            "64:ff9b::1.2.3.4", // NAT64 well-known prefix
            "2002:0102:0304::", // 6to4
            "2001::1.2.3.4",    // Teredo
        ] {
            assert!(
                !is_globally_routable(embedded.parse().unwrap()),
                "{embedded} must not be WAN-routable"
            );
        }
        // Mapped addresses defer to the embedded IPv4's routability.
        assert!(is_globally_routable("::ffff:1.2.3.4".parse().unwrap()));
        assert!(!is_globally_routable("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_globally_routable(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn hive_record_may_use_private_ips() {
        let ep = parse_endpoint("ws://hive.local:8443/").unwrap();
        let private = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))];
        let out = scoped_addresses(&ep, &private, Scope::Hive).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port(), 8443);
    }

    #[tokio::test]
    async fn wan_public_ip_is_dialable() {
        let ep = parse_endpoint("ws://mesh.example.com/").unwrap();
        let out = scoped_addresses(&ep, &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], Scope::Wan)
            .await
            .unwrap();
        assert_eq!(out[0].ip(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(out[0].port(), 80);
    }

    #[test]
    fn parse_variants() {
        let p = parse_endpoint("ws://mesh.example.com/path").unwrap();
        assert_eq!(p.port, 80);
        let p = parse_endpoint("ws://[fd00::1]:8443/").unwrap();
        assert_eq!(p.host, "fd00::1");
        assert_eq!(p.port, 8443);
        assert!(parse_endpoint("https://x/").is_err());
        assert!(parse_endpoint("ws://user:pw@host/").is_err());
    }
}
