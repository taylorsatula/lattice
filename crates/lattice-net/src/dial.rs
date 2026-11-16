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

use crate::client::{DialTarget, PeerContact, connect};
use crate::errors::NetError;
use crate::peer::PeerIo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain WebSocket; confidentiality comes from Noise.
    Ws,
    /// WebSocket over TLS. The TLS session is an opaque outer wrapper: no
    /// certificate trust decisions are made (Noise authenticates the peer);
    /// it exists for reachability through TLS-terminating fronts.
    Wss,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Scheme::Ws => 80,
            Scheme::Wss => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path prefix from the URL, without trailing slashes ("" when none).
    /// The dialer prepends it to the derived upgrade path.
    pub path_prefix: String,
}

impl EndpointUrl {
    /// The value for the `Host` header: the URL's host (bracketed when it is
    /// an IPv6 literal), with `:port` appended when the port is not the
    /// scheme's default.
    pub fn host_header(&self) -> String {
        let bare = match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{}]", self.host),
            _ => self.host.clone(),
        };
        if self.port == self.scheme.default_port() {
            bare
        } else {
            format!("{bare}:{}", self.port)
        }
    }
}

pub fn parse_endpoint(url: &str) -> Result<EndpointUrl, NetError> {
    let (scheme, rest) = url.split_once("://").ok_or(NetError::InvalidInput(
        "endpoint must be a ws:// or wss:// URL",
    ))?;
    let scheme = match scheme {
        "ws" => Scheme::Ws,
        "wss" => Scheme::Wss,
        _ => return Err(NetError::InvalidInput("endpoint scheme must be ws or wss")),
    };
    let (authority, path_and_rest) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(NetError::InvalidInput(
            "endpoint must have a host and no userinfo",
        ));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // [v6]:port
        let end = rest
            .find(']')
            .ok_or(NetError::InvalidInput("unterminated [v6] host"))?;
        let h = &rest[..end];
        h.parse::<std::net::Ipv6Addr>()
            .map_err(|_| NetError::InvalidInput("bad bracketed IPv6 host"))?;
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if after.is_empty() => scheme.default_port(),
            None => return Err(NetError::InvalidInput("trailing data after [v6] host")),
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if p.bytes().any(|b| !b.is_ascii_digit()) {
            return Err(NetError::InvalidInput("invalid port"));
        }
        (h.to_string(), parse_port(p)?)
    } else {
        (authority.to_string(), scheme.default_port())
    };
    if host.is_empty() {
        return Err(NetError::InvalidInput("empty host"));
    }
    let path = path_and_rest.split(['?', '#']).next().unwrap_or("");
    if path_and_rest.contains(['?', '#']) {
        return Err(NetError::InvalidInput(
            "endpoint URL must not carry a query or fragment",
        ));
    }
    let path_prefix = normalize_path_prefix(path)?;
    Ok(EndpointUrl {
        scheme,
        host,
        port,
        path_prefix,
    })
}

fn parse_port(p: &str) -> Result<u16, NetError> {
    let port: u16 = p
        .parse()
        .map_err(|_| NetError::InvalidInput("invalid port"))?;
    if port == 0 {
        return Err(NetError::InvalidInput("port must be non-zero"));
    }
    Ok(port)
}

/// Normalize the URL's path into a prefix for the upgrade request line.
/// The path goes on the request line verbatim, so it is restricted to
/// visible ASCII; trailing slashes are dropped so the derived upgrade
/// path joins cleanly.
fn normalize_path_prefix(path: &str) -> Result<String, NetError> {
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    if !path.starts_with('/') {
        return Err(NetError::InvalidInput("endpoint path must start with /"));
    }
    if !path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(NetError::InvalidInput(
            "endpoint path contains invalid characters",
        ));
    }
    Ok(path.trim_end_matches('/').to_string())
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
            .map_err(NetError::Io)?;
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
        return Err(NetError::NoUsableAddress);
    }
    Ok(allowed
        .into_iter()
        .map(|ip| SocketAddr::new(ip, endpoint.port))
        .collect())
}

/// Connect to an endpoint honoring the record's scope. `expected_ik` is the
/// record's channel key for IK peers; `xx_path` for an XX root contact.
pub async fn connect_scoped(
    channel_seed: &lattice_types::ChannelSeed,
    endpoint: &EndpointUrl,
    record_ips: &[IpAddr],
    scope: Scope,
    ik_channel_key: Option<lattice_types::ChannelPublicKey>,
    xx_path: Option<String>,
) -> Result<PeerIo, NetError> {
    let addrs = scoped_addresses(endpoint, record_ips, scope).await?;
    // Unreachable while `scoped_addresses` errors on an empty list; the
    // variant still says the right thing if that ever changes.
    let mut last_err = NetError::NoUsableAddress;
    for addr in addrs {
        let target = DialTarget {
            addr,
            host: endpoint.host_header(),
            path_prefix: endpoint.path_prefix.clone(),
            tls: endpoint.scheme == Scheme::Wss,
        };
        let contact = match (ik_channel_key, &xx_path) {
            (Some(ck), _) => PeerContact::Ik {
                target,
                channel_key: ck,
            },
            (None, Some(path)) => PeerContact::Xx {
                target,
                path: path.clone(),
            },
            (None, None) => {
                return Err(NetError::InvalidInput(
                    "either a channel key or a path is required",
                ));
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
        assert_eq!(p.scheme, Scheme::Ws);
        assert_eq!(p.path_prefix, "/path");
        let p = parse_endpoint("ws://[fd00::1]:8443/").unwrap();
        assert_eq!(p.host, "fd00::1");
        assert_eq!(p.port, 8443);
        assert_eq!(p.path_prefix, "");
        assert!(parse_endpoint("https://x/").is_err());
        assert!(parse_endpoint("ws://user:pw@host/").is_err());
    }

    #[test]
    fn parse_wss_and_default_ports() {
        let p = parse_endpoint("wss://front.example.com/").unwrap();
        assert_eq!(p.scheme, Scheme::Wss);
        assert_eq!(p.port, 443);
        let p = parse_endpoint("wss://front.example.com:8443/lattice/").unwrap();
        assert_eq!(p.port, 8443);
        assert_eq!(p.path_prefix, "/lattice");
        let p = parse_endpoint("ws://mesh.example.com/").unwrap();
        assert_eq!(p.port, 80);
        // Nested prefixes are kept, trailing slashes trimmed.
        let p = parse_endpoint("wss://front.example.com/a/b/c/").unwrap();
        assert_eq!(p.path_prefix, "/a/b/c");
        // A bare path separator is no prefix at all.
        let p = parse_endpoint("ws://mesh.example.com/").unwrap();
        assert_eq!(p.path_prefix, "");
        // Bracketed IPv6 over wss.
        let p = parse_endpoint("wss://[2001:4860:4860::8888]/").unwrap();
        assert_eq!(p.host, "2001:4860:4860::8888");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_rejects_bad_paths_and_queries() {
        assert!(parse_endpoint("wss://front.example.com/lat tice/").is_err());
        assert!(parse_endpoint("wss://front.example.com/\u{7f}x").is_err());
        assert!(parse_endpoint("wss://front.example.com/?token=abc").is_err());
        assert!(parse_endpoint("wss://front.example.com/#frag").is_err());
        assert!(parse_endpoint("wss://front.example.com/lattice?x=y").is_err());
    }

    #[test]
    fn host_header_uses_url_host_and_default_port_rules() {
        let p = parse_endpoint("wss://front.example.com/").unwrap();
        assert_eq!(p.host_header(), "front.example.com");
        let p = parse_endpoint("wss://front.example.com:8443/").unwrap();
        assert_eq!(p.host_header(), "front.example.com:8443");
        let p = parse_endpoint("ws://mesh.example.com:8080/").unwrap();
        assert_eq!(p.host_header(), "mesh.example.com:8080");
        let p = parse_endpoint("ws://[2001:4860:4860::8888]/").unwrap();
        assert_eq!(p.host_header(), "[2001:4860:4860::8888]");
        let p = parse_endpoint("ws://[2001:4860:4860::8888]:8443/").unwrap();
        assert_eq!(p.host_header(), "[2001:4860:4860::8888]:8443");
    }
}
