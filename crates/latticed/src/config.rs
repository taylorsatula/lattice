//! latticed configuration (TOML). Unknown keys are rejected.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where seeds and the KEL live.
    #[serde(default = "default_identity_dir")]
    pub identity_dir: PathBuf,
    /// "public" or "private".
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Listen addresses for the WebSocket transport. Empty = loopback only.
    #[serde(default = "default_listen")]
    pub listen: Vec<SocketAddr>,
    /// CIDRs that make up the hive (informational for now).
    #[serde(default)]
    pub hive: Vec<String>,
    /// Peers to dial at startup.
    #[serde(default)]
    pub roots: Vec<RootConfig>,
    /// Services allowed on the application socket, by name and secret.
    pub services: HashMap<String, ServiceConfig>,
    /// Serve the /status endpoint on the listener (default true).
    #[serde(default = "default_true")]
    pub status: bool,
    /// Path of the application socket (mode 0660).
    #[serde(default = "default_app_socket")]
    pub app_socket: PathBuf,
    /// Path of the admin socket (mode 0600).
    #[serde(default = "default_admin_socket")]
    pub admin_socket: PathBuf,
    /// Endpoints to advertise in our record (public mode). `ws://host[:port]/` URLs.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Gateway node ids (hex, 32 bytes). Required in private mode; forbidden otherwise.
    #[serde(default)]
    pub gateways: Vec<String>,
    /// Envelope/record limits override.
    #[serde(default)]
    pub limits: Limits,
}

fn default_identity_dir() -> PathBuf {
    PathBuf::from("/var/lib/lattice")
}
fn default_mode() -> String {
    "public".into()
}
fn default_listen() -> Vec<SocketAddr> {
    vec!["127.0.0.1:8443".parse().unwrap()]
}
fn default_true() -> bool {
    true
}
fn default_app_socket() -> PathBuf {
    PathBuf::from("/run/lattice/app.sock")
}
fn default_admin_socket() -> PathBuf {
    PathBuf::from("/run/lattice/admin.sock")
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    pub addr: String,
    /// Channel key (hex, 32 bytes). Present → IK dial against this peer.
    pub channel_key: Option<String>,
    /// Node identifier (hex, 32 bytes). Optional; used to route before gossip resolves.
    pub id: Option<String>,
    /// Upgrade path for XX dials when no channel key is known.
    pub path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_custody_allowance")]
    pub custody_allowance: u64,
    #[serde(default = "default_transit_cap")]
    pub transit_cap: u64,
    #[serde(default = "default_inbox_max")]
    pub inbox_max: u64,
    #[serde(default = "default_inbox_max_total")]
    pub inbox_max_total: u64,
    #[serde(default = "default_snow_per_min")]
    pub snow_per_min: f64,
    #[serde(default = "default_sideways_prob")]
    pub sideways_prob: f64,
    #[serde(default)]
    pub waypoint_share: f64,
    /// Anti-entropy (record gossip) interval, seconds.
    #[serde(default = "default_reconcile_interval_secs")]
    pub reconcile_interval_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            custody_allowance: default_custody_allowance(),
            transit_cap: default_transit_cap(),
            inbox_max: default_inbox_max(),
            inbox_max_total: default_inbox_max_total(),
            snow_per_min: default_snow_per_min(),
            sideways_prob: default_sideways_prob(),
            waypoint_share: 0.0,
            reconcile_interval_secs: default_reconcile_interval_secs(),
        }
    }
}

fn default_custody_allowance() -> u64 {
    4 * 1024 * 1024
}
fn default_transit_cap() -> u64 {
    256 * 1024 * 1024
}
fn default_inbox_max() -> u64 {
    1024
}
fn default_inbox_max_total() -> u64 {
    4096
}
fn default_snow_per_min() -> f64 {
    2.0
}
fn default_sideways_prob() -> f64 {
    0.15
}
fn default_reconcile_interval_secs() -> u64 {
    60
}

// Validation ceilings. The defaults are far below these; they exist to catch
// unit mistakes and typos (e.g. 1000000000000 for bytes), not to constrain
// legitimate deployments.
/// Per-upstream-link custody allowance ceiling: 1 GiB (default 4 MiB).
const MAX_CUSTODY_ALLOWANCE: u64 = 1 << 30;
/// Total bytes held in transit ceiling: 64 GiB (default 256 MiB).
const MAX_TRANSIT_CAP: u64 = 64 << 30;
/// Deliveries per service inbox ceiling (default 1024).
const MAX_INBOX_MAX: u64 = 100_000;
/// Deliveries across all service inboxes ceiling (default 4096).
const MAX_INBOX_MAX_TOTAL: u64 = 1_000_000;
/// Dummy-traffic rate ceiling: 1000/minute, ~16 per second (default 2.0).
const MAX_SNOW_PER_MIN: f64 = 1000.0;
/// Anti-entropy interval ceiling: 1 day. Also keeps `now + interval` far
/// from u64 overflow.
const MAX_RECONCILE_INTERVAL_SECS: u64 = 86_400;

/// The config file carries service secrets in plaintext, so it must not be
/// readable by anyone but its owner (and optionally its group, for a
/// root:lattice 0640 deployment). Anything else is refused before the file
/// is read. Checked on every load, not just at first install: a later
/// `chmod` must not silently widen access.
#[cfg(unix)]
fn check_config_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    // Allowed: owner read/write (or read-only), optionally group read,
    // nothing else. 0600, 0640, 0400, 0440.
    const ALLOWED: [u32; 4] = [0o600, 0o640, 0o400, 0o440];
    if !ALLOWED.contains(&mode) {
        return Err(format!(
            "{}: config file mode {mode:04o} is too open; it contains service secrets. \
             Run: chmod 600 {} (owner read/write only) or chmod 640 {} (owner read/write, group read)",
            path.display(),
            path.display(),
            path.display()
        ));
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<Config, String> {
    #[cfg(unix)]
    check_config_mode(path)?;
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.mode != "public" && cfg.mode != "private" {
        return Err(format!(
            "mode must be \"public\" or \"private\", got {:?}",
            cfg.mode
        ));
    }
    if cfg.services.is_empty() {
        return Err("at least one service must be configured".into());
    }
    for (name, svc) in &cfg.services {
        if !valid_service_name(name) {
            return Err(format!(
                "service name {name:?} is invalid: use 1-64 chars of [A-Za-z0-9._-] (no whitespace or control characters)"
            ));
        }
        if svc.secret.len() < 16 {
            return Err(format!(
                "service {name:?}: secret must be at least 16 bytes"
            ));
        }
    }
    if cfg.app_socket == cfg.admin_socket {
        return Err("app_socket and admin_socket must differ".into());
    }
    match cfg.mode.as_str() {
        "public" => {
            if !cfg.gateways.is_empty() {
                return Err("gateways are only valid in private mode".into());
            }
        }
        "private" => {
            if cfg.gateways.is_empty() || cfg.gateways.len() > 3 {
                return Err("private mode requires 1-3 gateways".into());
            }
            for (i, gw) in cfg.gateways.iter().enumerate() {
                decode_hex32(gw).map_err(|e| format!("gateways[{i}]: {e}"))?;
            }
        }
        _ => unreachable!("mode checked above"),
    }
    for (i, ep) in cfg.advertise.iter().enumerate() {
        if !ep.starts_with("ws://") {
            return Err(format!("advertise[{i}] must be a ws:// URL, got {ep:?}"));
        }
        // Full validation (host syntax, port) happens by building the record at startup.
    }
    for (i, cidr) in cfg.hive.iter().enumerate() {
        parse_cidr(cidr).map_err(|e| format!("hive[{i}] {cidr:?}: {e}"))?;
    }
    for (i, root) in cfg.roots.iter().enumerate() {
        root.addr.parse::<std::net::SocketAddr>().map_err(|e| {
            format!(
                "roots[{i}].addr {:?} is not a socket address: {e}",
                root.addr
            )
        })?;
        if root.channel_key.is_none() && root.path.is_none() {
            return Err(format!(
                "roots[{i}] needs either channel_key (IK) or path (XX)"
            ));
        }
        if let Some(k) = &root.channel_key {
            decode_hex32(k).map_err(|e| format!("roots[{i}].channel_key: {e}"))?;
        }
        if let Some(id) = &root.id {
            decode_hex32(id).map_err(|e| format!("roots[{i}].id: {e}"))?;
        }
        if let Some(p) = &root.path {
            lattice_net::validate_upgrade_path(p)
                .map_err(|_| format!("roots[{i}].path {p:?} is not a valid upgrade path"))?;
        }
    }
    for (name, v) in [
        ("snow_per_min", cfg.limits.snow_per_min),
        ("sideways_prob", cfg.limits.sideways_prob),
        ("waypoint_share", cfg.limits.waypoint_share),
    ] {
        if !v.is_finite() {
            return Err(format!("limits.{name} must be finite, got {v}"));
        }
    }
    if !(0.0..=MAX_SNOW_PER_MIN).contains(&cfg.limits.snow_per_min) {
        return Err(format!(
            "limits.snow_per_min must be in [0, {MAX_SNOW_PER_MIN}] (dummy messages per minute), got {}",
            cfg.limits.snow_per_min
        ));
    }
    if cfg.limits.custody_allowance > MAX_CUSTODY_ALLOWANCE {
        return Err(format!(
            "limits.custody_allowance must be <= {MAX_CUSTODY_ALLOWANCE} bytes (1 GiB), got {}",
            cfg.limits.custody_allowance
        ));
    }
    if cfg.limits.transit_cap > MAX_TRANSIT_CAP {
        return Err(format!(
            "limits.transit_cap must be <= {MAX_TRANSIT_CAP} bytes (64 GiB), got {}",
            cfg.limits.transit_cap
        ));
    }
    if cfg.limits.inbox_max > MAX_INBOX_MAX {
        return Err(format!(
            "limits.inbox_max must be <= {MAX_INBOX_MAX} deliveries, got {}",
            cfg.limits.inbox_max
        ));
    }
    if cfg.limits.inbox_max_total > MAX_INBOX_MAX_TOTAL {
        return Err(format!(
            "limits.inbox_max_total must be <= {MAX_INBOX_MAX_TOTAL} deliveries, got {}",
            cfg.limits.inbox_max_total
        ));
    }
    if cfg.limits.reconcile_interval_secs == 0 {
        return Err("limits.reconcile_interval_secs must be >= 1 second".into());
    }
    if cfg.limits.reconcile_interval_secs > MAX_RECONCILE_INTERVAL_SECS {
        return Err(format!(
            "limits.reconcile_interval_secs must be <= {MAX_RECONCILE_INTERVAL_SECS} (1 day), got {}",
            cfg.limits.reconcile_interval_secs
        ));
    }
    for (name, v) in [
        ("sideways_prob", cfg.limits.sideways_prob),
        ("waypoint_share", cfg.limits.waypoint_share),
    ] {
        if !(0.0..=1.0).contains(&v) {
            return Err(format!("limits.{name} must be in [0, 1], got {v}"));
        }
    }
    Ok(())
}

/// Service names flow into event tags and logs; keep them to a conservative
/// ASCII set so they are safe to print and match on.
fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Parse `addr/prefix` CIDR notation. The address may be v4 or v6; the
/// prefix must fit the address family. Host bits need not be zero.
fn parse_cidr(s: &str) -> Result<(), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| "expected CIDR notation `<ip>/<prefix>`".to_string())?;
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("{addr:?} is not an IP address"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("{prefix:?} is not a valid prefix length"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix length {prefix} exceeds {max} for {ip}"));
    }
    Ok(())
}

/// Hex-decode a 32-byte key/id, as printed in documentation and logs.
pub fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).ok_or("odd-length hex")?, 16)
                .map_err(|_| "bad hex".to_string())
        })
        .collect::<Result<Vec<u8>, _>>()?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[services]
mira = { secret = "change-me-0123456789abcdef" }
"#;

    fn validate_str(toml_str: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(toml_str).map_err(|e| format!("parse: {e}"))?;
        validate(&cfg)?;
        Ok(cfg)
    }

    fn with_limits(limits: &str) -> String {
        format!("{BASE}\n[limits]\n{limits}\n")
    }

    fn with_hive(hive: &str) -> String {
        format!("hive = [{hive}]\n{BASE}")
    }

    #[test]
    fn example_config_is_accepted() {
        // The shipped example is world-readable in the repo; the loader
        // refuses that, so copy it to a private temp file first.
        let src = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/lattice.example.toml"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lattice.toml");
        std::fs::copy(src, &path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        load(&path).expect("shipped example config must validate");
    }

    #[cfg(unix)]
    fn load_with_mode(mode: u32) -> Result<Config, String> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lattice.toml");
        std::fs::write(&path, BASE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        load(&path)
    }

    #[cfg(unix)]
    #[test]
    fn config_mode_0600_and_0640_are_accepted() {
        load_with_mode(0o600).expect("0600 must be accepted");
        load_with_mode(0o640).expect("0640 must be accepted");
        load_with_mode(0o400).expect("0400 must be accepted");
        load_with_mode(0o440).expect("0440 must be accepted");
    }

    #[cfg(unix)]
    #[test]
    fn config_mode_group_or_world_accessible_is_refused() {
        for mode in [0o644, 0o604, 0o660, 0o664, 0o666, 0o646, 0o620] {
            let err = load_with_mode(mode).unwrap_err();
            assert!(
                err.contains("chmod 600"),
                "mode {mode:o}: error must name the chmod to run, got: {err}"
            );
        }
    }

    #[test]
    fn minimal_config_is_accepted() {
        validate_str(BASE).expect("minimal config must validate");
    }

    #[test]
    fn rejects_absurd_custody_allowance() {
        let err = validate_str(&with_limits("custody_allowance = 1000000000000")).unwrap_err();
        assert!(err.contains("custody_allowance"), "{err}");
    }

    #[test]
    fn rejects_absurd_transit_cap() {
        let err = validate_str(&with_limits("transit_cap = 1000000000000")).unwrap_err();
        assert!(err.contains("transit_cap"), "{err}");
    }

    #[test]
    fn rejects_absurd_inbox_max() {
        let err = validate_str(&with_limits("inbox_max = 1000000000")).unwrap_err();
        assert!(err.contains("inbox_max"), "{err}");
    }

    #[test]
    fn rejects_absurd_inbox_max_total() {
        let err = validate_str(&with_limits("inbox_max_total = 1000000000")).unwrap_err();
        assert!(err.contains("inbox_max_total"), "{err}");
    }

    #[test]
    fn rejects_zero_reconcile_interval() {
        let err = validate_str(&with_limits("reconcile_interval_secs = 0")).unwrap_err();
        assert!(err.contains("reconcile_interval_secs"), "{err}");
    }

    #[test]
    fn rejects_unbounded_snow_per_min() {
        let err = validate_str(&with_limits("snow_per_min = 1000000.0")).unwrap_err();
        assert!(err.contains("snow_per_min"), "{err}");
    }

    #[test]
    fn accepts_boundary_limits() {
        validate_str(&with_limits(
            "custody_allowance = 1073741824\n\
             transit_cap = 68719476736\n\
             inbox_max = 100000\n\
             inbox_max_total = 1000000\n\
             snow_per_min = 1000.0\n\
             reconcile_interval_secs = 86400",
        ))
        .expect("boundary values must validate");
    }

    #[test]
    fn rejects_garbage_hive_cidr() {
        for bad in [
            "garbage",
            "10.0.0.0",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/8/9",
            "/8",
            "10.0.0.0/",
        ] {
            let err = validate_str(&with_hive(&format!("\"{bad}\""))).unwrap_err();
            assert!(err.contains("hive[0]"), "{bad}: {err}");
        }
    }

    #[test]
    fn accepts_valid_hive_cidrs() {
        let toml_str =
            with_hive("\"10.0.0.0/8\", \"192.168.0.0/16\", \"fd00::/8\", \"2001:db8::/32\"");
        validate_str(&toml_str).expect("valid CIDRs must validate");
    }

    #[test]
    fn rejects_service_names_with_whitespace_or_control_chars() {
        // TOML strings may contain spaces and tabs, so these reach validation.
        for bad in ["my service", "svc\tname", " leading", "trailing "] {
            let toml_str =
                format!("[services]\n\"{bad}\" = {{ secret = \"change-me-0123456789abcdef\" }}\n");
            let err = validate_str(&toml_str).unwrap_err();
            assert!(err.contains("service name"), "{bad:?}: {err}");
        }
        // Other control characters are not TOML-representable; test the predicate.
        for bad in [
            "svc\nname",
            "svc\u{7}name",
            "svc\u{7f}name",
            "",
            "na/me",
            "na:me",
        ] {
            assert!(!valid_service_name(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn accepts_conservative_service_names() {
        for good in ["mira", "my-service", "my_service", "my.service", "Svc123"] {
            let toml_str =
                format!("[services]\n\"{good}\" = {{ secret = \"change-me-0123456789abcdef\" }}\n");
            validate_str(&toml_str).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }
}
