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
    /// Endpoints to advertise in our record (public mode). `wss://host[:port]/` URLs.
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
    #[serde(default = "default_snow_per_min")]
    pub snow_per_min: f64,
    #[serde(default = "default_sideways_prob")]
    pub sideways_prob: f64,
    #[serde(default)]
    pub waypoint_share: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            custody_allowance: default_custody_allowance(),
            transit_cap: default_transit_cap(),
            inbox_max: default_inbox_max(),
            snow_per_min: default_snow_per_min(),
            sideways_prob: default_sideways_prob(),
            waypoint_share: 0.0,
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
fn default_snow_per_min() -> f64 {
    2.0
}
fn default_sideways_prob() -> f64 {
    0.15
}

pub fn load(path: &Path) -> Result<Config, String> {
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
        if name.is_empty() || name.len() > 64 {
            return Err(format!("service name {name:?} is invalid"));
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
        if !ep.starts_with("wss://") && !ep.starts_with("ws://") {
            return Err(format!("advertise[{i}] must be a ws(s):// URL, got {ep:?}"));
        }
        // Full validation (host syntax, port) happens by building the record at startup.
    }
    for (i, root) in cfg.roots.iter().enumerate() {
        if root.channel_key.is_none() && root.path.is_none() {
            return Err(format!(
                "roots[{i}] needs either channel_key (IK) or path (XX)"
            ));
        }
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
