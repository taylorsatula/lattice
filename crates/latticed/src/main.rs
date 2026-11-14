//! latticed: the Lattice daemon.
//!
//! Usage:
//!   latticed init [--dir DIR]     create an identity and write a sample config
//!   latticed run [--config PATH]  run the daemon
//!
//! Secrets: 32-byte raw files in the identity directory (or systemd
//! credentials when $CREDENTIALS_DIRECTORY is set). The daemon refuses to
//! start if key self-tests fail.

#![forbid(unsafe_code)]

mod api;
mod config;
mod keys;
mod runtime;

use std::path::PathBuf;

use lattice_store::Store;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => cmd_init(&args[2..]),
        Some("run") | None => cmd_run(&args[2..]).await,
        Some(other) => {
            eprintln!("unknown subcommand {other:?}; expected `init` or `run`");
            std::process::ExitCode::from(2)
        }
    }
}

fn cmd_init(args: &[String]) -> std::process::ExitCode {
    let mut dir = PathBuf::from("/var/lib/lattice");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" {
            dir = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            eprintln!("unknown flag {}", args[i]);
            return std::process::ExitCode::from(2);
        }
    }
    match keys::init_identity(&dir) {
        Ok(()) => {
            println!("identity written to {}", dir.display());
            if let Ok(Ok(id)) =
                keys::load_identity(&dir).map(|id| lattice_proto::kel::identifier(&id.kel))
            {
                println!(
                    "node id: {}",
                    id.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
            println!("next: create a config, e.g. /etc/lattice/lattice.toml");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("init failed: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Build the record this node will publish and check it passes validation.
fn record_self_test(cfg: &config::Config, identity: &lattice_core::Identity) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let private = cfg.mode == "private";
    let mode = if private {
        lattice_proto::record::Mode::Private
    } else {
        lattice_proto::record::Mode::Public
    };
    let endpoints = if private {
        Vec::new()
    } else {
        cfg.advertise
            .iter()
            .map(|url| lattice_proto::record::Endpoint {
                url: url.clone(),
                ips: Vec::new(),
            })
            .collect()
    };
    let gateways = if private {
        cfg.gateways
            .iter()
            .map(|h| config::decode_hex32(h))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let params = lattice_proto::record::RecordParams {
        kel: identity.kel.clone(),
        seq: 1,
        exp: now + 3600,
        channel_key: lattice_crypto::x25519_public(&identity.channel_seed),
        envelope_key: identity.xwing_public,
        mode,
        scope: lattice_proto::record::Scope::Wan,
        endpoints,
        links: vec![],
        gateways,
        capabilities: 1,
    };
    lattice_proto::record::PeerRecord::build(params, &identity.signing_seed)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn cmd_run(args: &[String]) -> std::process::ExitCode {
    let mut config_path = PathBuf::from("/etc/lattice/lattice.toml");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" {
            config_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            eprintln!("unknown flag {}", args[i]);
            return std::process::ExitCode::from(2);
        }
    }
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let identity = match keys::load_identity(&cfg.identity_dir) {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "key material: {e}. Run `latticed init --dir {}` first.",
                cfg.identity_dir.display()
            );
            return std::process::ExitCode::from(1);
        }
    };
    if let Err(e) = keys::self_test(&identity) {
        eprintln!("key self-test failed: {e}");
        return std::process::ExitCode::from(1);
    }
    if !cfg.hive.is_empty() {
        eprintln!(
            "lattice: note: hive CIDRs are parsed but multicast discovery is not implemented yet; ignoring"
        );
    }
    // Record self-test: the record we will publish must pass validation, or
    // this node is unreachable the moment it goes live. Fail fast at boot.
    if let Err(e) = record_self_test(&cfg, &identity) {
        eprintln!("record self-test failed: {e}");
        return std::process::ExitCode::from(1);
    }
    let store_path = cfg.identity_dir.join("node.redb");
    let store = match lattice_store::RedbStore::open(&store_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("store: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Restore the persisted drain flag. Drain is a maintenance state, not a
    // transient one: an operator who drained a node for maintenance expects
    // it to stay drained across a restart (e.g. after a crash or a package
    // upgrade), not to silently resume accepting custody. Clearing it is an
    // explicit operator action (`latticectl drain off`).
    let draining = Arc::new(std::sync::atomic::AtomicBool::new(
        store.drain_get().unwrap_or(false),
    ));
    let cfg = Arc::new(cfg);

    // Install signal handlers before binding any socket, so SIGTERM/SIGINT
    // at any point after startup is caught and drains before exit. NB:
    // tokio registers the OS handler eagerly in `signal()`, so these must be
    // created here, not inside the future passed to run().
    #[cfg(unix)]
    let shutdown = {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        async move {
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
        }
    };
    #[cfg(not(unix))]
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    // Inbound listener: accept connections, hand peers to the runtime.
    let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<lattice_net::PeerIo>();
    for addr in &cfg.listen {
        let listener_cfg = lattice_net::ListenerConfig {
            channel_seed: identity.channel_seed,
            status_enabled: cfg.status,
            draining: draining.clone(),
            force_under_load: false,
            on_peer: peer_tx.clone(),
        };
        match lattice_net::serve(listener_cfg, vec![*addr]).await {
            Ok((bound, _handle)) => eprintln!("lattice: listening on {bound}"),
            Err(e) => {
                eprintln!("listen on {addr} failed: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    }

    let runtime = runtime::Runtime::new(&cfg, identity, store, now, peer_rx, draining.clone());

    // Dial configured roots at startup.
    for root in &cfg.roots {
        let addr: std::net::SocketAddr = match root.addr.parse() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("root {:?}: invalid socket address", root.addr);
                continue;
            }
        };
        let ik_key = root
            .channel_key
            .as_deref()
            .and_then(|h| config::decode_hex32(h).ok());
        let peer_id = root
            .id
            .as_deref()
            .and_then(|h| config::decode_hex32(h).ok());
        let path = root.path.clone();
        if ik_key.is_some() {
            runtime.spawn_dial(addr.to_string(), ik_key, None, peer_id);
        } else {
            runtime.spawn_dial(addr.to_string(), None, path, peer_id);
        }
    }

    // Bind both sockets before doing anything else; if either fails, exit
    // nonzero rather than run without a local API.
    let app_listener = match api::bind_app(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("app socket {}: {e}", cfg.app_socket.display());
            return std::process::ExitCode::from(1);
        }
    };
    let admin_listener = match api::bind_admin(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("admin socket {}: {e}", cfg.admin_socket.display());
            return std::process::ExitCode::from(1);
        }
    };
    let api_tx = runtime.api_tx();
    let app_broadcast = runtime.app_broadcast.clone();
    let app_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = api::serve_app(app_listener, app_cfg, api_tx.clone(), app_broadcast).await {
            eprintln!("application socket failed: {e}");
        }
    });
    let api_tx2 = runtime.api_tx();
    tokio::spawn(async move {
        if let Err(e) = api::serve_admin(admin_listener, api_tx2).await {
            eprintln!("admin socket failed: {e}");
        }
    });

    runtime.run(shutdown).await;
    std::process::ExitCode::SUCCESS
}
