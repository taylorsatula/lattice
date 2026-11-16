//! latticed: the Lattice daemon.
//!
//! Usage:
//!   latticed init [--dir DIR] [--next-key-out PATH]
//!                               create an identity and write a sample config
//!   latticed run [--config PATH]  run the daemon
//!
//! Secrets: 32-byte raw files in the identity directory (or systemd
//! credentials when $CREDENTIALS_DIRECTORY is set). The next signing key is
//! never written into the identity directory: `init` writes it to
//! `--next-key-out` (outside the identity directory) or prints it once to
//! stdout, and the directory stores only its BLAKE3 commitment. The daemon
//! refuses to start if a `next_signing_seed` file is present. The daemon
//! refuses to start if key self-tests fail.

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
    let mut next_key_out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("--dir needs a value");
                return std::process::ExitCode::from(2);
            };
            dir = PathBuf::from(v);
            i += 2;
        } else if args[i] == "--next-key-out" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("--next-key-out needs a value");
                return std::process::ExitCode::from(2);
            };
            next_key_out = Some(PathBuf::from(v));
            i += 2;
        } else {
            eprintln!("unknown flag {}", args[i]);
            return std::process::ExitCode::from(2);
        }
    }
    match keys::init_identity(&dir, next_key_out.as_deref()) {
        Ok(outcome) => {
            println!("identity written to {}", dir.display());
            if let Ok(Ok(id)) =
                keys::load_identity(&dir).map(|id| lattice_proto::kel::identifier(&id.kel))
            {
                println!("node id: {}", hex(id.as_ref()));
            }
            match &outcome.next_key_path {
                Some(path) => {
                    println!(
                        "next signing key written to {} (mode 0600); move it to offline storage. The daemon keeps only its commitment.",
                        path.display()
                    );
                }
                None => {
                    println!(
                        "WARNING: the next signing key is shown below exactly once. Store it offline (e.g. a USB drive or a password manager); the daemon does not keep a copy."
                    );
                    println!(
                        "next signing key (hex): {}",
                        hex(outcome.next_key.as_bytes())
                    );
                }
            }
            println!(
                "next key commitment (hex): {}",
                hex(outcome.next_key_commitment.as_bytes())
            );
            println!("next: create a config, e.g. /etc/lattice/lattice.toml");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("init failed: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Lowercase hex, no separators.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build the record this node will publish and check it passes validation.
fn record_self_test(cfg: &config::Config, identity: &lattice_core::Identity) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
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
            .map(|h| config::decode_hex32(h).map(lattice_types::Identifier::from_bytes))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let params = lattice_proto::record::RecordParams {
        kel: identity.kel.clone(),
        seq: 1,
        exp: now + 3600,
        channel_key: lattice_crypto::channel_public(&identity.channel_seed),
        channel_seed: identity.channel_seed.clone(),
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

/// Compare the stored own record (if any) against the loaded secrets.
/// Catches a store that disagrees with the identity directory — e.g. the
/// identity was re-initialized without clearing the store — before the
/// node publishes or honors a record carrying keys it does not hold.
/// Absent record is fine: first boot publishes it.
///
/// The envelope key may match either the current key or a retired key
/// still inside its grace period: an envelope rotation rewrites
/// `envelope_seed` before the republished record reaches the store, so a
/// crash in between leaves the store advertising the previous key. The
/// channel key has no rotation path, so it must always match exactly.
fn verify_stored_own_record(
    store: &lattice_store::RedbStore,
    identity: &lattice_core::Identity,
) -> Result<(), String> {
    use lattice_store::Store;
    let id = identity.id();
    let Some(stored) = store
        .record_get(&id, lattice_proto::record::Scope::Wan)
        .map_err(|e| format!("read own record: {e}"))?
    else {
        return Ok(());
    };
    // Expiry is not checked: an expired own record is still evidence about
    // which keys the store holds, and the node republishes on refresh.
    let record = lattice_proto::record::PeerRecord::from_bytes_unchecked_time(&stored.bytes, None)
        .map_err(|e| format!("stored own record does not validate: {e}"))?;
    let want_channel = lattice_crypto::channel_public(&identity.channel_seed);
    if record.channel_key != want_channel {
        return Err(
            "stored own record's channel key does not match the loaded channel seed; \
             the store and the identity directory disagree"
                .into(),
        );
    }
    let envelope_matches = record.envelope_key == identity.xwing_public
        || identity
            .retired_xwing
            .iter()
            .any(|r| lattice_crypto::xwing_public_key(&r.secret) == record.envelope_key);
    if !envelope_matches {
        return Err(
            "stored own record's envelope key matches neither the loaded envelope key nor any \
             retired key; the store and the identity directory disagree"
                .into(),
        );
    }
    Ok(())
}

/// Load and verify the configuration and identity: parse the config, load
/// the identity, run the key self-test and the record self-test. On failure
/// the reason is printed and the exit code to return is handed back.
fn load_and_verify(
    config_path: &std::path::Path,
) -> Result<(config::Config, lattice_core::Identity), std::process::ExitCode> {
    let cfg = config::load(config_path).map_err(|e| {
        eprintln!("config: {e}");
        std::process::ExitCode::from(1)
    })?;
    let identity = keys::load_identity(&cfg.identity_dir).map_err(|e| {
        if cfg.identity_dir.join("signing_seed").exists() {
            // The identity exists but failed to load (e.g. a stray
            // next_signing_seed, or corrupt key material): re-initializing
            // would destroy it, so don't suggest that.
            eprintln!("key material: {e}");
        } else {
            eprintln!(
                "key material: {e}. Run `latticed init --dir {}` first.",
                cfg.identity_dir.display()
            );
        }
        std::process::ExitCode::from(1)
    })?;
    if let Err(e) = keys::self_test(&identity) {
        eprintln!("key self-test failed: {e}");
        return Err(std::process::ExitCode::from(1));
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
        return Err(std::process::ExitCode::from(1));
    }
    Ok((cfg, identity))
}

/// Open the store and read the persisted drain flag. Refuses to start if
/// the flag cannot be read: a node that cannot tell whether the operator
/// drained it must not take custody, and a store that cannot serve this
/// read is not one to run on.
fn open_store(
    cfg: &config::Config,
) -> Result<(lattice_store::RedbStore, bool), std::process::ExitCode> {
    let store_path = cfg.identity_dir.join("node.redb");
    let store = lattice_store::RedbStore::open(&store_path).map_err(|e| {
        eprintln!("store: {e}");
        std::process::ExitCode::from(1)
    })?;
    // Restore the persisted drain flag. Drain is a maintenance state, not a
    // transient one: an operator who drained a node for maintenance expects
    // it to stay drained across a restart (e.g. after a crash or a package
    // upgrade), not to silently resume accepting custody. Clearing it is an
    // explicit operator action (`latticectl drain off`).
    let drain_flag = store.drain_get().map_err(|e| {
        eprintln!(
            "store: reading the drain flag failed: {e}. Refusing to start: \
             the drain flag is the maintenance safety hatch and must not fail open. \
             Inspect or restore the store, then retry."
        );
        std::process::ExitCode::from(1)
    })?;
    Ok((store, drain_flag.is_draining()))
}

/// Bind the inbound listeners from the config, handing accepted peers to
/// `peer_tx`.
async fn bind_listeners(
    cfg: &config::Config,
    identity: &lattice_core::Identity,
    draining: &Arc<std::sync::atomic::AtomicBool>,
    peer_tx: &tokio::sync::mpsc::UnboundedSender<lattice_net::PeerIo>,
) -> Result<(), std::process::ExitCode> {
    for addr in &cfg.listen {
        let listener_cfg = lattice_net::ListenerConfig {
            channel_seed: identity.channel_seed.clone(),
            status_enabled: cfg.status,
            draining: draining.clone(),
            force_under_load: false,
            on_peer: peer_tx.clone(),
        };
        match lattice_net::serve(listener_cfg, vec![*addr]).await {
            Ok(served) => eprintln!("lattice: listening on {}", served.addr),
            Err(e) => {
                eprintln!("listen on {addr} failed: {e}");
                return Err(std::process::ExitCode::from(1));
            }
        }
    }
    Ok(())
}

async fn cmd_run(args: &[String]) -> std::process::ExitCode {
    let mut config_path = PathBuf::from("/etc/lattice/lattice.toml");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("--config needs a value");
                return std::process::ExitCode::from(2);
            };
            config_path = PathBuf::from(v);
            i += 2;
        } else {
            eprintln!("unknown flag {}", args[i]);
            return std::process::ExitCode::from(2);
        }
    }
    let (cfg, identity) = match load_and_verify(&config_path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let (store, drain_flag) = match open_store(&cfg) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(e) = verify_stored_own_record(&store, &identity) {
        eprintln!(
            "stored own record: {e}. Refusing to start: the store and the identity directory disagree; move node.redb aside or restore the matching identity."
        );
        return std::process::ExitCode::from(1);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let draining = Arc::new(std::sync::atomic::AtomicBool::new(drain_flag));
    let cfg = Arc::new(cfg);

    // Install signal handlers before binding any socket, so SIGTERM/SIGINT
    // at any point after startup is caught and drains before exit. NB:
    // tokio registers the OS handler eagerly in `signal()`, so these must be
    // created here, not inside the future passed to run().
    #[cfg(unix)]
    let shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = {
        use tokio::signal::unix::{SignalKind, signal};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => Box::pin(async move {
                tokio::select! {
                    _ = term.recv() => {},
                    _ = int.recv() => {},
                }
            }),
            (term, int) => {
                if term.is_err() {
                    eprintln!("lattice: failed to install SIGTERM handler");
                }
                if int.is_err() {
                    eprintln!("lattice: failed to install SIGINT handler");
                }
                return std::process::ExitCode::FAILURE;
            }
        }
    };
    #[cfg(not(unix))]
    let shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(async {
            let _ = tokio::signal::ctrl_c().await;
        });

    // Inbound listener: accept connections, hand peers to the runtime.
    let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<lattice_net::PeerIo>();
    if let Err(code) = bind_listeners(&cfg, &identity, &draining, &peer_tx).await {
        return code;
    }

    let mut runtime =
        match runtime::Runtime::new(&cfg, identity, store, now, peer_rx, draining.clone()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("node init: {e}");
                return std::process::ExitCode::from(1);
            }
        };

    // Register configured roots; the runtime dials them now and redials
    // with backoff until a link is up (and again if it drops later).
    let roots: Vec<runtime::RootSpec> = cfg
        .roots
        .iter()
        .filter_map(|root| {
            let addr: std::net::SocketAddr = match root.addr.parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("root {:?}: invalid socket address", root.addr);
                    return None;
                }
            };
            let ik_key = root
                .channel_key
                .as_deref()
                .and_then(|h| config::decode_hex32(h).ok())
                .map(lattice_types::ChannelPublicKey::from_bytes);
            let peer_id = root
                .id
                .as_deref()
                .and_then(|h| config::decode_hex32(h).ok())
                .map(lattice_types::Identifier::from_bytes);
            Some(runtime::RootSpec {
                addr,
                ik_key,
                path: root.path.clone(),
                peer_id,
            })
        })
        .collect();
    runtime.set_roots(roots);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "latticed-main-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn own_record_bytes(
        identity: &lattice_core::Identity,
        channel_seed: lattice_types::ChannelSeed,
        envelope_key: lattice_types::XWingPublicKey,
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let params = lattice_proto::record::RecordParams {
            kel: identity.kel.clone(),
            seq: 1,
            exp: now + 3600,
            channel_key: lattice_crypto::channel_public(&channel_seed),
            channel_seed,
            envelope_key,
            mode: lattice_proto::record::Mode::Public,
            scope: lattice_proto::record::Scope::Wan,
            endpoints: vec![],
            links: vec![],
            gateways: vec![],
            capabilities: 1,
        };
        lattice_proto::record::PeerRecord::build(params, &identity.signing_seed)
            .unwrap()
            .encode()
    }

    fn store_own_record(
        dir: &std::path::Path,
        identity: &lattice_core::Identity,
        bytes: &[u8],
    ) -> lattice_store::RedbStore {
        use lattice_store::Store;
        let mut store = lattice_store::RedbStore::open(dir.join("node.redb")).unwrap();
        store
            .record_put(&identity.id(), lattice_proto::record::Scope::Wan, bytes, 0)
            .unwrap();
        store
    }

    fn fresh_identity(dir: &std::path::Path) -> lattice_core::Identity {
        keys::init_identity(dir, None).unwrap();
        keys::load_identity(dir).unwrap()
    }

    #[test]
    fn stored_own_record_absent_is_accepted() {
        let dir = temp_dir("own-record-absent");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let store = lattice_store::RedbStore::open(dir.join("node.redb")).unwrap();
        verify_stored_own_record(&store, &identity).expect("no stored record is fine");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_own_record_matching_identity_is_accepted() {
        let dir = temp_dir("own-record-ok");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let bytes = own_record_bytes(
            &identity,
            identity.channel_seed.clone(),
            identity.xwing_public,
        );
        let store = store_own_record(&dir, &identity, &bytes);
        verify_stored_own_record(&store, &identity).expect("matching record must pass");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_own_record_with_foreign_channel_key_is_rejected() {
        let dir = temp_dir("own-record-channel");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let foreign_seed = lattice_types::ChannelSeed::from_bytes([9u8; 32]);
        let bytes = own_record_bytes(&identity, foreign_seed, identity.xwing_public);
        let store = store_own_record(&dir, &identity, &bytes);
        let err = verify_stored_own_record(&store, &identity).unwrap_err();
        assert!(err.contains("channel key"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_own_record_with_foreign_envelope_key_is_rejected() {
        let dir = temp_dir("own-record-envelope");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let foreign = lattice_crypto::generate_keypair();
        let bytes = own_record_bytes(&identity, identity.channel_seed.clone(), foreign.public);
        let store = store_own_record(&dir, &identity, &bytes);
        let err = verify_stored_own_record(&store, &identity).unwrap_err();
        assert!(err.contains("envelope key"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_own_record_with_retired_envelope_key_is_accepted() {
        // Crash window: envelope rotated on disk, record not yet republished.
        let dir = temp_dir("own-record-retired");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let old_envelope = identity.xwing_public;
        let bytes = own_record_bytes(&identity, identity.channel_seed.clone(), old_envelope);
        let store = store_own_record(&dir, &identity, &bytes);
        drop(store);
        keys::rotate_envelope_key(&dir, 3600).unwrap();
        let rotated = keys::load_identity(&dir).unwrap();
        assert_ne!(rotated.xwing_public, old_envelope);
        assert_eq!(rotated.retired_xwing.len(), 1);
        let store = lattice_store::RedbStore::open(dir.join("node.redb")).unwrap();
        verify_stored_own_record(&store, &rotated)
            .expect("record carrying the retired envelope key must pass");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_own_record_garbage_is_rejected() {
        let dir = temp_dir("own-record-garbage");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = fresh_identity(&dir);
        let store = store_own_record(&dir, &identity, b"not a record");
        let err = verify_stored_own_record(&store, &identity).unwrap_err();
        assert!(err.contains("does not validate"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
