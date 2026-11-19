//! Shared helpers for the daemon end-to-end tests. Each test boots real
//! `latticed` processes on loopback and drives them through the local API.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lattice_types::{ChannelPublicKey, Identifier};

/// The identity material `latticed init` produces for a fresh node.
pub struct NodeKeys {
    pub id: Identifier,
    pub channel_key: ChannelPublicKey,
    /// The offline next signing key, printed once by `latticed init`.
    pub next_key: [u8; 32],
}

/// A peer to dial at boot: address, channel key, and expected id.
#[derive(Clone, Copy)]
pub struct PeerSpec<'a> {
    pub addr: &'a str,
    pub channel_key: ChannelPublicKey,
    pub id: Identifier,
}

/// A service to expose on the application socket.
pub struct ServiceSpec {
    pub name: &'static str,
    pub secret: &'static str,
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn latticed() -> &'static str {
    env!("CARGO_BIN_EXE_latticed")
}

pub fn init_node(dir: &Path) -> NodeKeys {
    let out = Command::new(latticed())
        .args(["init", "--dir", dir.to_str().unwrap()])
        .output()
        .expect("latticed init");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let id_text = stdout
        .lines()
        .find_map(|l| l.strip_prefix("node id: "))
        .expect("init prints node id")
        .trim()
        .to_string();
    let id = lattice_proto::text::parse_id(&id_text).expect("node id is a text-form identifier");
    let next_key_hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("next signing key (hex): "))
        .expect("init prints the next signing key exactly once")
        .trim()
        .to_string();
    let next_key: [u8; 32] = hex_decode(&next_key_hex)
        .try_into()
        .expect("next key is 32 bytes");
    let channel_key = ChannelPublicKey::from_bytes(
        std::fs::read(dir.join("channel_key.pub"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    NodeKeys {
        id,
        channel_key,
        next_key,
    }
}

/// Config knobs for a test node. `private` switches the node to private
/// mode and names its gateways (hex ids). `serves` lists the private ids a
/// public node consents to serve as a gateway (spec §3).
pub struct NodeSpec<'a> {
    pub port: u16,
    pub app: &'a Path,
    pub admin: &'a Path,
    pub peer: Option<PeerSpec<'a>>,
    pub services: &'a [ServiceSpec],
    pub private_gateways: Option<Vec<Identifier>>,
    pub serves: Option<Vec<Identifier>>,
    /// Listen addresses. Empty means `127.0.0.1:{port}`.
    pub listen: Vec<String>,
    /// Hive CIDRs to configure (`hive = [...]`).
    pub hive: Vec<String>,
    /// Endpoints to advertise (`advertise = [...]`).
    pub advertise: Vec<String>,
    /// Literal IPs to advertise (`ips = [...]`).
    pub ips: Vec<String>,
}

/// Extra per-node config beyond the defaults, for tests that need a
/// non-default topology.
#[derive(Default, Clone)]
pub struct NodeExtras {
    pub private_gateways: Option<Vec<Identifier>>,
    pub serves: Option<Vec<Identifier>>,
    /// Listen addresses; `{port}` is replaced with the allocated port.
    /// Empty means `127.0.0.1:{port}`.
    pub listen: Vec<String>,
    /// Hive CIDRs to configure.
    pub hive: Vec<String>,
    /// Endpoints to advertise; `{port}` is replaced with the allocated port.
    pub advertise: Vec<String>,
    /// Literal IPs to advertise.
    pub ips: Vec<String>,
    /// Pin the listen port instead of allocating a free one. Used when a
    /// peer must know this node's port before it boots.
    pub port: Option<u16>,
}

pub fn write_config(dir: &Path, spec: &NodeSpec) {
    let roots = match &spec.peer {
        Some(peer) => format!(
            "[[roots]]\naddr = \"{}\"\nchannel_key = \"{}\"\nid = \"{}\"\n",
            peer.addr,
            hex_encode(peer.channel_key.as_ref()),
            hex_encode(peer.id.as_ref()),
        ),
        None => String::new(),
    };
    let services_toml = spec
        .services
        .iter()
        .map(|s| format!("{} = {{ secret = \"{}\" }}", s.name, s.secret))
        .collect::<Vec<_>>()
        .join("\n");
    let (mode, gateways) = match &spec.private_gateways {
        Some(gws) => (
            "private",
            format!(
                "gateways = [{}]\n",
                gws.iter()
                    .map(|g| format!("\"{}\"", hex_encode(g.as_ref())))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        None => ("public", String::new()),
    };
    let serves = match (&spec.serves, &spec.private_gateways) {
        (Some(ids), None) => format!(
            "serves = [{}]\n",
            ids.iter()
                .map(|i| format!("\"{}\"", hex_encode(i.as_ref())))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (Some(_), Some(_)) => panic!("serves is only valid for public nodes"),
        (None, _) => String::new(),
    };
    let port = spec.port.to_string();
    let listen = if spec.listen.is_empty() {
        format!("\"127.0.0.1:{port}\"")
    } else {
        spec.listen
            .iter()
            .map(|a| format!("\"{}\"", a.replace("{port}", &port)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let hive = if spec.hive.is_empty() {
        String::new()
    } else {
        format!(
            "hive = [{}]\n",
            spec.hive
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let advertise = if spec.advertise.is_empty() {
        String::new()
    } else {
        format!(
            "advertise = [{}]\n",
            spec.advertise
                .iter()
                .map(|u| format!("\"{}\"", u.replace("{port}", &port)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let ips = if spec.ips.is_empty() {
        String::new()
    } else {
        format!(
            "ips = [{}]\n",
            spec.ips
                .iter()
                .map(|i| format!("\"{i}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let toml = format!(
        r#"identity_dir = "{dir}"
mode = "{mode}"
listen = [{listen}]
{hive}{advertise}{ips}app_socket = "{app}"
admin_socket = "{admin}"
{gateways}{serves}
[services]
{services_toml}

[limits]
reconcile_interval_secs = 1
republish_min_interval_secs = 0

{roots}"#,
        dir = dir.display(),
        listen = listen,
        hive = hive,
        advertise = advertise,
        ips = ips,
        app = spec.app.display(),
        admin = spec.admin.display(),
    );
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("lattice.toml"))
            .and_then(|mut f| std::io::Write::write_all(&mut f, toml.as_bytes()))
            .unwrap();
    }
}

pub fn start_node(dir: &Path) -> Child {
    Command::new(latticed())
        .args([
            "run",
            "--config",
            dir.join("lattice.toml").to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn latticed")
}

pub struct TestNode {
    pub dir: PathBuf,
    pub port: u16,
    pub app: PathBuf,
    pub admin: PathBuf,
    pub id: Identifier,
    pub channel_key: ChannelPublicKey,
    pub next_key: [u8; 32],
    pub child: Option<Child>,
}

pub fn boot_node(
    tmp: &Path,
    name: &str,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
) -> TestNode {
    boot_node_full(tmp, name, peer, services, None)
}

pub fn boot_node_full(
    tmp: &Path,
    name: &str,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
    private_gateways: Option<Vec<Identifier>>,
) -> TestNode {
    let dir = tmp.join(name);
    let keys = init_node(&dir);
    boot_initialized(
        tmp,
        name,
        dir,
        keys,
        peer,
        services,
        NodeExtras {
            private_gateways,
            ..NodeExtras::default()
        },
    )
}

/// Boot a public node that consents to serve `serves` as a gateway
/// (spec §3, gateway consent). The ids must be known before boot, so the
/// caller pre-creates the private instance's identity with `init_node`.
pub fn boot_node_with_serves(
    tmp: &Path,
    name: &str,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
    serves: Vec<Identifier>,
) -> TestNode {
    let dir = tmp.join(name);
    let keys = init_node(&dir);
    boot_initialized(
        tmp,
        name,
        dir,
        keys,
        peer,
        services,
        NodeExtras {
            serves: Some(serves),
            ..NodeExtras::default()
        },
    )
}

/// Boot a node with explicit per-node extras: listen addresses, hive
/// CIDRs, advertised endpoints and IPs. `{port}` in `listen` and
/// `advertise` entries is replaced with the allocated port. Pass
/// `keys: Some(..)` to boot a node whose identity was pre-created with
/// `init_node` (needed when another node must name this one's id or key
/// before this node boots).
pub fn boot_node_ex(
    tmp: &Path,
    name: &str,
    keys: Option<NodeKeys>,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
    extras: NodeExtras,
) -> TestNode {
    let dir = tmp.join(name);
    let keys = keys.unwrap_or_else(|| init_node(&dir));
    boot_initialized(tmp, name, dir, keys, peer, services, extras)
}

/// Boot a node whose identity was already created with `init_node`
/// (used when another node must name this one's id in its own config
/// before this node boots — e.g. a gateway consenting to serve it).
pub fn boot_node_with_keys(
    tmp: &Path,
    name: &str,
    keys: NodeKeys,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
    private_gateways: Option<Vec<Identifier>>,
) -> TestNode {
    let dir = tmp.join(name);
    boot_initialized(
        tmp,
        name,
        dir,
        keys,
        peer,
        services,
        NodeExtras {
            private_gateways,
            ..NodeExtras::default()
        },
    )
}

fn boot_initialized(
    tmp: &Path,
    name: &str,
    dir: PathBuf,
    keys: NodeKeys,
    peer: Option<PeerSpec<'_>>,
    services: &[ServiceSpec],
    extras: NodeExtras,
) -> TestNode {
    let NodeKeys {
        id,
        channel_key,
        next_key,
    } = keys;
    let app = tmp.join(format!("{name}.app.sock"));
    let admin = tmp.join(format!("{name}.admin.sock"));
    let mut attempt = 0;
    loop {
        attempt += 1;
        let port = extras.port.unwrap_or_else(free_port);
        let spec = NodeSpec {
            port,
            app: &app,
            admin: &admin,
            peer,
            services,
            private_gateways: extras.private_gateways.clone(),
            serves: extras.serves.clone(),
            listen: extras.listen.clone(),
            hive: extras.hive.clone(),
            advertise: extras.advertise.clone(),
            ips: extras.ips.clone(),
        };
        write_config(&dir, &spec);
        let mut child = start_node(&dir);
        // Give the daemon a brief window to fail on bind (the port we just
        // probed can be taken between probe and bind). If it exits during
        // startup, retry with a fresh port instead of waiting 30s for
        // sockets that will never appear.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut early_exit = None;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => {
                    early_exit = Some(status);
                    break;
                }
                Ok(None) => {}
                Err(e) => panic!("wait failed: {e}"),
            }
            if std::os::unix::net::UnixStream::connect(&app).is_ok()
                && std::os::unix::net::UnixStream::connect(&admin).is_ok()
            {
                break; // daemon is up
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        match early_exit {
            Some(status) => {
                eprintln!(
                    "latticed exited during startup ({status}); retrying with a fresh port (attempt {attempt})"
                );
                if attempt >= 5 {
                    panic!("latticed failed to start after {attempt} attempts");
                }
                continue;
            }
            None => {
                return TestNode {
                    dir,
                    port,
                    app,
                    admin,
                    id,
                    channel_key,
                    next_key,
                    child: Some(child),
                };
            }
        }
    }
}

/// Wait until both sockets accept connections (not merely exist).
pub async fn wait_sockets(node: &TestNode) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let app_ok = std::os::unix::net::UnixStream::connect(&node.app).is_ok();
        let admin_ok = std::os::unix::net::UnixStream::connect(&node.admin).is_ok();
        if app_ok && admin_ok {
            return;
        }
        assert!(Instant::now() < deadline, "daemon sockets never came up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl TestNode {
    pub fn restart(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child = Some(start_node(&self.dir));
    }
    pub fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill(); // SIGKILL — no clean shutdown
            let _ = c.wait();
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub async fn wait_for_path(client: &mut lattice_client::Client, id: &Identifier, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match client.lookup(id).await {
            Ok(l) if l.have() && l.path() => return,
            _ => {
                assert!(Instant::now() < deadline, "never learned a path");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

/// Send a message and wait until it is fetched by the recipient's app.
/// Returns the delivery.
pub async fn send_and_fetch(
    sender: &mut lattice_client::Client,
    recipient: &mut lattice_client::Client,
    to: Identifier,
    body: &[u8],
    route: Option<u64>,
    timeout: Duration,
) -> lattice_client::Delivery {
    let mid = sender
        .send(&lattice_client::Send {
            to,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-test".to_vec(),
            body: body.to_vec(),
            exp: None,
            priority: None,
            route,
        })
        .await
        .expect("send");
    let deadline = Instant::now() + timeout;
    loop {
        let batch = recipient.fetch(16).await.expect("fetch");
        if let Some(d) = batch.into_iter().find(|d| d.mid == mid) {
            return d;
        }
        assert!(Instant::now() < deadline, "message never arrived");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
