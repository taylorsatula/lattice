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
    let id_hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("node id: "))
        .expect("init prints node id")
        .trim()
        .to_string();
    let id = Identifier::from_bytes(hex_decode(&id_hex).try_into().unwrap());
    let channel_key = ChannelPublicKey::from_bytes(
        std::fs::read(dir.join("channel_key.pub"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    NodeKeys { id, channel_key }
}

/// Config knobs for a test node. `private` switches the node to private
/// mode and names its gateways (hex ids).
pub struct NodeSpec<'a> {
    pub port: u16,
    pub app: &'a Path,
    pub admin: &'a Path,
    pub peer: Option<PeerSpec<'a>>,
    pub services: &'a [ServiceSpec],
    pub private_gateways: Option<Vec<Identifier>>,
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
    let toml = format!(
        r#"identity_dir = "{dir}"
mode = "{mode}"
listen = ["127.0.0.1:{port}"]
app_socket = "{app}"
admin_socket = "{admin}"
{gateways}
[services]
{services_toml}

[limits]
reconcile_interval_secs = 1

{roots}"#,
        dir = dir.display(),
        port = spec.port,
        app = spec.app.display(),
        admin = spec.admin.display(),
    );
    std::fs::write(dir.join("lattice.toml"), toml).unwrap();
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
    let NodeKeys { id, channel_key } = init_node(&dir);
    let app = tmp.join(format!("{name}.app.sock"));
    let admin = tmp.join(format!("{name}.admin.sock"));
    let mut attempt = 0;
    loop {
        attempt += 1;
        let port = free_port();
        let spec = NodeSpec {
            port,
            app: &app,
            admin: &admin,
            peer,
            services,
            private_gateways: private_gateways.clone(),
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
            Ok(l) if l.have && l.path => return,
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
