//! End-to-end: two latticed daemons on loopback, message delivered A to B
//! through the full stack (record gossip, routing, custody, local API).

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lattice_client::{Client, DrainRequest, DrainState, UnlinkOutcome};

mod common;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn latticed() -> &'static str {
    env!("CARGO_BIN_EXE_latticed")
}

fn write_config(
    dir: &Path,
    port: u16,
    app_sock: &Path,
    admin_sock: &Path,
    peer: Option<common::PeerSpec<'_>>,
) {
    let roots = match &peer {
        Some(peer) => format!(
            "[[roots]]\naddr = \"{}\"\nchannel_key = \"{}\"\nid = \"{}\"\n",
            peer.addr,
            hex_encode(peer.channel_key.as_ref()),
            hex_encode(peer.id.as_ref()),
        ),
        None => String::new(),
    };
    let toml = format!(
        r#"identity_dir = "{dir}"
mode = "public"
listen = ["127.0.0.1:{port}"]
app_socket = "{app}"
admin_socket = "{admin}"

[services]
test = {{ secret = "test-secret-with-plenty-of-entropy" }}

{roots}"#,
        dir = dir.display(),
        app = app_sock.display(),
        admin = admin_sock.display(),
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

fn start_node(dir: &Path) -> Child {
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

async fn wait_for<F: FnMut() -> bool>(mut f: F, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn two_nodes_deliver_and_drain() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let dir_a = tmp.join("node-a");
    let dir_b = tmp.join("node-b");

    let common::NodeKeys { id: id_a, .. } = common::init_node(&dir_a);
    let common::NodeKeys {
        id: id_b,
        channel_key: ck_b,
        ..
    } = common::init_node(&dir_b);

    let port_a = free_port();
    let port_b = free_port();
    let app_a = tmp.join("a.app.sock");
    let app_b = tmp.join("b.app.sock");
    let admin_a = tmp.join("a.admin.sock");
    let admin_b = tmp.join("b.admin.sock");

    write_config(
        &dir_a,
        port_a,
        &app_a,
        &admin_a,
        Some(common::PeerSpec {
            addr: &format!("127.0.0.1:{port_b}"),
            channel_key: ck_b,
            id: id_b,
        }),
    );
    write_config(&dir_b, port_b, &app_b, &admin_b, None);

    let mut child_b = start_node(&dir_b);
    let mut child_a = start_node(&dir_a);

    wait_for(
        || app_a.exists() && app_b.exists(),
        Duration::from_secs(10),
        "sockets",
    )
    .await;

    // A sends to B; wait until A knows a path to B, then send.
    let mut client_a = Client::connect_app(&app_a, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect A");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match client_a.lookup(&id_b).await {
            Ok(l) if l.have() && l.path() => break,
            _ => {
                assert!(Instant::now() < deadline, "A never learned a path to B");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    let mid = client_a
        .send(&lattice_client::Send {
            to: id_b,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-a".to_vec(),
            body: b"hello from A".to_vec(),
            exp: None,
            priority: None,
            route: Some(2), // direct: the two nodes are directly connected
        })
        .await
        .expect("send");

    // B should fetch the delivery.
    let mut client_b = Client::connect_app(&app_b, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect B");
    let deadline = Instant::now() + Duration::from_secs(30);
    let delivery = loop {
        let batch = client_b.fetch(16).await.expect("fetch");
        if let Some(d) = batch.into_iter().find(|d| d.mid == mid) {
            break d;
        }
        assert!(Instant::now() < deadline, "message never arrived at B");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(delivery.body, b"hello from A");
    assert_eq!(delivery.from, id_a);
    assert_eq!(delivery.fsvc, "test");

    // Ack it away.
    let n = client_b.ack(&[delivery.delivery_id]).await.expect("ack");
    assert_eq!(n, 1);
    assert!(
        client_b
            .fetch(16)
            .await
            .expect("fetch after ack")
            .is_empty()
    );

    // A should observe delivered once B's receipt comes back.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match client_a.status(&mid).await {
            Ok(Some(s)) if s.status == 3 => break, // 3 = delivered
            Ok(other) => {
                assert!(
                    Instant::now() < deadline,
                    "message status never became delivered (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => panic!("status: {e}"),
        }
    }

    // B replies to A. B's link to A is unpinned, so this exercises record-based
    // link attribution on B's side: without it, B cannot route to A at all.
    let mid_back = client_b
        .send(&lattice_client::Send {
            to: id_a,
            tsvc: "test".into(),
            tmbx: b"reply-mbx".to_vec(),
            fmbx: b"from-b".to_vec(),
            body: b"reply from B".to_vec(),
            exp: None,
            priority: None,
            route: Some(2), // direct
        })
        .await
        .expect("send from B");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut got_reply = false;
    while Instant::now() < deadline {
        let batch = client_a.fetch(16).await.expect("fetch A");
        if batch
            .iter()
            .any(|d| d.mid == mid_back && d.body == b"reply from B")
        {
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        got_reply,
        "B's reply to A never arrived (record-based link binding broken?)"
    );

    // Admin: drain B, check state, un-drain.
    let mut admin_b = Client::connect_admin(&admin_b)
        .await
        .expect("admin connect");
    let draining = admin_b
        .drain(DrainRequest::Set(DrainState::Draining))
        .await
        .expect("drain on")
        .draining;
    assert!(draining);
    let draining = admin_b
        .drain(DrainRequest::Query)
        .await
        .expect("drain query")
        .draining;
    assert!(draining);
    let draining = admin_b
        .drain(DrainRequest::Set(DrainState::Serving))
        .await
        .expect("drain off")
        .draining;
    assert!(!draining);
    let info = admin_b.node().await.expect("node info");
    assert_eq!(info.id, id_b);
    assert!(!info.draining);

    // Admin: unlink B's view of A (B never dialed; this may find nothing — just check no crash).
    let _ = admin_b.unlink(&id_a).await;

    let _ = child_a.kill();
    let _ = child_b.kill();
    let _ = child_a.wait();
    let _ = child_b.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------- shared helpers for the extended suite ----------

struct TestNode {
    dir: std::path::PathBuf,
    port: u16,
    app: std::path::PathBuf,
    admin: std::path::PathBuf,
    id: lattice_types::Identifier,
    channel_key: lattice_types::ChannelPublicKey,
    next_key: [u8; 32],
    child: Option<Child>,
}

fn write_config_multi(
    dir: &Path,
    port: u16,
    app: &Path,
    admin: &Path,
    peer: Option<common::PeerSpec<'_>>,
    services: &[(&str, &str)],
) {
    let roots = match &peer {
        Some(peer) => format!(
            "[[roots]]\naddr = \"{}\"\nchannel_key = \"{}\"\nid = \"{}\"\n",
            peer.addr,
            hex_encode(peer.channel_key.as_ref()),
            hex_encode(peer.id.as_ref()),
        ),
        None => String::new(),
    };
    let services_toml = services
        .iter()
        .map(|(name, secret)| format!("{name} = {{ secret = \"{secret}\" }}"))
        .collect::<Vec<_>>()
        .join("\n");
    let toml = format!(
        r#"identity_dir = "{dir}"
mode = "public"
listen = ["127.0.0.1:{port}"]
app_socket = "{app}"
admin_socket = "{admin}"

[services]
{services_toml}

{roots}"#,
        dir = dir.display(),
        app = app.display(),
        admin = admin.display(),
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

fn boot_node(
    tmp: &Path,
    name: &str,
    peer: Option<common::PeerSpec<'_>>,
    services: &[(&str, &str)],
) -> TestNode {
    let dir = tmp.join(name);
    let common::NodeKeys {
        id,
        channel_key,
        next_key,
    } = common::init_node(&dir);
    let app = tmp.join(format!("{name}.app.sock"));
    let admin = tmp.join(format!("{name}.admin.sock"));
    let mut attempt = 0;
    loop {
        attempt += 1;
        let port = free_port();
        write_config_multi(&dir, port, &app, &admin, peer, services);
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
async fn wait_sockets(node: &TestNode) {
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
    fn restart(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child = Some(start_node(&self.dir));
    }
    fn kill9(&mut self) {
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

async fn wait_for_path(client: &mut Client, id: &lattice_types::Identifier, secs: u64) {
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

fn http_get(addr: &str, path: &str) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    buf
}

fn status_accepting(body: &[u8]) -> bool {
    let header_end = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .expect("http response has a body");
    let v = lattice_proto::decode(&body[header_end..]).expect("status body is CBOR");
    lattice_proto::cbor::map_get(&v, 2)
        .and_then(lattice_proto::Value::as_bool)
        .expect("status has accepting flag")
}

#[tokio::test]
async fn drain_flips_status_accepting() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-drain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_sockets(&b).await;

    let addr = format!("127.0.0.1:{}", b.port);
    let before = http_get(&addr, "/status");
    assert!(status_accepting(&before), "fresh node must accept");

    let mut admin = Client::connect_admin(&b.admin)
        .await
        .expect("admin connect");
    let draining = admin
        .drain(DrainRequest::Set(DrainState::Draining))
        .await
        .expect("drain on")
        .draining;
    assert!(draining);
    let during = http_get(&addr, "/status");
    assert!(
        !status_accepting(&during),
        "draining node must report accepting=false"
    );

    let draining = admin
        .drain(DrainRequest::Set(DrainState::Serving))
        .await
        .expect("drain off")
        .draining;
    assert!(!draining);
    let after = http_get(&addr, "/status");
    assert!(status_accepting(&after), "un-drained node must accept");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn drain_persists_across_restart() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-drainpersist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let mut b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_sockets(&b).await;

    let mut admin = Client::connect_admin(&b.admin)
        .await
        .expect("admin connect");
    admin
        .drain(DrainRequest::Set(DrainState::Draining))
        .await
        .expect("drain on");
    drop(admin);

    b.restart();
    wait_sockets(&b).await;
    let mut admin = Client::connect_admin(&b.admin)
        .await
        .expect("admin reconnect");
    let draining = admin
        .drain(DrainRequest::Query)
        .await
        .expect("drain query")
        .draining;
    assert!(draining, "drain flag must survive a restart");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn kill9_restart_redelivers() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-kill9-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // Boot B first so A can dial it.
    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    let a_peer = format!("127.0.0.1:{}", b.port);
    let mut a = boot_node(
        &tmp,
        "a",
        Some(common::PeerSpec {
            addr: &a_peer,
            channel_key: b.channel_key,
            id: b.id,
        }),
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_for(
        || a.app.exists() && b.app.exists(),
        Duration::from_secs(10),
        "sockets",
    )
    .await;

    let mut client_a = Client::connect_app(&a.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect A");
    wait_for_path(&mut client_a, &b.id, 30).await;

    let mid = client_a
        .send(&lattice_client::Send {
            to: b.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-a".to_vec(),
            body: b"survive the kill".to_vec(),
            exp: None,
            priority: None,
            route: Some(2),
        })
        .await
        .expect("send");

    // Kill A before it can finish the exchange; the message is durable in
    // A's store at this point (send returns after the outbound write).
    a.kill9();
    a.restart();
    wait_for(
        || a.app.exists(),
        Duration::from_secs(10),
        "a app socket after restart",
    )
    .await;

    let mut client_b = Client::connect_app(&b.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect B");
    let deadline = Instant::now() + Duration::from_secs(45);
    let copies = loop {
        let batch = client_b.fetch(16).await.expect("fetch");
        let n = batch.iter().filter(|d| d.mid == mid).count();
        if n > 0 {
            break n;
        }
        assert!(
            Instant::now() < deadline,
            "message never arrived after A's restart"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(copies, 1, "exactly one copy must land in B's inbox");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn route_default_delivers() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-route-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    let a_peer = format!("127.0.0.1:{}", b.port);
    let a = boot_node(
        &tmp,
        "a",
        Some(common::PeerSpec {
            addr: &a_peer,
            channel_key: b.channel_key,
            id: b.id,
        }),
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_for(
        || a.app.exists() && b.app.exists(),
        Duration::from_secs(10),
        "sockets",
    )
    .await;

    let mut client_a = Client::connect_app(&a.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect A");
    wait_for_path(&mut client_a, &b.id, 30).await;

    let mid = client_a
        .send(&lattice_client::Send {
            to: b.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-a".to_vec(),
            body: b"default route".to_vec(),
            exp: None,
            priority: None,
            route: None, // default routing
        })
        .await
        .expect("send");

    let mut client_b = Client::connect_app(&b.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect B");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let batch = client_b.fetch(16).await.expect("fetch");
        if batch.iter().any(|d| d.mid == mid) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "default-routed message never arrived"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn events_are_scoped_per_service() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-events-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let services = [
        ("test", "test-secret-with-plenty-of-entropy"),
        ("other", "other-secret-with-plenty-of-entropy"),
    ];
    let b = boot_node(&tmp, "b", None, &services);
    let a_peer = format!("127.0.0.1:{}", b.port);
    let a = boot_node(
        &tmp,
        "a",
        Some(common::PeerSpec {
            addr: &a_peer,
            channel_key: b.channel_key,
            id: b.id,
        }),
        &services,
    );
    wait_for(
        || a.app.exists() && b.app.exists(),
        Duration::from_secs(10),
        "sockets",
    )
    .await;

    let mut a_test = Client::connect_app(&a.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect A/test");
    let mut a_other = Client::connect_app(&a.app, "other", b"other-secret-with-plenty-of-entropy")
        .await
        .expect("connect A/other");
    let mut b_test = Client::connect_app(&b.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect B/test");
    let mut b_other = Client::connect_app(&b.app, "other", b"other-secret-with-plenty-of-entropy")
        .await
        .expect("connect B/other");

    wait_for_path(&mut a_test, &b.id, 30).await;

    // A/test sends to B/test; A/other must see no events; A/test must see status events.
    let mid = a_test
        .send(&lattice_client::Send {
            to: b.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-a".to_vec(),
            body: b"scoped events".to_vec(),
            exp: None,
            priority: None,
            route: Some(2),
        })
        .await
        .expect("send");

    let status_ev = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match a_test.next_event().await {
                Ok(ev) if ev.event == 2 => break ev,
                Ok(_) => continue,
                Err(e) => panic!("event stream failed: {e}"),
            }
        }
    })
    .await
    .expect("sending service must observe a status event");
    assert_eq!(status_ev.event, 2);
    // The other service must not receive it: give the daemon a moment to
    // (not) deliver, then confirm silence.
    let other = tokio::time::timeout(Duration::from_secs(3), a_other.next_event()).await;
    assert!(
        other.is_err(),
        "other service must not observe status events"
    );

    // B/test receives the delivery; B/other must not see the inbox event.
    let inbox_ev = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match b_test.next_event().await {
                Ok(ev) if ev.event == 1 => break ev,
                Ok(_) => continue,
                Err(e) => panic!("event stream failed: {e}"),
            }
        }
    })
    .await
    .expect("receiving service must observe the inbox event");
    assert_eq!(inbox_ev.event, 1);
    let other = tokio::time::timeout(Duration::from_secs(3), b_other.next_event()).await;
    assert!(
        other.is_err(),
        "other service must not observe inbox events"
    );

    let _ = mid;
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn drain_stops_new_accepts() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-drainstop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    let a_peer = format!("127.0.0.1:{}", b.port);
    let a = boot_node(
        &tmp,
        "a",
        Some(common::PeerSpec {
            addr: &a_peer,
            channel_key: b.channel_key,
            id: b.id,
        }),
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_for(
        || a.app.exists() && b.app.exists(),
        Duration::from_secs(10),
        "sockets",
    )
    .await;

    let mut client_a = Client::connect_app(&a.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect A");
    let mut admin_b = Client::connect_admin(&b.admin).await.expect("admin B");
    wait_for_path(&mut client_a, &b.id, 30).await;

    admin_b
        .drain(DrainRequest::Set(DrainState::Draining))
        .await
        .expect("drain B");

    let mid = client_a
        .send(&lattice_client::Send {
            to: b.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-a".to_vec(),
            body: b"must wait".to_vec(),
            exp: None,
            priority: None,
            route: Some(2),
        })
        .await
        .expect("send");

    // While B is draining, the offer is refused; nothing may land in B's inbox.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let mut client_b = Client::connect_app(&b.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect B");
    let batch = client_b.fetch(16).await.expect("fetch");
    assert!(
        batch.iter().all(|d| d.mid != mid),
        "draining node must not accept new custody"
    );
    let status = client_a.status(&mid).await.expect("status");
    assert!(
        !matches!(status, Some(s) if s.status == 3),
        "message must not be delivered while the recipient drains"
    );

    admin_b
        .drain(DrainRequest::Set(DrainState::Serving))
        .await
        .expect("un-drain B");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn sigterm_sets_drain_and_it_persists() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-sigterm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let mut b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_sockets(&b).await;

    // SIGTERM: the daemon must set drain before exiting.
    let pid = b.child.as_ref().unwrap().id();
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match b.child.as_mut().unwrap().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                assert!(Instant::now() < deadline, "daemon did not exit on SIGTERM");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    b.child = None; // already reaped

    // Restart: the drain flag must still be set.
    b.restart();
    wait_sockets(&b).await;
    let mut admin = Client::connect_admin(&b.admin)
        .await
        .expect("admin reconnect");
    let draining = admin
        .drain(DrainRequest::Query)
        .await
        .expect("drain query")
        .draining;
    assert!(draining, "SIGTERM must persist the drain flag");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn unlink_closes_the_connection() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-unlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    let a_peer = format!("127.0.0.1:{}", b.port);
    let a = boot_node(
        &tmp,
        "a",
        Some(common::PeerSpec {
            addr: &a_peer,
            channel_key: b.channel_key,
            id: b.id,
        }),
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_sockets(&a).await;
    wait_sockets(&b).await;

    // Wait until both sides see the link.
    let mut admin_a = Client::connect_admin(&a.admin).await.expect("admin A");
    let mut admin_b = Client::connect_admin(&b.admin).await.expect("admin B");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let info = admin_a.node().await.expect("node A");
        if info.links >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "A never saw the link");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A unlinks B; B must observe the connection drop (its link count falls to 0).
    let removed = admin_a.unlink(&b.id).await.expect("unlink");
    assert!(
        matches!(removed, UnlinkOutcome::Removed),
        "unlink should report a removed link"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let info = admin_b.node().await.expect("node B");
        if info.links == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "B still sees the link after A unlinked"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn rotate_and_abandon_via_admin() {
    let tmp = std::env::temp_dir().join(format!("lattice-e2e-rotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let b = boot_node(
        &tmp,
        "b",
        None,
        &[("test", "test-secret-with-plenty-of-entropy")],
    );
    wait_sockets(&b).await;
    let mut admin = Client::connect_admin(&b.admin)
        .await
        .expect("admin connect");
    let before = admin.node().await.expect("node before");

    // Rotate the signing key; the node must stay up and keep its id.
    // The following key is generated offline; only its commitment is sent.
    let following = lattice_crypto::generate_seed();
    let commitment = lattice_crypto::hash(lattice_crypto::public_key(&following).as_ref());
    let msg = admin
        .rotate(&b.next_key, commitment.as_bytes())
        .await
        .expect("rotate");
    assert!(msg.contains("rotated"), "unexpected rotate reply: {msg}");
    let after = admin.node().await.expect("node after rotate");
    assert_eq!(before.id, after.id, "rotation must not change the node id");

    // Rotate the envelope key; the node must stay up.
    let msg = admin.rotate_envelope().await.expect("rotate envelope");
    assert!(msg.contains("envelope"), "unexpected reply: {msg}");
    let after = admin.node().await.expect("node after envelope rotate");
    assert_eq!(before.id, after.id);

    // Abandon: the node drains and the identity is dead. The current next
    // key is the following key committed to in the rotation above.
    let msg = admin.abandon(following.as_bytes()).await.expect("abandon");
    assert!(msg.contains("abandoned"), "unexpected reply: {msg}");
    let after = admin.node().await.expect("node after abandon");
    assert!(after.draining, "abandoned node must be draining");

    let _ = std::fs::remove_dir_all(&tmp);
}
