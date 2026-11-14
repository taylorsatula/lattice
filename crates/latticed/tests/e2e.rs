//! End-to-end: two latticed daemons on loopback, message delivered A to B
//! through the full stack (record gossip, routing, custody, local API).

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lattice_client::Client;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

fn init_node(dir: &Path) -> ([u8; 32], [u8; 32]) {
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
    let id: [u8; 32] = hex_decode(&id_hex).try_into().unwrap();
    let channel_key: [u8; 32] = std::fs::read(dir.join("channel_key.pub"))
        .unwrap()
        .try_into()
        .unwrap();
    (id, channel_key)
}

fn write_config(
    dir: &Path,
    port: u16,
    app_sock: &Path,
    admin_sock: &Path,
    peer: Option<(&str, [u8; 32], [u8; 32])>,
) {
    let roots = match peer {
        Some((addr, key, id)) => format!(
            "[[roots]]\naddr = \"{addr}\"\nchannel_key = \"{}\"\nid = \"{}\"\n",
            hex_encode(&key),
            hex_encode(&id),
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
    std::fs::write(dir.join("lattice.toml"), toml).unwrap();
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

    let (id_a, _ck_a) = init_node(&dir_a);
    let (id_b, ck_b) = init_node(&dir_b);

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
        Some((&format!("127.0.0.1:{port_b}"), ck_b, id_b)),
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
            Ok(l) if l.have && l.path => break,
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
            Ok(Some((3, _))) => break, // 3 = delivered
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
    let (draining, _) = admin_b.drain(Some(true)).await.expect("drain on");
    assert!(draining);
    let (draining, _) = admin_b.drain(None).await.expect("drain query");
    assert!(draining);
    let (draining, _) = admin_b.drain(Some(false)).await.expect("drain off");
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
