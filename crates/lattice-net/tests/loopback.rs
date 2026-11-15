//! Loopback integration: handshake, frames, cookies, /status, 404 behavior.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::mpsc;

use lattice_net::{PeerContact, connect, serve};
use lattice_proto::frames::Frame;
use lattice_proto::frames::PingFrame;

fn test_seeds() -> (lattice_types::ChannelSeed, lattice_types::ChannelSeed) {
    (
        lattice_types::ChannelSeed::from_bytes([0xA1; 32]),
        lattice_types::ChannelSeed::from_bytes([0xB2; 32]),
    )
}

async fn start_server(
    server_seed: lattice_types::ChannelSeed,
    under_load: bool,
    status: bool,
) -> (
    std::net::SocketAddr,
    mpsc::UnboundedReceiver<lattice_net::PeerIo>,
    Arc<AtomicBool>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let draining = Arc::new(AtomicBool::new(false));
    let cfg = lattice_net::ListenerConfig {
        channel_seed: server_seed,
        status_enabled: status,
        draining: draining.clone(),
        force_under_load: under_load,
        on_peer: tx,
    };
    let (addr, _handle) = serve(cfg, vec!["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    (addr, rx, draining)
}

#[tokio::test]
async fn ik_handshake_and_ping_pong() {
    let (server_seed, client_seed) = test_seeds();
    let server_ck = lattice_crypto::channel_public(&server_seed);
    let (addr, mut peers, _flag) = start_server(server_seed, false, false).await;

    let client = tokio::spawn(async move {
        connect(
            PeerContact::Ik {
                addr,
                channel_key: server_ck,
            },
            &client_seed,
        )
        .await
        .unwrap()
    });

    let mut server_side = peers.recv().await.unwrap();
    let mut client_side = client.await.unwrap();

    // client -> server ping
    client_side
        .send_frame(&Frame::Ping(PingFrame { nonce: 1234 }), None)
        .await
        .unwrap();
    let got = server_side.recv_frame().await.unwrap().unwrap();
    match got {
        Frame::Ping(p) => assert_eq!(p.nonce, 1234),
        other => panic!("expected ping, got {other:?}"),
    }
    // server -> client pong
    server_side
        .send_frame(&Frame::Ping(PingFrame { nonce: 1234 }), None)
        .await
        .unwrap();
    let got = client_side.recv_frame().await.unwrap().unwrap();
    assert!(matches!(got, Frame::Ping(p) if p.nonce == 1234));
}

#[tokio::test]
async fn xx_handshake_works() {
    let (server_seed, client_seed) = test_seeds();
    let client_seed_check = client_seed.clone();
    let path = lattice_net::upgrade_path(&lattice_crypto::channel_public(&server_seed));
    let (addr, mut peers, _flag) = start_server(server_seed.clone(), false, false).await;

    let client = tokio::spawn(async move {
        connect(PeerContact::Xx { addr, path }, &client_seed)
            .await
            .unwrap()
    });
    let mut server_side = peers.recv().await.unwrap();
    let mut client_side = client.await.unwrap();

    // Both sides must see each other's channel static key.
    let client_sk_pub = lattice_crypto::channel_x25519_public(&client_seed_check);
    assert_eq!(server_side.remote_static, client_sk_pub);
    assert_eq!(
        client_side.remote_static,
        lattice_crypto::channel_x25519_public(&server_seed)
    );

    client_side
        .send_frame(&Frame::Ping(PingFrame { nonce: 77 }), None)
        .await
        .unwrap();
    let got = server_side.recv_frame().await.unwrap().unwrap();
    assert!(matches!(got, Frame::Ping(p) if p.nonce == 77));
}

#[tokio::test]
async fn cookie_flow_enforced_under_load() {
    let (server_seed, client_seed) = test_seeds();
    let server_ck = lattice_crypto::channel_public(&server_seed);
    let (addr, mut peers, _flag) = start_server(server_seed, true, false).await;

    let client = tokio::spawn(async move {
        connect(
            PeerContact::Ik {
                addr,
                channel_key: server_ck,
            },
            &client_seed,
        )
        .await
        .unwrap()
    });
    let mut server_side = peers.recv().await.unwrap();
    let mut client_side = client.await.unwrap();
    client_side
        .send_frame(&Frame::Ping(PingFrame { nonce: 55 }), None)
        .await
        .unwrap();
    let got = server_side.recv_frame().await.unwrap().unwrap();
    assert!(matches!(got, Frame::Ping(p) if p.nonce == 55));
}

#[tokio::test]
async fn status_endpoint_and_404() {
    let (server_seed, _client_seed) = test_seeds();
    let (addr, _peers, _flag) = start_server(server_seed.clone(), false, true).await;

    // /status returns CBOR with keys 0..3
    let status = reqwest_get(&format!("http://{addr}/status")).await;
    assert!(
        status.starts_with(b"\xa4"),
        "expected a 4-entry map, got {:?}",
        &status[..2]
    );

    // unknown path -> 404
    let resp = reqwest_get_raw(&format!("http://{addr}/nope")).await;
    assert!(resp.starts_with(b"HTTP/1.1 404"));

    // disabled status -> same 404
    let (addr2, _peers2, _flag2) = start_server(server_seed, false, false).await;
    let resp2 = reqwest_get_raw(&format!("http://{addr2}/status")).await;
    assert!(resp2.starts_with(b"HTTP/1.1 404"));
}

async fn reqwest_get(url: &str) -> Vec<u8> {
    let (host_port, _path) = url
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    let mut stream = tokio::net::TcpStream::connect(host_port).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(
            format!("GET /status HTTP/1.1\r\nhost: {host_port}\r\nconnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    // split headers/body
    let idx = find_subslice(&buf, b"\r\n\r\n").unwrap();
    buf[idx + 4..].to_vec()
}

async fn reqwest_get_raw(url: &str) -> Vec<u8> {
    let (host_port, path) = url
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    let mut stream = tokio::net::TcpStream::connect(host_port).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(
            format!("GET /{path} HTTP/1.1\r\nhost: {host_port}\r\nconnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    buf
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
