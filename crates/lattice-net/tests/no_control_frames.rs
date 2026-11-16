//! Regression test for the no-control-frames posture: a non-binary WebSocket
//! frame from a peer tears the link down, and no control frame (Pong/Close)
//! is ever emitted by us in response. tungstenite 0.30 cannot be configured
//! to suppress its automatic Pong/Close replies, so the guarantee is that we
//! never touch the socket again after a non-binary frame arrives.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use lattice_net::handshake::{Pending, encode_handshake_frame};
use lattice_net::upgrade_path;
use lattice_proto::frames::{Frame, InitFrame, PingFrame, RespFrame};

#[tokio::test]
async fn non_binary_frame_tears_down_without_pong() {
    let server_seed = lattice_types::ChannelSeed::from_bytes([0xA1; 32]);
    let client_seed = lattice_types::ChannelSeed::from_bytes([0xB2; 32]);
    let server_ck = lattice_crypto::channel_public(&server_seed);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let draining = Arc::new(AtomicBool::new(false));
    let cfg = lattice_net::ListenerConfig {
        channel_seed: server_seed,
        status_enabled: false,
        draining: draining.clone(),
        force_under_load: false,
        on_peer: tx,
    };
    let served = lattice_net::serve(cfg, vec!["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let addr = served.addr;

    // Raw client: complete the IK handshake by hand so we can inject a
    // WebSocket-level Ping afterwards.
    let path = upgrade_path(&server_ck);
    let prologue = lattice_net::handshake::prologue(&path);
    let url = format!("ws://{addr}{path}");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let mut hs = Pending::initiator_ik(&client_seed, &server_ck, &prologue).unwrap();
    let msg1 = hs.write_message(&[]).unwrap();
    let mac1 = lattice_net::cookie::mac1(&server_ck, &msg1);
    let init = Frame::Init(InitFrame {
        noise_msg: msg1,
        mac1,
        mac2: None,
        padding: vec![],
    });
    let bytes = encode_handshake_frame(&init).unwrap();
    ws.send(Message::Binary(Bytes::from(bytes))).await.unwrap();
    let resp = ws.next().await.unwrap().unwrap();
    let Message::Binary(resp_bytes) = resp else {
        panic!("expected binary resp")
    };
    let value = lattice_proto::decode(&resp_bytes).unwrap();
    let Frame::Resp(RespFrame { noise_msg, .. }) = Frame::from_value(&value).unwrap() else {
        panic!("expected resp frame")
    };
    hs.read_message(&noise_msg).unwrap();

    let mut server_side = rx.recv().await.unwrap();

    // Inject a WebSocket-level Ping; the server must not answer it.
    ws.send(Message::Ping(Bytes::from_static(b"probe")))
        .await
        .unwrap();

    // The Ping must tear the link down: recv_frame reports end-of-stream.
    let got = server_side.recv_frame().await;
    assert!(matches!(got, Ok(None)), "expected Ok(None), got {got:?}");

    // After the teardown, send_frame must refuse without touching the wire.
    let send = server_side
        .send_frame(&Frame::Ping(PingFrame { nonce: 7 }), None)
        .await;
    assert!(matches!(send, Err(lattice_net::NetError::Closed)));

    // close() must not emit a Close handshake either.
    server_side.close().await;

    // The raw client must observe EOF (or a clean end) and never a Pong.
    let mut saw_pong = false;
    let mut saw_close = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Pong(_)))) => saw_pong = true,
            Ok(Some(Ok(Message::Close(_)))) => saw_close = true,
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => break,
        }
    }
    assert!(!saw_pong, "server emitted a Pong");
    assert!(!saw_close, "server emitted a Close frame");
}
