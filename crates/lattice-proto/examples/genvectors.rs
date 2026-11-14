//! Regenerate vectors/vectors.json. Run from the repo root:
//!   cargo run -p lattice-proto --example genvectors
//! Deterministic except the message vector's KEM randomness, which is
//! captured at generation time; committing the output re-pins it.

use lattice_crypto::{hash, public_key};
use lattice_proto::frames::*;
use lattice_proto::kel::KeyEvent;
use lattice_proto::message::*;
use lattice_proto::record::*;
use lattice_proto::{Value, encode};
use std::fs;

const NOW: u64 = 1_800_000_000;

fn main() {
    let mut vectors = Vec::new();

    // --- key events ---
    let seed0 = [1u8; 32];
    let seed1 = [2u8; 32];
    let inception = KeyEvent::inception(&seed0, hash(&public_key(&seed1)));
    let rotation = KeyEvent::rotation(&inception, &seed1, None);
    vectors.push(serde_json::json!({
        "name": "key_event_inception",
        "kind": "key_event",
        "hex": hex_of(inception.encode()),
        "expect": { "seq": 0, "kind": "inception", "commitment": hex_of(inception.commitment()) },
    }));
    vectors.push(serde_json::json!({
        "name": "key_event_rotation_abandons",
        "kind": "key_event",
        "hex": hex_of(rotation.encode()),
        "expect": { "seq": 1, "kind": "rotation", "prev": hex_of(inception.commitment()) },
    }));

    // --- peer record (public, WAN) ---
    let envelope_ek = [7u8; 1216];
    let channel = [9u8; 32];
    let kel = vec![inception.clone()];
    let id = lattice_proto::kel::identifier(&kel).unwrap();
    let rec = PeerRecord::build(
        lattice_proto::record::RecordParams {
            kel,
            seq: 7,
            exp: NOW + 86_400,
            channel_key: channel,
            envelope_key: envelope_ek,
            mode: Mode::Public,
            scope: Scope::Wan,
            endpoints: vec![Endpoint {
                url: "wss://mesh.example.com/".into(),
                ips: vec!["1.1.1.1".parse().unwrap()],
            }],
            links: vec![],
            gateways: vec![],
            capabilities: 1,
        },
        &seed0,
    )
    .unwrap();
    vectors.push(serde_json::json!({
        "name": "peer_record_public_wan",
        "kind": "peer_record",
        "hex": hex_of(rec.encode()),
        "now": NOW,
        "expect": { "id": hex_of(id), "seq": 7, "scope": 0, "mode": 0 },
    }));

    // --- frames ---
    let custody = Frame::Custody(CustodyFrame {
        leg: [0xAB; 16],
        result: CUSTODY_ACCEPTED,
        retry_after: None,
    });
    vectors.push(serde_json::json!({
        "name": "custody_accepted",
        "kind": "frame",
        "hex": hex_of(custody.encode()),
        "expect": { "type": "custody", "result": CUSTODY_ACCEPTED },
    }));
    let dummy = Frame::Dummy(DummyFrame { echo: true });
    vectors.push(serde_json::json!({
        "name": "dummy_echo",
        "kind": "frame",
        "hex": hex_of(dummy.encode()),
        "expect": { "type": "dummy", "echo": true },
    }));
    let ping = Frame::Ping(PingFrame { nonce: 0xDEADBEEF });
    vectors.push(serde_json::json!({
        "name": "ping_nonce",
        "kind": "frame",
        "hex": hex_of(ping.encode()),
        "expect": { "type": "ping", "nonce": 0xDEADBEEFu64 },
    }));
    let init = Frame::Init(InitFrame {
        noise_msg: vec![0xE1; 32],
        mac1: [0x11; 16],
        mac2: None,
        padding: vec![0u8; 64],
    });
    vectors.push(serde_json::json!({
        "name": "init_ik_no_mac2",
        "kind": "frame",
        "hex": hex_of(init.encode()),
        "expect": { "type": "init" },
    }));
    let init2 = Frame::Init(InitFrame {
        noise_msg: vec![0xE1; 32],
        mac1: [0x11; 16],
        mac2: Some([0x22; 16]),
        padding: vec![0u8; 0],
    });
    vectors.push(serde_json::json!({
        "name": "init_with_cookie_proof",
        "kind": "frame",
        "hex": hex_of(init2.encode()),
        "expect": { "type": "init" },
    }));
    let cookie = Frame::Cookie(CookieFrame {
        nonce: [0x33; 16],
        encrypted_cookie: vec![0x44; 64],
        padding: vec![0u8; 8],
    });
    vectors.push(serde_json::json!({
        "name": "cookie_reply",
        "kind": "frame",
        "hex": hex_of(cookie.encode()),
        "expect": { "type": "cookie" },
    }));
    let resp = Frame::Resp(RespFrame {
        noise_msg: vec![0xE2; 48],
        padding: vec![0u8; 8],
    });
    vectors.push(serde_json::json!({
        "name": "resp",
        "kind": "frame",
        "hex": hex_of(resp.encode()),
        "expect": { "type": "resp" },
    }));
    let reconcile = Frame::Reconcile(ReconcileFrame {
        ranges: vec![
            Range::Fingerprint {
                lower: ([0x01; 32], 0),
                upper: ([0x7f; 32], 0),
                count: 42,
                sum: [0x55; 32],
            },
            Range::Entries {
                lower: ([0x80; 32], 1),
                upper: ([0xfe; 32], 1),
                entries: vec![([0x90; 32], 0, 7)],
            },
        ],
    });
    vectors.push(serde_json::json!({
        "name": "reconcile_mixed",
        "kind": "frame",
        "hex": hex_of(reconcile.encode()),
        "expect": { "type": "reconcile" },
    }));
    let want = Frame::Want(WantFrame {
        wants: vec![([0x21; 32], 0), ([0x22; 32], 1)],
    });
    vectors.push(serde_json::json!({
        "name": "want",
        "kind": "frame",
        "hex": hex_of(want.encode()),
        "expect": { "type": "want" },
    }));
    let records = Frame::Records(RecordsFrame {
        records: vec![b"record-a".to_vec(), b"record-b".to_vec()],
    });
    vectors.push(serde_json::json!({
        "name": "records",
        "kind": "frame",
        "hex": hex_of(records.encode()),
        "expect": { "type": "records" },
    }));
    let wary = Frame::Wary(WaryFrame {
        ids: vec![[0x51; 32]],
        exp: 1_800_100_000,
    });
    vectors.push(serde_json::json!({
        "name": "wary",
        "kind": "frame",
        "hex": hex_of(wary.encode()),
        "expect": { "type": "wary" },
    }));

    // --- end-to-end message (sealed; KEM randomness captured here) ---
    let recipient_seed = [3u8; 32];
    let recipient_sk = lattice_crypto::XWingSecretKey::from_bytes(recipient_seed);
    let recipient_ek = recipient_sk.public_key();
    let from_seed = [2u8; 32];
    let env = Envelope {
        kind: KIND_MESSAGE,
        mid: [0x42; 16],
        from: public_key(&from_seed),
        fsvc: "mira".into(),
        fmbx: b"taylor".to_vec(),
        tsvc: "mira".into(),
        tmbx: b"sink".to_vec(),
        created: NOW,
        body: Some(b"vector payload".to_vec()),
        reference: None,
        reason: None,
        sig: [0u8; 64],
    };
    let msg_bytes = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &recipient_ek,
        real_dst: [0x77; 32],
        leg: [0x11; 16],
        exp: NOW + 86_400,
        gateway: None,
        waypoint: None,
    })
    .unwrap();
    vectors.push(serde_json::json!({
        "name": "message_direct",
        "kind": "message",
        "hex": hex(&msg_bytes),
        "now": NOW,
        "expect": {
            "bucket": msg_bytes.len(),
            "leg": hex(&[0x11u8; 16]),
            "dst": hex(&[0x77u8; 32]),
            "recipient_seed": hex(&recipient_seed),
            "sender": hex(&public_key(&from_seed)),
            "body_utf8": "vector payload",
        },
    }));

    fs::create_dir_all("vectors").unwrap();
    fs::write(
        "vectors/vectors.json",
        serde_json::to_string_pretty(&vectors).unwrap(),
    )
    .unwrap();
    eprintln!("wrote {} vectors", vectors.len());
}

fn hex_of(b: impl AsRef<[u8]>) -> String {
    hex(b.as_ref())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// silence unused import in some build configs
#[allow(dead_code)]
fn _t(_: Value) {}
#[allow(dead_code)]
fn _u(_: &Value) {
    let _ = encode;
}
