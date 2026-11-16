//! Regenerate vectors/vectors.json. Run from the repo root:
//!   cargo run -p lattice-proto --example genvectors
//! Deterministic except the message vector's KEM randomness, which is
//! captured at generation time; committing the output re-pins it.

use lattice_crypto::{hash, public_key};
use lattice_proto::frames::{
    CUSTODY_ACCEPTED, CUSTODY_SEEN, CookieFrame, CustodyFrame, DummyFrame, Frame, InitFrame,
    KelsFrame, PingFrame, Range, RangeBound, ReconcileFrame, RecordEntry, RecordRef, RecordsFrame,
    RespFrame, WantFrame,
};
use lattice_proto::kel::{KeyEvent, ValidatedKel};
use lattice_proto::message::{BuildParams, Envelope, KIND_MESSAGE, Message};
use lattice_proto::record::{Endpoint, Mode, PeerRecord, Scope};
use lattice_types::{
    ChannelSeed, Commitment, Cookie, Hash32, Identifier, LegId, Mac16, MessageId, SigningSeed,
    XWingPublicKey, XWingSecretKey,
};
use std::fs;

const NOW: u64 = 1_800_000_000;

fn main() {
    let mut vectors = Vec::new();

    // --- key events ---
    let seed0 = SigningSeed::from_bytes([1u8; 32]);
    let seed1 = SigningSeed::from_bytes([2u8; 32]);
    let commitment =
        |seed: &SigningSeed| Commitment::from_bytes(hash(public_key(seed).as_ref()).into_bytes());
    let inception = KeyEvent::inception(&seed0, commitment(&seed1));
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

    // --- KEL object ---
    let kel_events = vec![inception.clone(), rotation.clone()];
    let kel = ValidatedKel::validate(kel_events).unwrap();
    let kel_bytes = kel.to_object_bytes().unwrap();
    vectors.push(serde_json::json!({
        "name": "kel_object",
        "kind": "kel_object",
        "hex": hex_of(&kel_bytes),
        "expect": {
            "id": hex_of(kel.identifier()),
            "head_seq": kel.head().seq,
            "head_commitment": hex_of(kel.head().commitment),
            "abandoned": true,
        },
    }));

    // --- peer record (public, WAN) ---
    let envelope_ek = XWingPublicKey::from_bytes([7u8; 1216]);
    let channel_seed = ChannelSeed::from_bytes([9u8; 32]);
    let channel = lattice_crypto::channel_public(&channel_seed);
    let record_kel = ValidatedKel::validate(vec![inception.clone()]).unwrap();
    let record_kel_bytes = record_kel.to_object_bytes().unwrap();
    let id = record_kel.identifier();
    let rec = PeerRecord::build(
        lattice_proto::record::RecordParams {
            kel: record_kel,
            prev_seq: 6,
            now: 7,
            exp: NOW + 86_400,
            channel_key: channel,
            channel_seed,
            envelope_key: envelope_ek,
            mode: Mode::Public,
            scope: Scope::Wan,
            endpoints: vec![Endpoint {
                url: "ws://mesh.example.com/".into(),
                ips: vec!["1.1.1.1".parse().unwrap()],
            }],
            links: vec![],
            gateways: vec![],
            capabilities: 1,
            serves: vec![],
        },
        &seed0,
    )
    .unwrap();
    vectors.push(serde_json::json!({
        "name": "peer_record_public_wan",
        "kind": "peer_record",
        "hex": hex_of(rec.encode()),
        "kel": hex_of(&record_kel_bytes),
        "now": NOW,
        "expect": { "id": hex_of(id), "seq": 7, "scope": 0, "mode": 0, "khs": 0 },
    }));

    // --- frames ---
    let custody = Frame::Custody(CustodyFrame {
        leg: LegId::from_bytes([0xAB; 16]),
        result: CUSTODY_ACCEPTED,
        retry_after: None,
    });
    vectors.push(serde_json::json!({
        "name": "custody_accepted",
        "kind": "frame",
        "hex": hex_of(custody.encode()),
        "expect": { "type": "custody", "result": CUSTODY_ACCEPTED },
    }));
    let seen = Frame::Custody(CustodyFrame {
        leg: LegId::from_bytes([0xAB; 16]),
        result: CUSTODY_SEEN,
        retry_after: None,
    });
    vectors.push(serde_json::json!({
        "name": "custody_seen",
        "kind": "frame",
        "hex": hex_of(seen.encode()),
        "expect": { "type": "custody", "result": CUSTODY_SEEN },
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
        mac1: Mac16::from_bytes([0x11; 16]),
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
        mac1: Mac16::from_bytes([0x11; 16]),
        mac2: Some(Mac16::from_bytes([0x22; 16])),
        padding: vec![0u8; 0],
    });
    vectors.push(serde_json::json!({
        "name": "init_with_cookie_proof",
        "kind": "frame",
        "hex": hex_of(init2.encode()),
        "expect": { "type": "init" },
    }));
    let cookie = Frame::Cookie(CookieFrame {
        cookie: Cookie::from_bytes([0x44; 24]),
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
                lower: Some(RangeBound {
                    id: Identifier::from_bytes([0x01; 32]),
                    scope: 0,
                }),
                upper: Some(RangeBound {
                    id: Identifier::from_bytes([0x7f; 32]),
                    scope: 0,
                }),
                count: 42,
                sum: Hash32::from_bytes([0x55; 32]),
            },
            Range::Entries {
                lower: Some(RangeBound {
                    id: Identifier::from_bytes([0x80; 32]),
                    scope: 1,
                }),
                upper: Some(RangeBound {
                    id: Identifier::from_bytes([0xfe; 32]),
                    scope: 1,
                }),
                entries: vec![RecordEntry {
                    id: Identifier::from_bytes([0x90; 32]),
                    scope: 0,
                    khs: 3,
                    seq: 7,
                    hash_prefix: [0x5A; 8],
                }],
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
        wants: vec![
            RecordRef {
                id: Identifier::from_bytes([0x21; 32]),
                scope: 0,
            },
            RecordRef {
                id: Identifier::from_bytes([0x22; 32]),
                scope: 1,
            },
        ],
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
    let kels = Frame::Kels(KelsFrame {
        kels: vec![kel_bytes.clone()],
    });
    vectors.push(serde_json::json!({
        "name": "kels",
        "kind": "frame",
        "hex": hex_of(kels.encode()),
        "expect": { "type": "kels" },
    }));

    // --- end-to-end message (sealed; KEM randomness captured here) ---
    let recipient_seed = [3u8; 32];
    let recipient_sk = XWingSecretKey::from_bytes(recipient_seed);
    let recipient_ek = lattice_crypto::xwing_public_key(&recipient_sk);
    let from_seed = SigningSeed::from_bytes([2u8; 32]);
    let env = Envelope {
        kind: KIND_MESSAGE,
        mid: MessageId::from_bytes([0x42; 16]),
        from: Identifier::from_bytes(public_key(&from_seed).into_bytes()),
        fsvc: "mira".into(),
        fmbx: b"taylor".to_vec(),
        tsvc: "mira".into(),
        tmbx: b"sink".to_vec(),
        created: NOW,
        body: Some(b"vector payload".to_vec()),
        reference: None,
        reason: None,
        sig: lattice_types::Signature::from_bytes([0u8; 64]),
    };
    let msg_bytes = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &recipient_ek,
        real_dst: Identifier::from_bytes([0x77; 32]),
        leg: LegId::from_bytes([0x11; 16]),
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
            "sender": hex(public_key(&from_seed).as_ref()),
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
