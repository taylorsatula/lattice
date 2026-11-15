//! Verifies vectors/vectors.json. Regenerate with:
//!   cargo run -p lattice-proto --example genvectors
//! The file is generated from the implementation and serves as a regression
//! anchor across refactors and languages; independent ground truth for the
//! crypto lives in vectors/xwing-kat.json and the RFC 8949 checks in cbor.rs.

use lattice_crypto::XWingSecretKey;
use lattice_proto::frames::Frame;
use lattice_proto::kel::KeyEvent;
use lattice_proto::message::{Envelope, KIND_MESSAGE, Message};
use lattice_proto::record::PeerRecord;

use std::fs;

fn vectors() -> Vec<serde_json::Value> {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/vectors.json"
    ))
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn bhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn all_vectors() {
    for v in vectors() {
        let name = v["name"].as_str().unwrap().to_string();
        let bytes = bhex(v["hex"].as_str().unwrap());
        match v["kind"].as_str().unwrap() {
            "key_event" => {
                let ev = KeyEvent::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(ev.seq, v["expect"]["seq"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    hex(ev.commitment().as_ref()),
                    v["expect"]["commitment"]
                        .as_str()
                        .unwrap_or(hex(ev.commitment().as_ref()).as_str()),
                    "{name}"
                );
                assert_eq!(ev.encode(), bytes, "{name}: re-encode mismatch");
            }
            "peer_record" => {
                let now = v["now"].as_u64().unwrap();
                let (rec, _) = PeerRecord::from_bytes(&bytes, now, None)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    hex(rec.id.as_ref()),
                    v["expect"]["id"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(rec.seq, v["expect"]["seq"].as_u64().unwrap());
                assert_eq!(rec.encode(), bytes, "{name}: re-encode mismatch");
            }
            "frame" => {
                let f = Frame::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(f.encode(), bytes, "{name}: re-encode mismatch");
            }
            "message" => {
                let now = v["now"].as_u64().unwrap();
                let msg = Message::parse(&bytes, now).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    bytes.len(),
                    v["expect"]["bucket"].as_u64().unwrap() as usize
                );
                assert_eq!(
                    hex(msg.header.leg.as_ref()),
                    v["expect"]["leg"].as_str().unwrap()
                );
                assert_eq!(
                    hex(msg.header.dst.as_ref()),
                    v["expect"]["dst"].as_str().unwrap()
                );
                let secret = XWingSecretKey::from_bytes(
                    bhex(v["expect"]["recipient_seed"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                );
                let env: Envelope = msg
                    .open_envelope(&secret)
                    .unwrap_or_else(|e| panic!("{name}: open: {e}"));
                assert_eq!(env.kind, KIND_MESSAGE);
                assert_eq!(
                    env.body.as_deref().unwrap(),
                    v["expect"]["body_utf8"].as_str().unwrap().as_bytes()
                );
                assert_eq!(
                    hex(env.from.as_ref()),
                    v["expect"]["sender"].as_str().unwrap()
                );
                let sender_pk = lattice_types::SigningPublicKey::from_bytes(
                    bhex(v["expect"]["sender"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                );
                assert!(env.verify_signature(&sender_pk, msg.routing_header_bytes()));
            }
            other => panic!("{name}: unknown kind {other}"),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Every single-byte corruption of a signed object must be rejected.
/// Covers the record and both key events plus the message (whose bucket
/// invariant, padding check, AEAD and signature all gate parsing/opening).
#[test]
fn single_byte_flips_are_rejected() {
    let vectors = vectors();
    for v in &vectors {
        let name = v["name"].as_str().unwrap();
        let bytes = bhex(v["hex"].as_str().unwrap());
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            let parsed = match v["kind"].as_str().unwrap() {
                "peer_record" => {
                    PeerRecord::from_bytes(&bad, v["now"].as_u64().unwrap(), None).map(|_| ())
                }
                "key_event" => KeyEvent::from_bytes(&bad).and_then(|ev| {
                    if ev.verify_signature() {
                        Ok(())
                    } else {
                        Err(lattice_proto::ProtoError::BadSignature)
                    }
                }),
                "message" => {
                    let now = v["now"].as_u64().unwrap();
                    let seed: [u8; 32] = bhex(v["expect"]["recipient_seed"].as_str().unwrap())
                        .try_into()
                        .unwrap();
                    let sk = XWingSecretKey::from_bytes(seed);
                    let sender_pk = lattice_types::SigningPublicKey::from_bytes(
                        bhex(v["expect"]["sender"].as_str().unwrap())
                            .try_into()
                            .unwrap(),
                    );
                    (|| {
                        let msg = Message::parse(&bad, now)?;
                        let env = msg
                            .open_envelope(&sk)
                            .map_err(|_| lattice_proto::ProtoError::Invalid("open failed"))?;
                        if !env.verify_signature(&sender_pk, msg.routing_header_bytes()) {
                            return Err(lattice_proto::ProtoError::BadSignature);
                        }
                        Ok(())
                    })()
                }
                _ => continue,
            };
            assert!(
                parsed.is_err(),
                "{name}: single-byte flip at offset {i} was accepted"
            );
        }
    }
}
