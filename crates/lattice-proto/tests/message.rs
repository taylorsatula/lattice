use lattice_crypto::{generate_keypair, generate_seed};
use lattice_proto::message::*;
use lattice_proto::{CLOCK_SKEW, MAX_MESSAGE_HORIZON, MESSAGE_BUCKETS, MESSAGE_BUCKETS as BUCKETS};

const NOW: u64 = 1_800_000_000;
const EXP: u64 = NOW + 86_400;

fn envelope_for(from_seed: &[u8; 32], tmbx: &[u8]) -> Envelope {
    Envelope {
        kind: KIND_MESSAGE,
        mid: lattice_crypto::os_bytes::<16>(),
        from: lattice_crypto::public_key(from_seed),
        fsvc: "mira".into(),
        fmbx: b"taylor".to_vec(),
        tsvc: "mira".into(),
        tmbx: tmbx.to_vec(),
        created: NOW,
        body: Some(b"hello".to_vec()),
        reference: None,
        reason: None,
        sig: [0; 64],
    }
}

#[test]
fn direct_roundtrip_full() {
    let from_seed = generate_seed();
    let from_pk = lattice_crypto::public_key(&from_seed);
    let kp = generate_keypair();
    let env = envelope_for(&from_seed, b"sink");
    let dst = lattice_crypto::hash(b"recipient");
    let bytes = Message::build(BuildParams {
        envelope: env.clone(),
        sender_seed: &from_seed,
        recipient_ek: &kp.public,
        real_dst: dst,
        leg: [7u8; 16],
        exp: EXP,
        gateway: None,
        waypoint: None,
    })
    .unwrap();

    let msg = Message::parse(&bytes, NOW).unwrap();
    let opened = msg.open_envelope(&kp.secret).unwrap();
    assert_eq!(opened.from, from_pk);
    assert_eq!(opened.kind, KIND_MESSAGE);
    assert_eq!(opened.body.as_deref(), Some(b"hello".as_slice()));
    assert!(opened.verify_signature(&from_pk, msg.routing_header_bytes()));
}

#[test]
fn waypoint_route_roundtrip() {
    let from_seed = generate_seed();
    let from_pk = lattice_crypto::public_key(&from_seed);
    let recipient_kp = generate_keypair();
    let wp_kp = generate_keypair();
    let recipient_id = lattice_crypto::hash(b"recipient");
    let waypoint_id = lattice_crypto::hash(b"waypoint");

    let env = envelope_for(&from_seed, b"sink");
    let bytes = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &recipient_kp.public,
        real_dst: recipient_id,
        leg: [1u8; 16],
        exp: EXP,
        gateway: None,
        waypoint: Some(WaypointSeal {
            waypoint_id,
            waypoint_ek: wp_kp.public,
            leg: [2u8; 16],
            exp: EXP,
        }),
    })
    .unwrap();

    // Outer hop: parse and open the waypoint layer.
    let msg = Message::parse(&bytes, NOW).unwrap();
    assert_eq!(msg.header.dst, waypoint_id);
    let inner = msg.open_hop_layer(&wp_kp.secret).unwrap();
    let after = msg.into_after_waypoint(inner).unwrap();

    // Second leg: same envelope, header now dst = recipient, no hop layer.
    let msg2 = Message::parse(&after, NOW).unwrap();
    assert_eq!(msg2.header.dst, recipient_id);
    assert!(msg2.hop_layer.is_none());
    let opened = msg2.open_envelope(&recipient_kp.secret).unwrap();
    assert_eq!(opened.from, from_pk);
}

#[test]
fn waypoint_gateway_route_roundtrip() {
    let from_seed = generate_seed();
    let from_pk = lattice_crypto::public_key(&from_seed);
    let recipient_kp = generate_keypair(); // private recipient
    let gateway_kp = generate_keypair();
    let wp_kp = generate_keypair();
    let recipient_id = lattice_crypto::hash(b"private-recipient");
    let gateway_id = lattice_crypto::hash(b"gateway");
    let waypoint_id = lattice_crypto::hash(b"waypoint");

    let env = envelope_for(&from_seed, b"sink");
    let bytes = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &recipient_kp.public,
        real_dst: gateway_id, // routing header names the gateway
        leg: [3u8; 16],
        exp: EXP,
        gateway: Some(GatewaySeal {
            gateway_ek: gateway_kp.public,
            rcpt: recipient_id,
        }),
        waypoint: Some(WaypointSeal {
            waypoint_id,
            waypoint_ek: wp_kp.public,
            leg: [4u8; 16],
            exp: EXP,
        }),
    })
    .unwrap();

    let msg = Message::parse(&bytes, NOW).unwrap();
    // Waypoint opens its layer, learns the gateway route.
    let inner = msg.open_hop_layer(&wp_kp.secret).unwrap();
    let after_wp = msg.into_after_waypoint(inner).unwrap();
    let msg2 = Message::parse(&after_wp, NOW).unwrap();
    assert_eq!(msg2.header.dst, gateway_id);
    // Gateway opens its layer, learns the private recipient.
    let gw = msg2.open_hop_layer(&gateway_kp.secret).unwrap();
    match gw {
        HopLayerPlain::Gateway { rcpt } => assert_eq!(rcpt, recipient_id),
        _ => panic!("expected gateway layer after waypoint"),
    }
    // Final recipient opens the envelope.
    let opened = msg2.open_envelope(&recipient_kp.secret).unwrap();
    assert_eq!(opened.from, from_pk);
}

#[test]
fn gateway_route_roundtrip_no_waypoint() {
    let from_seed = generate_seed();
    let recipient_kp = generate_keypair();
    let gateway_kp = generate_keypair();
    let recipient_id = lattice_crypto::hash(b"private-recipient");
    let gateway_id = lattice_crypto::hash(b"gateway");

    let env = envelope_for(&from_seed, b"sink");
    let bytes = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &recipient_kp.public,
        real_dst: gateway_id,
        leg: [5u8; 16],
        exp: EXP,
        gateway: Some(GatewaySeal {
            gateway_ek: gateway_kp.public,
            rcpt: recipient_id,
        }),
        waypoint: None,
    })
    .unwrap();

    let msg = Message::parse(&bytes, NOW).unwrap();
    let gw = msg.open_hop_layer(&gateway_kp.secret).unwrap();
    match gw {
        HopLayerPlain::Gateway { rcpt } => assert_eq!(rcpt, recipient_id),
        _ => panic!("expected gateway layer"),
    }
    assert!(msg.open_envelope(&recipient_kp.secret).is_ok());
}

#[test]
fn messages_land_in_exact_buckets() {
    let from_seed = generate_seed();
    let kp = generate_keypair();
    let mut sizes = Vec::new();
    for body_len in [1usize, 100, 1500, 7000, 30000] {
        let mut env = envelope_for(&from_seed, b"sink");
        env.body = Some(vec![0xAB; body_len]);
        let bytes = Message::build(BuildParams {
            envelope: env,
            sender_seed: &from_seed,
            recipient_ek: &kp.public,
            real_dst: lattice_crypto::hash(b"r"),
            leg: [9u8; 16],
            exp: EXP,
            gateway: None,
            waypoint: None,
        })
        .unwrap();
        assert!(
            BUCKETS.contains(&bytes.len()),
            "body_len {body_len} -> {}",
            bytes.len()
        );
        sizes.push(bytes.len());
    }
    assert!(sizes.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn oversized_message_refused() {
    let from_seed = generate_seed();
    let kp = generate_keypair();
    let mut env = envelope_for(&from_seed, b"sink");
    env.body = Some(vec![0u8; MESSAGE_BUCKETS[2]]); // way beyond the largest bucket once base64... plain bytes + overhead
    let result = Message::build(BuildParams {
        envelope: env,
        sender_seed: &from_seed,
        recipient_ek: &kp.public,
        real_dst: lattice_crypto::hash(b"r"),
        leg: [9u8; 16],
        exp: EXP,
        gateway: None,
        waypoint: None,
    });
    assert!(result.is_err());
}

#[test]
fn expired_message_rejected_at_parse() {
    let bytes = {
        let from_seed = generate_seed();
        let kp = generate_keypair();
        Message::build(BuildParams {
            envelope: envelope_for(&from_seed, b"sink"),
            sender_seed: &from_seed,
            recipient_ek: &kp.public,
            real_dst: lattice_crypto::hash(b"r"),
            leg: [1u8; 16],
            exp: NOW - 1, // already expired
            gateway: None,
            waypoint: None,
        })
        .unwrap()
    };
    assert!(Message::parse(&bytes, NOW).is_err());
}

#[test]
fn horizon_violation_rejected_at_parse() {
    let from_seed = generate_seed();
    let kp = generate_keypair();
    let bytes = Message::build(BuildParams {
        envelope: envelope_for(&from_seed, b"sink"),
        sender_seed: &from_seed,
        recipient_ek: &kp.public,
        real_dst: lattice_crypto::hash(b"r"),
        leg: [1u8; 16],
        exp: NOW + MAX_MESSAGE_HORIZON + CLOCK_SKEW + 100,
        gateway: None,
        waypoint: None,
    })
    .unwrap();
    assert!(Message::parse(&bytes, NOW).is_err());
}

#[test]
fn tampered_padding_rejected() {
    let from_seed = generate_seed();
    let kp = generate_keypair();
    let mut bytes = Message::build(BuildParams {
        envelope: envelope_for(&from_seed, b"sink"),
        sender_seed: &from_seed,
        recipient_ek: &kp.public,
        real_dst: lattice_crypto::hash(b"r"),
        leg: [1u8; 16],
        exp: EXP,
        gateway: None,
        waypoint: None,
    })
    .unwrap();
    let n = bytes.len();
    bytes[n - 1] = 1;
    assert!(Message::parse(&bytes, NOW).is_err());
}

#[test]
fn wrong_size_rejected() {
    let bytes = vec![0u8; 1000];
    assert!(Message::parse(&bytes, NOW).is_err());
}

#[test]
fn receipt_roundtrip() {
    let kp = generate_keypair();
    let recipient_from = generate_seed();
    let env = Envelope {
        kind: KIND_RECEIPT,
        mid: lattice_crypto::os_bytes::<16>(),
        from: lattice_crypto::public_key(&recipient_from),
        fsvc: "mira".into(),
        fmbx: b"sink".to_vec(),
        tsvc: "mira".into(),
        tmbx: b"taylor".to_vec(),
        created: NOW,
        body: None,
        reference: Some([0x55; 16]),
        reason: None,
        sig: [0; 64],
    };
    let bytes = Message::build(BuildParams {
        envelope: env.clone(),
        sender_seed: &recipient_from,
        recipient_ek: &kp.public,
        real_dst: lattice_crypto::hash(b"original-sender"),
        leg: [6u8; 16],
        exp: EXP,
        gateway: None,
        waypoint: None,
    })
    .unwrap();
    let msg = Message::parse(&bytes, NOW).unwrap();
    let opened = msg.open_envelope(&kp.secret).unwrap();
    assert_eq!(opened.kind, KIND_RECEIPT);
    assert_eq!(opened.reference, Some([0x55; 16]));
}
