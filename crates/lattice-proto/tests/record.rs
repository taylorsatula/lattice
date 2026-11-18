use lattice_crypto::generate_seed;
use lattice_proto::kel::{KeyEvent, ValidatedKel};
use lattice_proto::record::*;
use lattice_proto::{CLOCK_SKEW, MAX_RECORD_HORIZON};
use lattice_types::{
    ChannelPublicKey, ChannelSeed, Commitment, Identifier, SigningSeed, XWingPublicKey,
};

fn commitment(bytes: &[u8]) -> Commitment {
    Commitment::from_bytes(lattice_crypto::hash(bytes).into_bytes())
}

const NOW: u64 = 1_800_000_000;

struct Fixture {
    seed: SigningSeed,
    next_seed: SigningSeed,
    kel: Vec<KeyEvent>,
    envelope: XWingPublicKey,
    channel: ChannelPublicKey,
    channel_seed: ChannelSeed,
}

impl Fixture {
    fn validated_kel(&self) -> ValidatedKel {
        ValidatedKel::validate(self.kel.clone()).unwrap()
    }

    fn params(&self) -> RecordParams {
        RecordParams {
            kel: self.validated_kel(),
            prev_seq: 0,
            now: 1,
            exp: NOW + 86_400,
            channel_key: self.channel,
            channel_seed: self.channel_seed.clone(),
            envelope_key: self.envelope,
            mode: Mode::Public,
            scope: Scope::Wan,
            endpoints: vec![Endpoint {
                url: "ws://mesh.example.com/".into(),
                ips: vec![],
            }],
            links: vec![],
            gateways: vec![],
            capabilities: 0,
            serves: vec![],
        }
    }
}

fn fixture() -> Fixture {
    let seed = generate_seed();
    let next_seed = generate_seed();
    let channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let kel = vec![KeyEvent::inception(
        &seed,
        commitment(lattice_crypto::public_key(&next_seed).as_ref()),
    )];
    let channel = lattice_crypto::channel_public(&channel_seed);
    Fixture {
        seed,
        next_seed,
        kel,
        envelope: XWingPublicKey::from_bytes([7u8; 1216]),
        channel,
        channel_seed,
    }
}

fn public_record(f: &Fixture) -> PeerRecord {
    PeerRecord::build(f.params(), &f.seed).unwrap()
}

#[test]
fn public_record_roundtrip() {
    let f = fixture();
    let rec = public_record(&f);
    let bytes = rec.encode();
    assert!(bytes.len() <= 3072);
    let kel = f.validated_kel();
    let parsed = PeerRecord::from_bytes(&bytes, NOW, &kel).unwrap();
    assert_eq!(parsed.id, rec.id);
    assert_eq!(parsed.seq, 1);
    assert_eq!(parsed.khs, 0);
    assert_eq!(parsed.khc, kel.head().commitment);
    assert_eq!(parsed.k, kel.head().current_key);
    assert_eq!(parsed.kel_head().seq, 0);
}

#[test]
fn seq_is_max_of_prev_plus_one_and_now() {
    let f = fixture();
    // prev_seq + 1 wins when it exceeds now.
    let mut params = f.params();
    params.prev_seq = 41;
    params.now = 10;
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    assert_eq!(rec.seq, 42);
    // now wins when it exceeds prev_seq + 1.
    let mut params = f.params();
    params.prev_seq = 41;
    params.now = 1_800_000_000;
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    assert_eq!(rec.seq, 1_800_000_000);
}

#[test]
fn expired_record_rejected() {
    let f = fixture();
    let mut rec = public_record(&f);
    rec.exp = NOW - 10;
    let bytes = rec.encode(); // signature now invalid, but expiry is checked first
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&bytes, NOW, &kel).is_err());
}

#[test]
fn far_future_expiry_rejected() {
    let f = fixture();
    let mut rec = public_record(&f);
    rec.exp = NOW + MAX_RECORD_HORIZON + CLOCK_SKEW + 100;
    let bytes = rec.encode();
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&bytes, NOW, &kel).is_err());
}

#[test]
fn private_record_with_private_endpoints_rejected() {
    let f = fixture();
    // Building refuses it outright.
    let mut params = f.params();
    params.mode = Mode::Private;
    params.endpoints = vec![Endpoint {
        url: "ws://x.example/".into(),
        ips: vec![],
    }];
    params.gateways = vec![Identifier::from_bytes([1u8; 32])];
    assert!(PeerRecord::build(params, &f.seed).is_err());
    // And a private record with gateways builds and validates.
    let mut params = f.params();
    params.mode = Mode::Private;
    params.endpoints = vec![];
    params.gateways = vec![Identifier::from_bytes([1u8; 32])];
    let ok = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&ok.encode(), NOW, &kel).is_ok());
}

#[test]
fn wan_record_rejects_private_endpoint_ip() {
    let f = fixture();
    // build() now rejects this too (boot-time record self-test relies on it).
    let mut params = f.params();
    params.endpoints = vec![Endpoint {
        url: "ws://mesh.example.com/".into(),
        ips: vec!["192.168.1.10".parse().unwrap()],
    }];
    assert!(PeerRecord::build(params, &f.seed).is_err());
}

#[test]
fn hive_record_allows_private_endpoint_ip() {
    let f = fixture();
    let mut params = f.params();
    params.scope = Scope::Hive;
    params.endpoints = vec![Endpoint {
        url: "ws://hive.local/".into(),
        ips: vec!["192.168.1.10".parse().unwrap()],
    }];
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&rec.encode(), NOW, &kel).is_ok());
}

#[test]
fn signature_tampering_rejected() {
    let f = fixture();
    let rec = public_record(&f);
    let mut bytes = rec.encode();
    let n = bytes.len();
    bytes[n - 10] ^= 1; // inside the signature
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&bytes, NOW, &kel).is_err());
}

#[test]
fn equivocation_detection() {
    let f = fixture();
    let a = public_record(&f);
    let mut params = f.params();
    params.capabilities = 42;
    let signed = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    let a_v = PeerRecord::from_bytes(&a.encode(), NOW, &kel).unwrap();
    let signed_v = PeerRecord::from_bytes(&signed.encode(), NOW, &kel).unwrap();
    assert!(is_equivocation(
        &a_v,
        &a.encode(),
        &signed_v,
        &signed.encode()
    ));
}

#[test]
fn record_order_total_order() {
    use std::cmp::Ordering;
    let f = fixture();
    let base = public_record(&f);
    let mut higher_khs = base.clone();
    higher_khs.khs = base.khs + 1;
    let mut higher_seq = base.clone();
    higher_seq.seq = base.seq + 1;
    // khs dominates seq.
    assert_eq!(record_order(&higher_khs, &higher_seq), Ordering::Greater);
    assert_eq!(record_order(&higher_seq, &higher_khs), Ordering::Less);
    // equal khs: seq decides.
    assert_eq!(record_order(&higher_seq, &base), Ordering::Greater);
    assert_eq!(record_order(&base, &higher_seq), Ordering::Less);
    // equal (khs, seq): the lower hash wins.
    let a = base.clone();
    let mut b = base.clone();
    b.capabilities = 42;
    let ord_ab = record_order(&a, &b);
    let ord_ba = record_order(&b, &a);
    assert_eq!(ord_ab, ord_ba.reverse());
    assert_ne!(ord_ab, Ordering::Equal);
    // The winner has the lower hash.
    let winner = if ord_ab == Ordering::Greater { &a } else { &b };
    let loser = if ord_ab == Ordering::Greater { &b } else { &a };
    assert!(record_hash(&winner.encode()) < record_hash(&loser.encode()));
}

#[test]
fn record_citing_wrong_kel_rejected() {
    let f = fixture();
    let rec = public_record(&f);
    let bytes = rec.encode();
    // A different, valid KEL for a different identity.
    let other_seed = generate_seed();
    let other_next = generate_seed();
    let other_kel = ValidatedKel::validate(vec![KeyEvent::inception(
        &other_seed,
        commitment(lattice_crypto::public_key(&other_next).as_ref()),
    )])
    .unwrap();
    assert!(PeerRecord::from_bytes(&bytes, NOW, &other_kel).is_err());
}

#[test]
fn record_citing_older_head_rejected() {
    // A record citing head sn 0 is rejected once the held KEL has advanced.
    let f = fixture();
    let rec = public_record(&f);
    let bytes = rec.encode();
    let rotated = KeyEvent::rotation(&f.kel[0], &f.next_seed, None);
    let mut events = f.kel.clone();
    events.push(rotated);
    let advanced = ValidatedKel::validate(events).unwrap();
    assert!(PeerRecord::from_bytes(&bytes, NOW, &advanced).is_err());
}

fn abandoned_fixture() -> Fixture {
    // The inception commits to `next_seed`; the abandonment rotation must
    // be signed by that key.
    let seed = generate_seed();
    let next_seed = generate_seed();
    let channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let inception = KeyEvent::inception(
        &seed,
        commitment(lattice_crypto::public_key(&next_seed).as_ref()),
    );
    let abandonment = KeyEvent::rotation(&inception, &next_seed, None);
    let channel = lattice_crypto::channel_public(&channel_seed);
    Fixture {
        seed,
        next_seed,
        kel: vec![inception, abandonment],
        envelope: XWingPublicKey::from_bytes([7u8; 1216]),
        channel,
        channel_seed,
    }
}

#[test]
fn record_citing_abandoned_kel_rejected() {
    // A record whose KEL head is an abandonment is not accepted (spec §3);
    // the KEL object is the only carrier of an abandonment.
    let f = abandoned_fixture();
    let mut params = f.params();
    params.prev_seq = 1;
    let rec = PeerRecord::build(params, &f.next_seed).unwrap();
    let kel = f.validated_kel();
    assert!(kel.is_abandoned());
    assert!(PeerRecord::from_bytes(&rec.encode(), NOW, &kel).is_err());
}

#[test]
fn serves_roundtrip_and_limits() {
    let f = fixture();
    let mut params = f.params();
    params.serves = vec![
        Identifier::from_bytes([1; 32]),
        Identifier::from_bytes([2; 32]),
    ];
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    let parsed = PeerRecord::from_bytes(&rec.encode(), NOW, &kel).unwrap();
    assert_eq!(parsed.serves.len(), 2);

    // More than 16 distinct ids is rejected at build time.
    let mut params = f.params();
    params.serves = (0..17u8).map(|i| Identifier::from_bytes([i; 32])).collect();
    assert!(PeerRecord::build(params, &f.seed).is_err());

    // Duplicate ids are rejected.
    let mut params = f.params();
    params.serves = vec![Identifier::from_bytes([1; 32]); 2];
    assert!(PeerRecord::build(params, &f.seed).is_err());

    // Private records may not carry serves.
    let mut params = f.params();
    params.mode = Mode::Private;
    params.endpoints = vec![];
    params.gateways = vec![Identifier::from_bytes([9; 32])];
    params.serves = vec![Identifier::from_bytes([1; 32])];
    assert!(PeerRecord::build(params, &f.seed).is_err());
}

#[test]
fn record_size_limit_is_3kb() {
    assert_eq!(lattice_proto::RECORD_MAX, 3072);
}

#[test]
fn wss_endpoint_builds_and_validates() {
    let f = fixture();
    let mut params = f.params();
    params.endpoints = vec![Endpoint {
        url: "wss://front.example.com/lattice/".into(),
        ips: vec![],
    }];
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    let parsed = PeerRecord::from_bytes(&rec.encode(), NOW, &kel).unwrap();
    assert_eq!(parsed.endpoints[0].url, "wss://front.example.com/lattice/");
}

#[test]
fn bracketed_ipv6_endpoint_builds_and_validates() {
    let f = fixture();
    for url in [
        "ws://[2001:4860:4860::8888]/",
        "ws://[2001:4860:4860::8888]:8443/",
        "wss://[2001:4860:4860::8888]/",
    ] {
        let mut params = f.params();
        params.endpoints = vec![Endpoint {
            url: url.into(),
            ips: vec![],
        }];
        let rec = PeerRecord::build(params, &f.seed).unwrap_or_else(|e| panic!("{url}: {e:?}"));
        let kel = f.validated_kel();
        PeerRecord::from_bytes(&rec.encode(), NOW, &kel).unwrap_or_else(|e| panic!("{url}: {e:?}"));
    }
}

#[test]
fn bracketed_ipv6_private_rejected_in_wan_accepted_in_hive() {
    let f = fixture();
    let mut params = f.params();
    params.endpoints = vec![Endpoint {
        url: "ws://[fd00::1]:8443/".into(),
        ips: vec![],
    }];
    assert!(PeerRecord::build(params, &f.seed).is_err());
    let mut params = f.params();
    params.scope = Scope::Hive;
    params.endpoints = vec![Endpoint {
        url: "ws://[fd00::1]:8443/".into(),
        ips: vec![],
    }];
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    assert!(PeerRecord::from_bytes(&rec.encode(), NOW, &kel).is_ok());
}

#[test]
fn bracketed_ipv6_malformed_rejected() {
    let f = fixture();
    for url in [
        "ws://[2001:4860:4860::8888",         // unterminated
        "ws://[not-an-ip]/",                  // not an IPv6 literal
        "ws://[2001:4860:4860::8888]x/",      // trailing garbage
        "ws://[2001:4860:4860::8888]:0/",     // port zero
        "ws://[2001:4860:4860::8888]:99999/", // port out of range
        "ws://2001:4860:4860::8888/",         // bare IPv6 must be bracketed
    ] {
        let mut params = f.params();
        params.endpoints = vec![Endpoint {
            url: url.into(),
            ips: vec![],
        }];
        assert!(
            PeerRecord::build(params, &f.seed).is_err(),
            "{url} must be rejected"
        );
    }
}

#[test]
fn endpoint_ips_roundtrip_through_record() {
    let f = fixture();
    let mut params = f.params();
    params.endpoints = vec![Endpoint {
        url: "ws://mesh.example.com/".into(),
        ips: vec![
            "1.2.3.4".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ],
    }];
    let rec = PeerRecord::build(params, &f.seed).unwrap();
    let kel = f.validated_kel();
    let parsed = PeerRecord::from_bytes(&rec.encode(), NOW, &kel).unwrap();
    assert_eq!(
        parsed.endpoints[0].ips,
        vec![
            "1.2.3.4".parse::<std::net::IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ]
    );
}

#[test]
fn wss_scheme_required_exactly() {
    let f = fixture();
    for url in [
        "http://mesh.example.com/",
        "wssx://mesh.example.com/",
        "WSS://mesh.example.com/",
    ] {
        let mut params = f.params();
        params.endpoints = vec![Endpoint {
            url: url.into(),
            ips: vec![],
        }];
        assert!(
            PeerRecord::build(params, &f.seed).is_err(),
            "{url} must be rejected"
        );
    }
}
