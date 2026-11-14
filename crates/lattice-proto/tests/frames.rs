use lattice_proto::CLOCK_SKEW;
use lattice_proto::frames::*;

#[test]
fn custody_roundtrip() {
    let f = Frame::Custody(CustodyFrame {
        leg: [7u8; 16],
        result: CUSTODY_ACCEPTED,
        retry_after: None,
    });
    let bytes = f.encode();
    assert_eq!(Frame::from_bytes(&bytes).unwrap(), f);
    let busy = Frame::Custody(CustodyFrame {
        leg: [7; 16],
        result: CUSTODY_BUSY,
        retry_after: Some(30),
    });
    assert_eq!(Frame::from_bytes(&busy.encode()).unwrap(), busy);
}

#[test]
fn offer_roundtrip() {
    let f = Frame::Offer(OfferFrame {
        message: vec![0xAA; 1984],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
}

#[test]
fn custody_result_out_of_range_rejected() {
    let bytes = Frame::Custody(CustodyFrame {
        leg: [7; 16],
        result: 0,
        retry_after: None,
    })
    .encode();
    let v = lattice_proto::decode(&bytes).unwrap();
    let mut m: Vec<(lattice_proto::Value, lattice_proto::Value)> = v.as_map().unwrap().to_vec();
    for (k, v) in m.iter_mut() {
        if k.as_uint() == Some(3) {
            *v = lattice_proto::Value::UInt(9);
        }
    }
    let bad = lattice_proto::encode(&lattice_proto::Value::map(m));
    assert!(Frame::from_bytes(&bad).is_err());
}

#[test]
fn reconcile_roundtrip_both_range_kinds() {
    let f = Frame::Reconcile(ReconcileFrame {
        ranges: vec![
            Range::Fingerprint {
                lower: ([1; 32], 0),
                upper: ([9; 32], 1),
                count: 1234,
                sum: [7; 32],
            },
            Range::Entries {
                lower: ([1; 32], 0),
                upper: ([2; 32], 0),
                entries: vec![([8; 32], 1, 42), ([9; 32], 0, 7)],
            },
        ],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
}

#[test]
fn want_records_wary_ping_dummy_roundtrip() {
    let f = Frame::Want(WantFrame {
        wants: vec![([1; 32], 0), ([2; 32], 1)],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Records(RecordsFrame {
        records: vec![vec![1, 2, 3], vec![4]],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Wary(WaryFrame {
        ids: vec![[1; 32], [2; 32]],
        exp: 1_800_000_000,
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Ping(PingFrame { nonce: 42 });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Dummy(DummyFrame { echo: true });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
}

#[test]
fn handshake_frames_roundtrip() {
    let f = Frame::Init(InitFrame {
        noise_msg: vec![1, 2, 3],
        mac1: [9; 16],
        mac2: None,
        padding: vec![0; 100],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Init(InitFrame {
        noise_msg: vec![1],
        mac1: [9; 16],
        mac2: Some([8; 16]),
        padding: vec![],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Cookie(CookieFrame {
        nonce: [3; 16],
        encrypted_cookie: vec![0xAB; 64],
        padding: vec![0; 10],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Resp(RespFrame {
        noise_msg: vec![5; 48],
        padding: vec![0; 4],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
}

#[test]
fn unknown_frame_type_rejected() {
    let v = lattice_proto::Value::map(vec![(
        lattice_proto::Value::UInt(0),
        lattice_proto::Value::UInt(99),
    )]);
    assert!(Frame::from_value(&v).is_err());
}

#[test]
fn clock_skew_constant_is_six_hours() {
    assert_eq!(CLOCK_SKEW, 6 * 3600);
}
