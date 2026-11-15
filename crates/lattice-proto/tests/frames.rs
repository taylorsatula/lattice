use lattice_proto::CLOCK_SKEW;
use lattice_proto::frames::{
    CUSTODY_ACCEPTED, CUSTODY_BUSY, CookieFrame, CustodyFrame, DummyFrame, Frame, InitFrame,
    OfferFrame, PingFrame, Range, RangeBound, ReconcileFrame, RecordEntry, RecordRef, RecordsFrame,
    RespFrame, WantFrame,
};
use lattice_types::{Cookie, Hash32, Identifier, LegId, Mac16};

#[test]
fn custody_roundtrip() {
    let f = Frame::Custody(CustodyFrame {
        leg: LegId::from_bytes([7u8; 16]),
        result: CUSTODY_ACCEPTED,
        retry_after: None,
    });
    let bytes = f.encode();
    assert_eq!(Frame::from_bytes(&bytes).unwrap(), f);
    let busy = Frame::Custody(CustodyFrame {
        leg: LegId::from_bytes([7; 16]),
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
        leg: LegId::from_bytes([7; 16]),
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
                lower: Some(RangeBound {
                    id: Identifier::from_bytes([1; 32]),
                    scope: 0,
                }),
                upper: Some(RangeBound {
                    id: Identifier::from_bytes([9; 32]),
                    scope: 1,
                }),
                count: 1234,
                sum: Hash32::from_bytes([7; 32]),
            },
            Range::Entries {
                lower: Some(RangeBound {
                    id: Identifier::from_bytes([1; 32]),
                    scope: 0,
                }),
                upper: Some(RangeBound {
                    id: Identifier::from_bytes([2; 32]),
                    scope: 0,
                }),
                entries: vec![
                    RecordEntry {
                        id: Identifier::from_bytes([8; 32]),
                        scope: 1,
                        seq: 42,
                    },
                    RecordEntry {
                        id: Identifier::from_bytes([9; 32]),
                        scope: 0,
                        seq: 7,
                    },
                ],
            },
        ],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
}

#[test]
fn want_records_ping_dummy_roundtrip() {
    let f = Frame::Want(WantFrame {
        wants: vec![
            RecordRef {
                id: Identifier::from_bytes([1; 32]),
                scope: 0,
            },
            RecordRef {
                id: Identifier::from_bytes([2; 32]),
                scope: 1,
            },
        ],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Records(RecordsFrame {
        records: vec![vec![1, 2, 3], vec![4]],
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
        mac1: Mac16::from_bytes([9; 16]),
        mac2: None,
        padding: vec![0; 100],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Init(InitFrame {
        noise_msg: vec![1],
        mac1: Mac16::from_bytes([9; 16]),
        mac2: Some(Mac16::from_bytes([8; 16])),
        padding: vec![],
    });
    assert_eq!(Frame::from_bytes(&f.encode()).unwrap(), f);
    let f = Frame::Cookie(CookieFrame {
        cookie: Cookie::from_bytes([0xCD; 24]),
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
