use lattice_proto::Value;
use lattice_proto::local::*;

#[test]
fn request_response_roundtrip() {
    let req = Request {
        id: 7,
        op: OP_SEND,
        args: Value::map(vec![(Value::UInt(0), Value::Bytes(vec![1; 32]))]),
    };
    let back = Request::from_value(&req.to_value()).unwrap();
    assert_eq!(req, back);

    let resp = Response::Ok {
        id: 7,
        result: Value::map(vec![(Value::UInt(0), Value::Bytes(vec![9; 16]))]),
    };
    let back = Response::from_value(&resp.to_value()).unwrap();
    assert_eq!(resp, back);

    let err = Response::Err {
        id: 7,
        code: ERR_NOT_FOUND,
    };
    let back = Response::from_value(&err.to_value()).unwrap();
    assert_eq!(err, back);
}

#[test]
fn event_roundtrip() {
    let ev = Event {
        event: EVENT_INBOX,
        data: Value::map(vec![(Value::UInt(1), Value::UInt(3))]),
    };
    assert_eq!(Event::from_value(&ev.to_value()).unwrap(), ev);
}

#[test]
fn send_args_roundtrip_and_limits() {
    let args = Value::map(vec![
        (Value::UInt(0), Value::Bytes(vec![1; 32])),
        (Value::UInt(1), Value::Text("mira".into())),
        (Value::UInt(2), Value::Bytes(b"inbox".to_vec())),
        (Value::UInt(3), Value::Bytes(b"me".to_vec())),
        (Value::UInt(4), Value::Bytes(b"payload".to_vec())),
        (Value::UInt(6), Value::UInt(2)),
        (Value::UInt(7), Value::UInt(ROUTE_WAYPOINT)),
    ]);
    let parsed = SendArgs::from_value(&args).unwrap();
    assert_eq!(parsed.priority, Some(2));
    assert_eq!(parsed.route, Some(ROUTE_WAYPOINT));
    assert_eq!(parsed.to, lattice_types::Identifier::from_bytes([1u8; 32]));

    let bad = Value::map(vec![
        (Value::UInt(0), Value::Bytes(vec![1; 32])),
        (Value::UInt(1), Value::Text("mira".into())),
        (Value::UInt(2), Value::Bytes(vec![1])),
        (Value::UInt(3), Value::Bytes(vec![2])),
        (Value::UInt(4), Value::Bytes(vec![3])),
        (Value::UInt(6), Value::UInt(9)),
    ]);
    assert!(SendArgs::from_value(&bad).is_err(), "priority > 3 rejected");
}

#[test]
fn length_prefix_roundtrip() {
    let payload = br#"{"0":1}"#;
    let framed = frame_local(payload).unwrap();
    let (out, used) = deframe_local(&framed).unwrap().unwrap();
    assert_eq!(out, payload);
    assert_eq!(used, framed.len());
    // partial frame yields None, not an error
    assert!(deframe_local(&framed[..3]).unwrap().is_none());
    // oversized prefix rejected
    let mut huge = (LOCAL_MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
    huge.extend_from_slice(&[0; 16]);
    assert!(deframe_local(&huge).is_err());
}

#[test]
fn status_encodes() {
    let bytes = encode_status(true, false, &[1]);
    let v = lattice_proto::decode(&bytes).unwrap();
    let m = v.as_map().unwrap();
    let up = m
        .iter()
        .find(|(k, _)| k.as_uint() == Some(1))
        .unwrap()
        .1
        .as_bool()
        .unwrap();
    assert!(up);
}
