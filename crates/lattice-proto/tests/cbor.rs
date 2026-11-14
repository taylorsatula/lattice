//! CBOR codec: RFC 8949 Appendix A spot checks and hostile-input rejection.

use lattice_proto::cbor::{self, Value};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn assert_roundtrip(encoded: &str, expected: Value) {
    let bytes = hex(encoded);
    let decoded = cbor::decode(&bytes).unwrap_or_else(|e| panic!("decode {encoded}: {e}"));
    assert_eq!(decoded, expected, "decode of {encoded}");
    assert_eq!(cbor::encode(&decoded), bytes, "re-encode of {encoded}");
}

#[test]
fn rfc8949_appendix_a() {
    // Unsigned ints
    assert_roundtrip("00", Value::UInt(0));
    assert_roundtrip("17", Value::UInt(23));
    assert_roundtrip("1818", Value::UInt(24));
    assert_roundtrip("1819", Value::UInt(25));
    assert_roundtrip("1864", Value::UInt(100));
    assert_roundtrip("1903e8", Value::UInt(1000));
    assert_roundtrip("1a000f4240", Value::UInt(1_000_000));
    assert_roundtrip("1b000000e8d4a51000", Value::UInt(1_000_000_000_000));
    assert_roundtrip("1bffffffffffffffff", Value::UInt(u64::MAX));
    // Negative ints (kept for decoder completeness)
    assert_roundtrip("20", Value::NInt(0));
    assert_roundtrip("37", Value::NInt(23));
    assert_roundtrip("38 63", Value::NInt(99));
    // Bytes and text
    assert_roundtrip("40", Value::Bytes(vec![]));
    assert_roundtrip("4401020304", Value::Bytes(vec![1, 2, 3, 4]));
    assert_roundtrip("60", Value::Text(String::new()));
    assert_roundtrip("6161", Value::Text("a".into()));
    assert_roundtrip("6449455446", Value::Text("IETF".into()));
    // Arrays and maps
    assert_roundtrip("80", Value::Array(vec![]));
    assert_roundtrip(
        "8301820203820405",
        Value::Array(vec![
            Value::UInt(1),
            Value::Array(vec![Value::UInt(2), Value::UInt(3)]),
            Value::Array(vec![Value::UInt(4), Value::UInt(5)]),
        ]),
    );
    assert_roundtrip("a0", Value::Map(vec![]));
    assert_roundtrip(
        "a201020304",
        Value::Map(vec![
            (Value::UInt(1), Value::UInt(2)),
            (Value::UInt(3), Value::UInt(4)),
        ]),
    );
    // Nested map with out-of-order source keys must re-encode canonically.
    let src = hex("a202020101"); // {2:2, 1:1} — non-canonical order
    assert!(
        cbor::decode(&src).is_err(),
        "out-of-order map must be rejected"
    );
    // Booleans and null
    assert_roundtrip("f4", Value::Bool(false));
    assert_roundtrip("f5", Value::Bool(true));
    assert_roundtrip("f6", Value::Null);
}

#[test]
fn rejects_non_shortest_form() {
    assert!(cbor::decode(&hex("1800")).is_err(), "0 encoded in 2 bytes");
    assert!(cbor::decode(&hex("190017")).is_err());
    assert!(cbor::decode(&hex("1a00000017")).is_err());
}

#[test]
fn rejects_indefinite_lengths_and_tags_and_floats() {
    assert!(cbor::decode(&hex("9f01ff")).is_err()); // indefinite array
    assert!(cbor::decode(&hex("5f4100ff")).is_err()); // indefinite bytes
    assert!(cbor::decode(&hex("c074323031332d30332d32315432303a30343a3030")).is_err()); // tag
    assert!(cbor::decode(&hex("f93c00")).is_err()); // float16
    assert!(cbor::decode(&hex("fb7e37e43c8800759c")).is_err()); // float64
}

#[test]
fn rejects_trailing_bytes() {
    assert!(cbor::decode(&hex("0000")).is_err());
    assert!(cbor::decode(&hex("814000")).is_err());
}

#[test]
fn rejects_deep_nesting_and_huge_containers() {
    // 9 nested arrays exceeds the depth limit of 8.
    let mut deep = vec![0x81; 9];
    deep.push(0x00);
    assert!(cbor::decode(&deep).is_err());
    // Declared length 513 (> 512) must fail before allocation matters.
    let huge = hex("b90101"); // map(513)
    assert!(cbor::decode(&huge).is_err());
    // Declared array length larger than remaining input must fail fast.
    let lying = hex("9a000f4240");
    assert!(cbor::decode(&lying).is_err());
}

#[test]
fn rejects_duplicate_and_unsorted_map_keys() {
    // {1: 1, 1: 2}
    assert!(cbor::decode(&hex("a201010102")).is_err());
    // {2: x, 1: y} order violation
    assert!(cbor::decode(&hex("a20201010203")).is_err());
}

#[test]
fn deterministic_encode_of_map_builder() {
    // Insert in unsorted order; encoding must come out sorted.
    let v = Value::map(vec![
        (Value::UInt(30), Value::UInt(1)),
        (Value::UInt(2), Value::UInt(2)),
        (Value::UInt(10), Value::UInt(3)),
        (Value::UInt(100), Value::UInt(4)),
    ]);
    let bytes = cbor::encode(&v);
    // keys 2, 10, 30, 100 in canonical (length, then bytewise) order
    assert_eq!(bytes, hex("a402020a03181e01186404"));
}

#[test]
fn sizes_match_cbor_spec() {
    assert_eq!(cbor::encode(&Value::UInt(0)).len(), 1);
    assert_eq!(cbor::encode(&Value::UInt(23)).len(), 1);
    assert_eq!(cbor::encode(&Value::UInt(24)).len(), 2);
    assert_eq!(cbor::encode(&Value::UInt(255)).len(), 2);
    assert_eq!(cbor::encode(&Value::UInt(256)).len(), 3);
    assert_eq!(cbor::encode(&Value::UInt(65536)).len(), 5);
}
