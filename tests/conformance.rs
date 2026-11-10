//! Conformance against the official pikaid interoperability vectors.
//!
//! The fixtures in `tests/vectors/` are unmodified copies from pikaid-php
//! v1.2.0 (commit `e3f843edeb5157a5d2d25196cac0d69580810a95`). They are
//! independent of this implementation, so these tests are genuine
//! cross-implementation checks rather than self-fulfilling round trips.

use pikaid::{Error, MAX_TIMESTAMP, PikaId, PikaIdBinary};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/pikaid-v1.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("official vector fixture is valid JSON")
}

fn hex_value(value: &Value, key: &str) -> Vec<u8> {
    let text = value[key].as_str().expect("hex field is a string");
    decode_hex(text)
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex length must be even: {text}");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
            let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
            (high << 4) | low
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn fixture_metadata_matches_the_crate_and_the_specification() {
    let fixture = vectors();
    let meta = &fixture["meta"];

    assert_eq!(meta["project"], "pikaid");
    assert_eq!(meta["string_length"], 26);
    assert_eq!(meta["timestamp"]["encoding"], "base36-lower");
    assert_eq!(meta["timestamp"]["chars"], 7);
    assert_eq!(meta["timestamp"]["min"], 0);
    assert_eq!(meta["timestamp"]["max"], MAX_TIMESTAMP);
    assert_eq!(meta["entropy"]["bytes"], 12);
    assert_eq!(meta["entropy"]["chars"], 19);
    assert_eq!(meta["binary"]["bytes"], 17);
    assert_eq!(
        meta["binary"]["layout"],
        "[5 bytes timestamp big-endian][12 bytes entropy]"
    );
    assert_eq!(meta["spec_revision"], "1.0.4");

    // The fixture filename is historical; the format itself is unversioned.
    assert_eq!(meta["identifier_format"], "immutable and unversioned");
    assert!(
        !meta.to_string().contains("\"version\""),
        "the identifier must not gain a format version"
    );
}

#[test]
fn every_valid_vector_round_trips_across_all_representations() {
    let fixture = vectors();
    let valid = fixture["valid"].as_array().expect("valid is an array");
    assert!(!valid.is_empty(), "fixture must contain valid vectors");

    for vector in valid {
        let name = vector["name"].as_str().expect("name");
        let text = vector["id"].as_str().expect("id");
        let timestamp = vector["timestamp"].as_u64().expect("timestamp");
        let entropy = hex_value(vector, "entropy_hex");
        let binary = hex_value(vector, "bin_hex");
        assert_eq!(entropy.len(), 12, "{name}: entropy length");
        assert_eq!(binary.len(), 17, "{name}: binary length");

        let id = PikaId::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(id.as_str(), text, "{name}: canonical text");
        assert_eq!(id.to_string(), text, "{name}: Display");
        assert!(PikaId::is_valid(text), "{name}: is_valid");
        assert!(PikaId::is_well_formed(text), "{name}: is_well_formed");
        assert_eq!(id.timestamp(), timestamp, "{name}: timestamp");
        assert_eq!(id.randomness().as_slice(), entropy, "{name}: randomness");
        assert_eq!(id.randomness_hex(), encode_hex(&entropy), "{name}: hex");
        assert_eq!(
            id.as_bytes().as_slice(),
            text.as_bytes(),
            "{name}: raw text bytes"
        );

        // Text -> binary must match the official binary vector byte for byte.
        let from_text = id.to_binary();
        assert_eq!(from_text.as_bytes().as_slice(), binary, "{name}: to_binary");
        assert_eq!(from_text.to_hex(), encode_hex(&binary), "{name}: to_hex");

        // Binary -> text must also match, through both public paths.
        let parsed_binary =
            PikaIdBinary::parse(&binary).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(parsed_binary.timestamp(), timestamp, "{name}: bin ts");
        assert_eq!(
            parsed_binary.randomness().as_slice(),
            entropy,
            "{name}: bin randomness"
        );
        assert_eq!(parsed_binary.to_pikaid(), id, "{name}: bin -> text");
        assert_eq!(PikaId::from_binary(&binary), Ok(id), "{name}: from_binary");
        assert_eq!(PikaId::from(parsed_binary), id, "{name}: From impl");

        // Deterministic construction from the independent fields.
        assert_eq!(
            PikaId::from_parts(timestamp, entropy.as_slice().try_into().unwrap()),
            Ok(id),
            "{name}: from_parts"
        );
        assert_eq!(
            PikaIdBinary::from_parts(timestamp, entropy.as_slice().try_into().unwrap())
                .map(|bytes| bytes.to_hex()),
            Ok(encode_hex(&binary)),
            "{name}: binary from_parts"
        );

        // Ordering is canonical bytewise order.
        assert_eq!(
            id.as_str().as_bytes(),
            id.as_bytes(),
            "{name}: canonical representation"
        );
    }
}

#[test]
fn every_invalid_string_vector_is_rejected_with_a_specific_error() {
    let fixture = vectors();
    let invalid = fixture["invalid"]["string"]
        .as_array()
        .expect("invalid strings");
    assert!(!invalid.is_empty());

    for vector in invalid {
        let name = vector["name"].as_str().expect("name");
        let text = vector["id"].as_str().expect("id");

        assert!(!PikaId::is_valid(text), "{name}: must not be valid");
        let error = PikaId::parse(text).expect_err(name);
        assert!(
            matches!(
                error,
                Error::InvalidLength { .. }
                    | Error::InvalidCharacter { .. }
                    | Error::RandomnessOverflow
            ),
            "{name}: unexpected error {error:?}"
        );

        // The overflow case is well formed but semantically invalid.
        if name == "entropy-overflow" {
            assert!(PikaId::is_well_formed(text), "{name}: shape is valid");
            assert_eq!(error, Error::RandomnessOverflow, "{name}: exact error");
        } else {
            assert!(
                !PikaId::is_well_formed(text),
                "{name}: shape must also be invalid"
            );
        }

        // No conversion path may accept the value.
        assert!(PikaId::from_binary(text.as_bytes()).is_err());
    }
}

#[test]
fn every_invalid_binary_vector_is_rejected_with_a_specific_error() {
    let fixture = vectors();
    let invalid = fixture["invalid"]["binary"]
        .as_array()
        .expect("invalid binaries");
    assert!(!invalid.is_empty());

    for vector in invalid {
        let name = vector["name"].as_str().expect("name");
        let bytes = hex_value(vector, "bin_hex");

        let error = PikaIdBinary::parse(&bytes).expect_err(name);
        match name {
            "too-short" | "too-long" => assert!(
                matches!(error, Error::InvalidLength { .. }),
                "{name}: expected length error, got {error:?}"
            ),
            "timestamp-overflow" | "timestamp-overflow-max-40-bit" => assert!(
                matches!(error, Error::TimestampOutOfRange { .. }),
                "{name}: expected timestamp error, got {error:?}"
            ),
            other => panic!("unexpected invalid binary vector {other}"),
        }
        assert!(PikaId::from_binary(&bytes).is_err(), "{name}");
        assert!(
            PikaIdBinary::try_from(bytes.as_slice()).is_err(),
            "{name}: TryFrom"
        );
        if let Ok(array) = <[u8; 17]>::try_from(bytes.as_slice()) {
            assert!(
                PikaIdBinary::try_from(array).is_err(),
                "{name}: TryFrom array"
            );
        }
    }
}

#[test]
fn vector_named_boundaries_match_the_specification_prose() {
    let fixture = vectors();
    let valid = fixture["valid"].as_array().expect("valid");

    let find = |name: &str| {
        valid
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("missing vector {name}"))
    };

    let zero = find("all-zero");
    assert_eq!(zero["id"], "00000000000000000000000000");
    assert_eq!(zero["bin_hex"], "0000000000000000000000000000000000");

    let max = find("max-values");
    assert_eq!(max["timestamp"], MAX_TIMESTAMP);
    assert_eq!(max["id"], "zzzzzzz7oiylpimjg5u2ca1ypr");
    assert_eq!(max["bin_hex"], "123ede3fffffffffffffffffffffffffff");

    // The specification's "randomness exceeds 96 bits" example.
    assert!(!PikaId::is_valid("0000000zzzzzzzzzzzzzzzzzzz"));
    // The specification's 40-bit timestamp binary example.
    let forty_bit = decode_hex("ffffffffff000000000000000000000000");
    assert_eq!(
        PikaIdBinary::parse(&forty_bit),
        Err(Error::TimestampOutOfRange {
            timestamp: 0xFF_FFFF_FFFF
        })
    );
}
