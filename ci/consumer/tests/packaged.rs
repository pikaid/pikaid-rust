//! External consumer smoke test against the packaged `pikaid` crate.
//!
//! This crate has no access to the pikaid repository: `run.sh` copies it into a
//! temporary directory, points its only dependency at the unpacked `.crate`
//! archive, and sets `PIKAID_ORACLE_TABLE` to the oracle table *inside that
//! archive*. Passing therefore proves three things at once:
//!
//! 1. the published archive contains every file the tests need;
//! 2. an unrelated crate can depend on it without a workspace or path hacks;
//! 3. the packaged implementation still reproduces the independent oracle.

use std::str::FromStr;

use pikaid::{Error, PikaId, PikaIdBinary, RANDOMNESS_BYTES, STRING_LENGTH};
use serde_json::Value;

fn oracle() -> Value {
    let path = std::env::var("PIKAID_ORACLE_TABLE")
        .expect("run.sh must set PIKAID_ORACLE_TABLE to the table in the packaged archive");
    let text = std::fs::read_to_string(&path).expect("oracle table is readable");
    serde_json::from_str(&text).expect("oracle table is valid JSON")
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex length");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
            let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
            (high << 4) | low
        })
        .collect()
}

#[test]
fn packaged_archive_carries_the_pinned_oracle_table() {
    let table = oracle();
    assert_eq!(table["meta"]["spec_revision"], "1.0.4");
    assert_eq!(
        table["meta"]["spec_commit"],
        "17014d76f568c3ac9f9ce2927c1a018fdbc36d1d"
    );
    let cases = table["valid"].as_array().expect("valid array");
    assert!(cases.len() >= 330, "packaged corpus is truncated");
    assert_eq!(
        table["invalid"]["string"].as_array().unwrap().len(),
        22,
        "packaged negative corpus is truncated"
    );
}

#[test]
fn packaged_crate_reproduces_every_oracle_case() {
    let table = oracle();
    for case in table["valid"].as_array().expect("valid array") {
        let name = case["name"].as_str().unwrap();
        let text = case["id"].as_str().unwrap();
        let timestamp = case["timestamp"].as_u64().unwrap();
        let randomness_hex = case["entropy_hex"].as_str().unwrap();
        let binary = decode_hex(case["bin_hex"].as_str().unwrap());

        let mut randomness = [0u8; RANDOMNESS_BYTES];
        randomness.copy_from_slice(&decode_hex(randomness_hex));

        let parsed = PikaId::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(parsed, PikaId::from_str(text).unwrap(), "{name}: FromStr");
        assert_eq!(parsed.as_str(), text, "{name}: as_str");
        assert_eq!(parsed.timestamp(), timestamp, "{name}: timestamp");
        assert_eq!(parsed.randomness(), randomness, "{name}: randomness");
        assert_eq!(parsed.randomness_hex(), randomness_hex, "{name}: hex");
        assert_eq!(parsed.as_bytes().len(), STRING_LENGTH, "{name}: width");
        assert_eq!(
            parsed,
            PikaId::from_parts(timestamp, randomness).unwrap(),
            "{name}: from_parts"
        );

        let binary_value = PikaIdBinary::parse(&binary).unwrap();
        assert_eq!(binary_value.timestamp(), timestamp, "{name}: bin ts");
        assert_eq!(binary_value.randomness(), randomness, "{name}: bin rand");
        assert_eq!(parsed.to_binary(), binary_value, "{name}: to_binary");
        assert_eq!(binary_value.to_pikaid(), parsed, "{name}: to_pikaid");
    }
}

#[test]
fn packaged_crate_rejects_the_expanded_negative_corpus() {
    let table = oracle();
    for case in table["invalid"]["string"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = case["id"].as_str().unwrap();
        let expected = case["error"].as_str().unwrap();
        let error = PikaId::parse(text)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected an error"));
        assert_eq!(kind(error), expected, "{name}: {error:?}");
        assert!(!PikaId::is_valid(text), "{name}: is_valid");
    }
    for case in table["invalid"]["binary"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bytes = decode_hex(case["bin_hex"].as_str().unwrap());
        let expected = case["error"].as_str().unwrap();
        let error = PikaIdBinary::parse(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected an error"));
        assert_eq!(kind(error), expected, "{name}: {error:?}");
    }
}

fn kind(error: Error) -> &'static str {
    match error {
        Error::InvalidLength { .. } => "length",
        Error::InvalidCharacter { .. } => "character",
        Error::RandomnessOverflow => "overflow",
        Error::TimestampOutOfRange { .. } => "timestamp",
        _ => panic!("parsing returned a non-parsing error: {error:?}"),
    }
}
