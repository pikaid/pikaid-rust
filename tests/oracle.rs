//! Digest-pinned conformance against an independently derived oracle table.
//!
//! `tests/vectors/oracle-cases.json` is produced by
//! `scripts/generate_oracle_cases.py`, a Python program that recomputes the
//! pikaid 1.0.4 arithmetic from first principles and never imports, links or
//! executes this crate. Its committed SHA-256 is pinned below, so silently
//! editing an expected value fails the suite. CI re-runs the generator with
//! `--check`, which makes the table a second, independent oracle next to the
//! vendored pikaid-php fixtures.
//!
//! Every valid case is pushed through *all* public entry points and every
//! invalid case must report the exact error variant, so a partial regression
//! (for example text parsing drifting from binary parsing) is caught.

use std::str::FromStr;

use pikaid::{
    BINARY_LENGTH, Error, MAX_TIMESTAMP, PikaId, PikaIdBinary, RANDOMNESS_BYTES, STRING_LENGTH,
};
use serde_json::Value;

const ORACLE_JSON: &str = include_str!("vectors/oracle-cases.json");
const OFFICIAL_JSON: &str = include_str!("vectors/pikaid-v1.json");
const OFFICIAL_SCHEMA_JSON: &str = include_str!("vectors/pikaid-v1.schema.json");

/// SHA-256 of `tests/vectors/oracle-cases.json` (spec 1.0.4, 2026-11-09).
const ORACLE_SHA256: &str = "4acbeded373feb765572b5f5e6e4ff0238ff82eaaee5ad2fc9d1bddafd4021de";
/// SHA-256 of the unmodified pikaid-php v1.2.0 `pikaid-v1.json` fixture.
const OFFICIAL_SHA256: &str = "b0c9dfdd063613424414fef5c9065fbd2f81d645d0ab42b34e27cde715613500";
/// SHA-256 of the unmodified pikaid-php v1.2.0 `pikaid-v1.schema.json` fixture.
const OFFICIAL_SCHEMA_SHA256: &str =
    "4441d4dbaa6c5450ae9cbfb2438c53bc0421bba2b7fcc9ef9b158e5d1de0759e";

const SPEC_COMMIT: &str = "17014d76f568c3ac9f9ce2927c1a018fdbc36d1d";
const FIXTURE_COMMIT: &str = "e3f843edeb5157a5d2d25196cac0d69580810a95";

// ---------------------------------------------------------------------------
// Self-contained SHA-256.
//
// The crate has no hashing dependency and this suite should not add one just
// to pin fixtures, so a small, allocation-only implementation is inlined here.
// It is test-only code and is checked against published vectors below.
// ---------------------------------------------------------------------------

#[allow(clippy::needless_range_loop)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());

    let mut schedule = [0u32; 64];
    for chunk in message.chunks_exact(64) {
        for i in 0..16 {
            schedule[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = schedule[i - 15].rotate_right(7)
                ^ schedule[i - 15].rotate_right(18)
                ^ (schedule[i - 15] >> 3);
            let s1 = schedule[i - 2].rotate_right(17)
                ^ schedule[i - 2].rotate_right(19)
                ^ (schedule[i - 2] >> 10);
            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }

        let mut working = state;
        for i in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choice = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[i])
                .wrapping_add(schedule[i]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);

            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            state[i] = state[i].wrapping_add(working[i]);
        }
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
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

fn randomness_bytes(value: &Value) -> [u8; RANDOMNESS_BYTES] {
    let hex = value["entropy_hex"].as_str().expect("entropy_hex string");
    let bytes = decode_hex(hex);
    let mut out = [0u8; RANDOMNESS_BYTES];
    out.copy_from_slice(&bytes);
    out
}

fn error_kind(error: Error) -> &'static str {
    match error {
        Error::InvalidLength { .. } => "length",
        Error::InvalidCharacter { .. } => "character",
        Error::RandomnessOverflow => "overflow",
        Error::TimestampOutOfRange { .. } => "timestamp",
        // Generation-only variants must never be produced by parsing.
        _ => panic!("parsing returned a non-parsing error: {error:?}"),
    }
}

fn oracle() -> Value {
    serde_json::from_str(ORACLE_JSON).expect("oracle table is valid JSON")
}

// ---------------------------------------------------------------------------
// Pins.
// ---------------------------------------------------------------------------

#[test]
fn sha256_matches_published_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn fixtures_are_byte_identical_to_the_pinned_revisions() {
    assert_eq!(
        sha256_hex(OFFICIAL_JSON.as_bytes()),
        OFFICIAL_SHA256,
        "pikaid-v1.json drifted from pikaid-php v1.2.0"
    );
    assert_eq!(
        sha256_hex(OFFICIAL_SCHEMA_JSON.as_bytes()),
        OFFICIAL_SCHEMA_SHA256,
        "pikaid-v1.schema.json drifted from pikaid-php v1.2.0"
    );
    assert_eq!(
        sha256_hex(ORACLE_JSON.as_bytes()),
        ORACLE_SHA256,
        "oracle table changed without regenerating it from scripts/generate_oracle_cases.py"
    );
}

#[test]
fn vectors_are_lf_only() {
    // A CRLF checkout or an editor that rewrites line endings must not quietly
    // change the bytes that are pinned above.
    for (name, text) in [
        ("oracle-cases.json", ORACLE_JSON),
        ("pikaid-v1.json", OFFICIAL_JSON),
        ("pikaid-v1.schema.json", OFFICIAL_SCHEMA_JSON),
    ] {
        assert!(!text.contains('\r'), "{name} contains a carriage return");
    }
}

#[test]
fn oracle_metadata_matches_the_pinned_specification() {
    let table = oracle();
    let meta = &table["meta"];
    assert_eq!(meta["spec_revision"], "1.0.4");
    assert_eq!(meta["spec_commit"], SPEC_COMMIT);
    assert_eq!(meta["official_fixture_commit"], FIXTURE_COMMIT);
    assert_eq!(meta["max_timestamp"].as_u64(), Some(MAX_TIMESTAMP));
    assert_eq!(meta["string_length"].as_u64(), Some(STRING_LENGTH as u64));
    assert_eq!(meta["binary_length"].as_u64(), Some(BINARY_LENGTH as u64));
    assert_eq!(meta["two96"], "79228162514264337593543950336");
    assert_eq!(meta["base36_pow19"], "371319292745659279662190166016");
}

// ---------------------------------------------------------------------------
// Valid corpus: every case through every public entry point.
// ---------------------------------------------------------------------------

#[test]
fn every_valid_case_round_trips_through_every_public_entry_point() {
    let table = oracle();
    let cases = table["valid"].as_array().expect("valid array");
    assert!(
        cases.len() >= 330,
        "oracle corpus unexpectedly small: {}",
        cases.len()
    );

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let text = case["id"].as_str().expect("id string");
        let binary_hex = case["bin_hex"].as_str().expect("bin_hex string");
        let timestamp = case["timestamp"].as_u64().expect("timestamp");
        let randomness = randomness_bytes(case);
        let binary = decode_hex(binary_hex);
        assert_eq!(text.len(), STRING_LENGTH, "{name}: text width");
        assert_eq!(binary.len(), BINARY_LENGTH, "{name}: binary width");
        assert_eq!(text, text.to_lowercase(), "{name}: alphabet case");

        // Text entry points.
        let parsed = PikaId::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        let via_from_str = PikaId::from_str(text).expect("FromStr");
        let via_parse_method: PikaId = text.parse().expect("str::parse");
        assert_eq!(parsed, via_from_str, "{name}: FromStr");
        assert_eq!(parsed, via_parse_method, "{name}: str::parse");
        assert_eq!(parsed.as_str(), text, "{name}: as_str");
        assert_eq!(parsed.as_bytes(), text.as_bytes(), "{name}: as_bytes");
        assert_eq!(parsed.to_string(), text, "{name}: Display");
        assert_eq!(format!("{parsed}"), text, "{name}: format");
        assert_eq!(parsed.timestamp(), timestamp, "{name}: timestamp");
        assert_eq!(parsed.randomness(), randomness, "{name}: randomness");
        assert_eq!(
            parsed.randomness_hex(),
            case["entropy_hex"].as_str().unwrap(),
            "{name}: randomness_hex"
        );
        assert!(PikaId::is_valid(text), "{name}: is_valid");
        assert!(PikaId::is_well_formed(text), "{name}: is_well_formed");
        assert_eq!(
            format!("{parsed:?}"),
            format!("PikaId({text})"),
            "{name}: Debug"
        );

        // Construction entry points must reproduce the same value.
        assert_eq!(
            PikaId::from_parts(timestamp, randomness).expect("from_parts"),
            parsed,
            "{name}: text from_parts"
        );
        assert_eq!(
            PikaIdBinary::from_parts(timestamp, randomness).expect("binary from_parts"),
            PikaIdBinary::parse(&binary).expect("binary parse"),
            "{name}: binary from_parts"
        );

        // Binary entry points.
        let binary_value = PikaIdBinary::parse(&binary).expect("binary parse");
        assert_eq!(binary_value.as_bytes(), binary.as_slice(), "{name}: bytes");
        assert_eq!(binary_value.timestamp(), timestamp, "{name}: bin ts");
        assert_eq!(binary_value.randomness(), randomness, "{name}: bin rand");
        assert_eq!(
            binary_value.randomness_hex(),
            case["entropy_hex"].as_str().unwrap(),
            "{name}: bin rand hex"
        );
        assert_eq!(binary_value.to_hex(), binary_hex, "{name}: to_hex");
        let _ = format!("{binary_value:?}");

        // Cross-representation entry points.
        assert_eq!(parsed.to_binary(), binary_value, "{name}: to_binary");
        assert_eq!(binary_value.to_pikaid(), parsed, "{name}: to_pikaid");
        assert_eq!(
            PikaId::from_binary(&binary).expect("from_binary"),
            parsed,
            "{name}: from_binary"
        );

        // Hashing must be deterministic for the same value.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut text_hash = DefaultHasher::new();
        parsed.hash(&mut text_hash);
        let first = text_hash.finish();
        let mut again = DefaultHasher::new();
        parsed.hash(&mut again);
        assert_eq!(first, again.finish(), "{name}: hash determinism");
    }
}

#[test]
fn oracle_ordering_matches_canonical_order() {
    let table = oracle();
    let cases = table["valid"].as_array().expect("valid array");
    let expected: Vec<&str> = table["ordering"]
        .as_array()
        .expect("ordering array")
        .iter()
        .map(|value| value.as_str().expect("ordering name"))
        .collect();
    assert_eq!(expected.len(), cases.len(), "ordering covers every case");

    let mut by_text: Vec<(&str, &str)> = cases
        .iter()
        .map(|case| (case["name"].as_str().unwrap(), case["id"].as_str().unwrap()))
        .collect();
    by_text.sort_by(|a, b| a.1.cmp(b.1));
    assert_eq!(
        by_text.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        expected,
        "text order"
    );

    let mut by_binary: Vec<(&str, Vec<u8>)> = cases
        .iter()
        .map(|case| {
            (
                case["name"].as_str().unwrap(),
                decode_hex(case["bin_hex"].as_str().unwrap()),
            )
        })
        .collect();
    by_binary.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        by_binary.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        expected,
        "binary order"
    );

    // Both parsed types must implement the same order as the raw bytes.
    let mut parsed_text: Vec<(&str, PikaId)> = cases
        .iter()
        .map(|case| {
            let name = case["name"].as_str().unwrap();
            let text = case["id"].as_str().unwrap();
            (name, PikaId::parse(text).unwrap())
        })
        .collect();
    parsed_text.sort_by_key(|a| a.1);
    assert_eq!(
        parsed_text
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        expected,
        "PikaId Ord"
    );

    let mut parsed_binary: Vec<(&str, PikaIdBinary)> = cases
        .iter()
        .map(|case| {
            let name = case["name"].as_str().unwrap();
            let binary = decode_hex(case["bin_hex"].as_str().unwrap());
            (name, PikaIdBinary::parse(&binary).unwrap())
        })
        .collect();
    parsed_binary.sort_by_key(|a| a.1);
    assert_eq!(
        parsed_binary
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        expected,
        "PikaIdBinary Ord"
    );

    // The ordering table must be a permutation of the corpus, and the derived
    // text keys must be non-decreasing. Duplicate identifiers are allowed
    // (different case names may target the same value) but they must be
    // adjacent after sorting.
    let mut expected_sorted = expected.clone();
    expected_sorted.sort_unstable();
    let mut names: Vec<&str> = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(expected_sorted, names, "ordering must cover each case once");

    for window in by_text.windows(2) {
        assert!(window[0].1 <= window[1].1, "ordering is not sorted");
    }
}

// ---------------------------------------------------------------------------
// Invalid corpus: exact error variant, exact reported details.
// ---------------------------------------------------------------------------

#[test]
fn invalid_strings_report_the_exact_error() {
    let table = oracle();
    let cases = table["invalid"]["string"].as_array().expect("string array");
    assert!(cases.len() >= 20, "negative corpus unexpectedly small");

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let text = case["id"].as_str().expect("id");
        let expected = case["error"].as_str().expect("error kind");
        let error = PikaId::parse(text)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected an error"));
        assert_eq!(error_kind(error), expected, "{name}: {error:?}");
        assert!(PikaId::from_str(text).is_err(), "{name}: FromStr");
        assert!(!PikaId::is_valid(text), "{name}: is_valid");

        match error {
            Error::InvalidLength {
                actual,
                expected: width,
            } => {
                assert_eq!(actual, text.len(), "{name}: actual length");
                assert_eq!(width, STRING_LENGTH, "{name}: expected length");
            }
            Error::InvalidCharacter { byte, index } => {
                assert_eq!(byte, text.as_bytes()[index], "{name}: reported byte");
                assert!(
                    !matches!(byte, b'0'..=b'9' | b'a'..=b'z'),
                    "{name}: reported byte is a valid digit"
                );
                assert!(
                    text.as_bytes()[..index]
                        .iter()
                        .all(|&candidate| matches!(candidate, b'0'..=b'9' | b'a'..=b'z')),
                    "{name}: reported index is not the first bad byte"
                );
            }
            Error::RandomnessOverflow => {
                // The 96-bit overflow corpus always has a zero timestamp.
                assert_eq!(&text[..7], "0000000", "{name}: timestamp prefix");
            }
            Error::TimestampOutOfRange { .. } => {
                panic!("{name}: text parsing must not report a timestamp error")
            }
            _ => panic!("{name}: unexpected error {error:?}"),
        }
    }
}

#[test]
fn invalid_binaries_report_the_exact_error() {
    let table = oracle();
    let cases = table["invalid"]["binary"].as_array().expect("binary array");
    assert!(cases.len() >= 8, "negative corpus unexpectedly small");

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let bytes = decode_hex(case["bin_hex"].as_str().expect("bin_hex"));
        let expected = case["error"].as_str().expect("error kind");
        let error = PikaIdBinary::parse(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected an error"));
        assert_eq!(error_kind(error), expected, "{name}: {error:?}");
        assert!(PikaId::from_binary(&bytes).is_err(), "{name}: from_binary");

        match error {
            Error::InvalidLength {
                actual,
                expected: width,
            } => {
                assert_eq!(actual, bytes.len(), "{name}: actual length");
                assert_eq!(width, BINARY_LENGTH, "{name}: expected length");
            }
            Error::TimestampOutOfRange { timestamp } => {
                assert!(timestamp > MAX_TIMESTAMP, "{name}: timestamp bound");
            }
            _ => panic!("{name}: unexpected error {error:?}"),
        }
    }
}

#[test]
fn well_formed_is_shape_only_not_validity() {
    let table = oracle();
    for case in table["invalid"]["string"].as_array().expect("string array") {
        let name = case["name"].as_str().unwrap();
        let text = case["id"].as_str().unwrap();
        let shape_ok = text.len() == STRING_LENGTH
            && text
                .as_bytes()
                .iter()
                .all(|&byte| matches!(byte, b'0'..=b'9' | b'a'..=b'z'));
        assert_eq!(
            PikaId::is_well_formed(text),
            shape_ok,
            "{name}: is_well_formed must only check shape"
        );
    }
}
