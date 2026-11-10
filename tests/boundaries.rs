//! Boundary and malformed-input tests.
//!
//! Every expected value here is derived from the specification's arithmetic
//! (`36^7 - 1`, `2^96 - 1`, five big-endian bytes) and was cross-checked with an
//! independent Python script, not by calling the implementation under test.

use pikaid::{
    BINARY_LENGTH, Error, MAX_TIMESTAMP, PikaId, PikaIdBinary, RANDOMNESS_BYTES, STRING_LENGTH,
};

/// 36^19, the first randomness value that no longer fits in 96 bits.
const BASE36_POW_19: u128 = 371_319_292_745_659_279_662_190_166_016;

#[test]
fn known_answers_for_timestamp_boundaries() {
    // Independently computed with Python: base36(ts).rjust(7, "0") + base36(e).rjust(19, "0").
    let cases: &[(u64, u128, &str)] = &[
        (0, 0, "00000000000000000000000000"),
        (0, 1, "00000000000000000000000001"),
        (1, 0, "00000010000000000000000000"),
        (1, 1, "00000010000000000000000001"),
        // Last timestamp that still fits in six Base36 digits.
        (2_176_782_335, 0, "0zzzzzz0000000000000000000"),
        // First timestamp that needs the seventh digit.
        (2_176_782_336, 0, "10000000000000000000000000"),
        (MAX_TIMESTAMP, 0, "zzzzzzz0000000000000000000"),
        (MAX_TIMESTAMP, (1 << 96) - 1, "zzzzzzz7oiylpimjg5u2ca1ypr"),
    ];

    for &(timestamp, entropy_value, expected) in cases {
        let entropy = value_to_bytes(entropy_value);
        let id = PikaId::from_parts(timestamp, entropy).expect("boundary parts are valid");
        assert_eq!(id.as_str(), expected, "timestamp {timestamp}");
        assert_eq!(id.timestamp(), timestamp);
        assert_eq!(id.randomness(), entropy);

        // And the same value parses back from its canonical text.
        let parsed = PikaId::parse(expected).expect("canonical text parses");
        assert_eq!(parsed, id);

        // Binary form is the five big-endian timestamp bytes plus entropy.
        let mut expected_binary = [0u8; BINARY_LENGTH];
        expected_binary[..5].copy_from_slice(&timestamp.to_be_bytes()[3..]);
        expected_binary[5..].copy_from_slice(&entropy);
        assert_eq!(id.to_binary().as_bytes(), &expected_binary);
    }
}

#[test]
fn timestamp_above_the_maximum_is_rejected_everywhere() {
    for timestamp in [MAX_TIMESTAMP + 1, MAX_TIMESTAMP + 2, u64::MAX] {
        assert_eq!(
            PikaId::from_parts(timestamp, [0; RANDOMNESS_BYTES]),
            Err(Error::TimestampOutOfRange { timestamp })
        );
        assert_eq!(
            PikaIdBinary::from_parts(timestamp, [0; RANDOMNESS_BYTES]),
            Err(Error::TimestampOutOfRange { timestamp })
        );
        assert!(PikaId::generate_at(timestamp).is_err());
        assert!(PikaIdBinary::generate_at(timestamp).is_err());
    }
}

#[test]
fn randomness_above_96_bits_is_rejected() {
    // base36(2^96) is exactly 19 digits and therefore well formed in shape,
    // yet too large to be 96 bits of randomness.
    // 36^19 exceeds 2^96, which is why a 19-digit suffix can still overflow.
    assert!(BASE36_POW_19 > 2u128.pow(96));
    let overflow_text = "00000007oiylpimjg5u2ca1yps";
    assert_eq!(overflow_text.len(), STRING_LENGTH);
    assert!(PikaId::is_well_formed(overflow_text));
    assert!(!PikaId::is_valid(overflow_text));
    assert_eq!(PikaId::parse(overflow_text), Err(Error::RandomnessOverflow));

    // The all-z suffix is the largest 19-digit Base36 suffix and overflows too.
    let all_z = "0000000zzzzzzzzzzzzzzzzzzz";
    assert!(PikaId::is_well_formed(all_z));
    assert_eq!(PikaId::parse(all_z), Err(Error::RandomnessOverflow));
}

#[test]
fn text_length_boundaries_report_exact_lengths() {
    for length in [0usize, 1, 25, 27, 32] {
        let input = "0".repeat(length);
        assert_eq!(
            PikaId::parse(&input),
            Err(Error::InvalidLength {
                actual: length,
                expected: STRING_LENGTH
            }),
            "length {length}"
        );
    }
    assert!(PikaId::parse(&"0".repeat(STRING_LENGTH)).is_ok());
}

#[test]
fn non_ascii_input_is_rejected_without_lossy_normalization() {
    // 24 ASCII digits plus a two-byte UTF-8 character is 26 bytes long, so the
    // length check passes and the alphabet check must catch the bytes.
    let input = format!("{}é", "0".repeat(24));
    assert_eq!(input.len(), STRING_LENGTH);
    assert_eq!(
        PikaId::parse(&input),
        Err(Error::InvalidCharacter {
            byte: 0xC3,
            index: 24
        })
    );

    // A 25-byte ASCII prefix plus the same character is 27 bytes.
    let longer = format!("{}é", "0".repeat(25));
    assert_eq!(
        PikaId::parse(&longer),
        Err(Error::InvalidLength {
            actual: 27,
            expected: STRING_LENGTH
        })
    );
}

#[test]
fn uppercase_and_punctuation_are_rejected_at_their_byte_offsets() {
    let cases: &[(usize, u8)] = &[(0, b'A'), (6, b'Z'), (7, b'Q'), (25, b'-')];
    for &(index, byte) in cases {
        let mut bytes = *b"00000000000000000000000000";
        bytes[index] = byte;
        let input = core::str::from_utf8(&bytes).expect("ASCII");
        assert_eq!(
            PikaId::parse(input),
            Err(Error::InvalidCharacter { byte, index }),
            "offset {index}"
        );
        assert!(!PikaId::is_valid(input));
    }

    // Whitespace and a NUL are rejected as well; nothing is trimmed.
    assert!(PikaId::parse(" 0000000000000000000000000").is_err());
    assert!(PikaId::parse("00000000000000000000000000 ").is_err());
    assert!(PikaId::parse("0000000000000000000000000\0").is_err());
}

#[test]
fn binary_length_and_timestamp_boundaries() {
    for length in [0usize, 1, 16, 18, 34] {
        let input = vec![0u8; length];
        assert_eq!(
            PikaIdBinary::parse(&input),
            Err(Error::InvalidLength {
                actual: length,
                expected: BINARY_LENGTH
            })
        );
    }
    assert!(PikaIdBinary::parse(&[0u8; BINARY_LENGTH]).is_ok());

    // MAX_TIMESTAMP in five big-endian bytes is 12 3e de 3f ff.
    let mut max = [0u8; BINARY_LENGTH];
    max[..5].copy_from_slice(&MAX_TIMESTAMP.to_be_bytes()[3..]);
    assert_eq!(max[..5], [0x12, 0x3e, 0xde, 0x3f, 0xff]);
    assert_eq!(
        PikaIdBinary::parse(&max).expect("max is valid").timestamp(),
        MAX_TIMESTAMP
    );

    // One more is rejected rather than truncated.
    let mut overflow = [0u8; BINARY_LENGTH];
    overflow[..5].copy_from_slice(&(MAX_TIMESTAMP + 1).to_be_bytes()[3..]);
    assert_eq!(
        PikaIdBinary::parse(&overflow),
        Err(Error::TimestampOutOfRange {
            timestamp: MAX_TIMESTAMP + 1
        })
    );

    // A full 40-bit timestamp is representable in the bytes but not in pikaid.
    let mut forty_bit = [0u8; BINARY_LENGTH];
    forty_bit[..5].copy_from_slice(&[0xff; 5]);
    assert_eq!(
        PikaIdBinary::parse(&forty_bit),
        Err(Error::TimestampOutOfRange {
            timestamp: 0xff_ffff_ffff
        })
    );
}

#[test]
fn binary_leading_zeros_are_preserved() {
    let bytes = PikaIdBinary::parse(&[0u8; BINARY_LENGTH]).expect("zero id");
    assert_eq!(bytes.timestamp(), 0);
    assert_eq!(bytes.randomness(), [0u8; RANDOMNESS_BYTES]);
    assert_eq!(bytes.randomness_hex(), "000000000000000000000000");
    assert_eq!(bytes.to_pikaid().as_str(), "00000000000000000000000000");

    // Entropy with a leading zero byte must survive the round trip.
    let entropy = value_to_bytes(0x00_11_22_33_44_55_66_77_88_99_aa_bb);
    let id = PikaId::from_parts(1_700_000_000, entropy).expect("valid");
    assert_eq!(id.as_str(), "0s44we8002loz3po6mcf6vsn23");
    assert_eq!(id.randomness(), entropy);
    assert_eq!(id.randomness()[0], 0x00);
    assert_eq!(id.to_binary().randomness(), entropy);
}

#[test]
fn canonical_text_has_no_alternative_representation() {
    // Fixed-width fields mean padding is not optional: dropping a leading zero
    // changes the length and is rejected rather than accepted as a short id.
    let canonical = "00000000000000000000000001";
    assert!(PikaId::parse(canonical).is_ok());
    assert_eq!(
        PikaId::parse("0000000000000000000000001"),
        Err(Error::InvalidLength {
            actual: 25,
            expected: STRING_LENGTH
        })
    );
}

/// Places a 96-bit value in the low 12 bytes of a 16-byte buffer.
fn value_to_bytes(value: u128) -> [u8; RANDOMNESS_BYTES] {
    let bytes = value.to_be_bytes();
    let mut out = [0u8; RANDOMNESS_BYTES];
    out.copy_from_slice(&bytes[4..]);
    out
}
