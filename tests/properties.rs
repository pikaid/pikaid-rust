//! Property and randomized round-trip tests.
//!
//! The pseudo-random generator below only produces *test inputs*; it is not
//! used by the crate. Expected outputs come from the independent arithmetic
//! oracle in `boundaries.rs` and the official fixtures in `conformance.rs`.
//!
//! The final section adds bounded, deterministic mutation controls: they sweep a
//! fixed mutation space instead of fuzzing (`cargo-fuzz` is not available in
//! this environment) and then prove the sweep is discriminating by running it
//! against a deliberately permissive decoder.

use pikaid::{BINARY_LENGTH, Error, MAX_TIMESTAMP, PikaId, PikaIdBinary, RANDOMNESS_BYTES};

/// Deterministic xorshift64* generator so failures are reproducible.
struct TestRng(u64);

impl TestRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn next_u128(&mut self) -> u128 {
        (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
    }

    fn next_timestamp(&mut self) -> u64 {
        self.next_u64() % (MAX_TIMESTAMP + 1)
    }

    fn next_entropy(&mut self) -> [u8; 12] {
        let value = self.next_u128() & ((1u128 << 96) - 1);
        let mut out = [0u8; 12];
        out.copy_from_slice(&value.to_be_bytes()[4..]);
        out
    }
}

#[test]
fn randomized_text_binary_parts_round_trips() {
    let mut rng = TestRng(0x5eed_1234_abcd_9876);
    for iteration in 0..5_000 {
        let timestamp = rng.next_timestamp();
        let entropy = rng.next_entropy();

        let id = PikaId::from_parts(timestamp, entropy).expect("timestamp is in range");
        assert_eq!(id.timestamp(), timestamp, "iteration {iteration}");
        assert_eq!(id.randomness(), entropy, "iteration {iteration}");
        assert_eq!(id.as_str().len(), 26);
        assert!(
            id.as_str()
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        );

        // Text -> parsed -> binary -> text.
        let parsed = PikaId::parse(id.as_str()).expect("canonical text parses");
        assert_eq!(parsed, id, "iteration {iteration}");
        let binary = id.to_binary();
        assert_eq!(binary.timestamp(), timestamp);
        assert_eq!(binary.randomness(), entropy);
        assert_eq!(binary.to_pikaid(), id);
        assert_eq!(PikaId::from_binary(binary.as_bytes()), Ok(id));
        assert_eq!(PikaIdBinary::parse(binary.as_bytes()), Ok(binary));
        assert_eq!(PikaId::from(binary), id);
        assert_eq!(PikaIdBinary::from(id), binary);

        // The canonical text is exactly the Base36 encodings of both fields.
        assert_eq!(
            id.as_str(),
            format!(
                "{}{}",
                base36(u128::from(timestamp), 7),
                base36(u128::from_be_bytes(pad12(entropy)), 19)
            ),
            "iteration {iteration}"
        );
    }
}

#[test]
fn ordering_follows_unsigned_bytewise_order_across_representations() {
    let mut rng = TestRng(0x0bad_c0de_1234_5678);
    let mut ids = Vec::new();
    for _ in 0..1_000 {
        let id = PikaId::from_parts(rng.next_timestamp(), rng.next_entropy()).expect("valid");
        ids.push(id);
    }
    ids.sort_unstable();

    for pair in ids.windows(2) {
        let (low, high) = (pair[0], pair[1]);
        assert!(low <= high);
        // Text order, binary order and struct order must agree for distinct
        // values, since the text is the canonical encoding of the binary.
        assert_eq!(
            low.as_str().as_bytes() <= high.as_str().as_bytes(),
            low <= high
        );
        assert_eq!(low.to_binary() <= high.to_binary(), low <= high);
        if low.timestamp() < high.timestamp() {
            // Strictly earlier timestamps always sort strictly earlier.
            assert!(low < high);
        }
    }
}

#[test]
fn timestamps_with_different_seconds_sort_chronologically() {
    let mut previous: Option<PikaId> = None;
    for timestamp in [
        0,
        1,
        35,
        36,
        1_000_000,
        2_176_782_335,
        2_176_782_336,
        MAX_TIMESTAMP,
    ] {
        let id = PikaId::from_parts(timestamp, [0xff; 12]).expect("valid timestamp");
        if let Some(previous) = previous {
            assert!(previous.timestamp() < id.timestamp());
            assert!(previous < id, "text order must follow time");
            assert!(previous.to_binary() < id.to_binary());
        }
        previous = Some(id);
    }
}

#[test]
fn same_second_ordering_is_random_not_creation_order() {
    // Two identifiers in the same second are ordered by their random suffix.
    let lower = PikaId::from_parts(1_700_000_000, [0x00; 12]).expect("valid");
    let higher = PikaId::from_parts(1_700_000_000, [0x01; 12]).expect("valid");
    assert!(lower < higher);
    assert_eq!(lower.timestamp(), higher.timestamp());
    assert!(lower.as_str() < higher.as_str());

    // "Generated later" is not represented: creating the smaller value second
    // still sorts first. This is documented, not a bug.
    let later_but_smaller = PikaId::from_parts(1_700_000_000, [0x00; 12]).expect("valid");
    assert!(later_but_smaller < higher);
}

#[test]
fn zero_padding_is_exact_at_every_field_width() {
    for timestamp in [0u64, 1, 35, 36, 36 * 36] {
        let id = PikaId::from_parts(timestamp, [0; 12]).expect("valid");
        assert_eq!(id.timestamp(), timestamp);
        assert_eq!(&id.as_str()[..7], &base36(u128::from(timestamp), 7));
        assert_eq!(&id.as_str()[7..], "0000000000000000000");
    }

    // Every single-bit entropy value must round-trip through 19 Base36 digits.
    for bit in 0..96 {
        let mut entropy = [0u8; 12];
        entropy[11 - bit / 8] = 1 << (bit % 8);
        let value = u128::from_be_bytes(pad12(entropy));
        let id = PikaId::from_parts(0, entropy).expect("valid");
        assert_eq!(id.as_str(), format!("0000000{}", base36(value, 19)));
        assert_eq!(PikaId::parse(id.as_str()), Ok(id));
        assert_eq!(id.to_binary().randomness(), entropy);
    }
}

fn pad12(entropy: [u8; 12]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[4..].copy_from_slice(&entropy);
    out
}

/// Independent fixed-width Base36 encoder used only as a test oracle.
fn base36(mut value: u128, width: usize) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = vec![b'0'; width];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value % 36) as usize];
        value /= 36;
    }
    assert_eq!(value, 0, "value does not fit in {width} digits");
    String::from_utf8(out).expect("ASCII")
}

// ---------------------------------------------------------------------------
// Bounded, deterministic mutation controls.
//
// These are not coverage-guided fuzzing; they sweep a small fixed mutation space
// and assert exact failure modes.
// ---------------------------------------------------------------------------

/// Bytes that must never be accepted by the textual alphabet, including one
/// representative of every class: uppercase letters, printable punctuation,
/// whitespace, control characters and the DEL boundary.
const NON_ALPHABET_BYTES: &[u8] = &[b'A', b'Z', b'-', b'_', b'.', b'+', b' ', b'\t', b'\0', 0x7f];

/// Canonical identifiers used as mutation bases. They cover zero padding, the
/// maximum timestamp and a mid-range value with non-zero randomness.
fn bases() -> Vec<PikaId> {
    vec![
        PikaId::from_parts(0, [0; RANDOMNESS_BYTES]).expect("zero id"),
        PikaId::from_parts(MAX_TIMESTAMP, [0xff; RANDOMNESS_BYTES]).expect("max id"),
        PikaId::from_parts(1_700_000_000, [0x11; RANDOMNESS_BYTES]).expect("mid id"),
    ]
}

#[test]
fn every_out_of_alphabet_byte_is_rejected_at_its_byte_offset() {
    for base in bases() {
        let text = base.as_str();
        assert_eq!(text.len(), 26);
        let canonical = text.as_bytes().to_owned();

        for index in 0..canonical.len() {
            for &mutant in NON_ALPHABET_BYTES {
                let mut bytes = canonical.clone();
                bytes[index] = mutant;
                let input = core::str::from_utf8(&bytes).expect("single-byte ASCII");

                assert_eq!(
                    PikaId::parse(input),
                    Err(Error::InvalidCharacter {
                        byte: mutant,
                        index
                    }),
                    "mutant {mutant:#04x} at offset {index} of {text}"
                );
                assert!(!PikaId::is_valid(input));
                assert!(!PikaId::is_well_formed(input));
            }
        }
    }
}

/// A deliberately permissive decoder that mirrors the classic defect of
/// accepting uppercase input. The mutation sweep above must fail for it, which
/// shows the sweep is not vacuous.
fn mutant_accepts_uppercase(input: &str) -> bool {
    input.len() == 26
        && input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_alphabetic())
}

#[test]
fn the_mutation_sweep_would_catch_a_permissive_decoder() {
    let text = bases()[2].as_str().to_owned();
    let mut mutant = text.into_bytes();
    mutant[7] = b'A';
    let mutant = core::str::from_utf8(&mutant).expect("ASCII");

    // The real implementation rejects it...
    assert_eq!(
        PikaId::parse(mutant),
        Err(Error::InvalidCharacter {
            byte: b'A',
            index: 7
        })
    );
    // ...while the mutant decoder accepts it, so the assertion above has teeth.
    assert!(mutant_accepts_uppercase(mutant));
}

#[test]
fn randomness_byte_mutations_are_accepted_and_preserve_the_timestamp() {
    let timestamp = 1_700_000_000;
    let base = PikaId::from_parts(timestamp, [0; RANDOMNESS_BYTES]).expect("valid");
    let mut bytes = base.to_binary().as_bytes().to_owned();

    for index in 0..RANDOMNESS_BYTES {
        for mutant in [0x01u8, 0x7f, 0x80, 0xff] {
            bytes[5 + index] = mutant;
            let binary = PikaIdBinary::parse(&bytes).expect("any randomness is valid");
            assert_eq!(binary.timestamp(), timestamp);
            assert_eq!(binary.randomness()[index], mutant);

            // Only the mutated byte differs from the base identifier.
            let id = binary.to_pikaid();
            assert_eq!(id.timestamp(), timestamp);
            assert_eq!(id, PikaId::from_binary(&bytes).expect("same value"));
            assert_eq!(id.to_binary(), binary);
            assert_eq!(PikaId::parse(id.as_str()), Ok(id));
        }
        bytes[5 + index] = 0;
    }
    assert_eq!(PikaIdBinary::parse(&bytes), Ok(base.to_binary()));
}

#[test]
fn binary_timestamp_mutations_above_the_maximum_are_rejected() {
    let max = MAX_TIMESTAMP;
    for high_byte in [0x13u8, 0x20, 0x7f, 0x80, 0xff] {
        for random_suffix in [[0u8; RANDOMNESS_BYTES], [0xff; RANDOMNESS_BYTES]] {
            let mut mutant = [0u8; BINARY_LENGTH];
            mutant[0] = high_byte;
            mutant[5..].copy_from_slice(&random_suffix);
            let timestamp = u64::from(high_byte) << 32;

            assert!(timestamp > max);
            assert_eq!(
                PikaIdBinary::parse(&mutant),
                Err(Error::TimestampOutOfRange { timestamp })
            );
            assert_eq!(
                PikaId::from_binary(&mutant),
                Err(Error::TimestampOutOfRange { timestamp })
            );
        }
    }
}
