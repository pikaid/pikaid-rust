//! The 17-byte binary pikaid type.

use core::fmt;

use crate::id::PikaId;
use crate::{
    BINARY_LENGTH, EntropySource, Error, MAX_TIMESTAMP, RANDOMNESS_BYTES, SystemEntropy,
    TIMESTAMP_BYTES, encode_hex, system_timestamp,
};

/// A validated 17-byte pikaid.
///
/// Layout:
///
/// ```text
/// [ 5-byte unsigned timestamp, big-endian ][ 12 randomness bytes, unchanged ]
/// ```
///
/// A `PikaIdBinary` can only be created through generation,
/// [`PikaIdBinary::parse`] or [`PikaIdBinary::from_parts`], so the timestamp
/// always satisfies `timestamp <= 36^7 - 1`. `Ord` is the unsigned bytewise
/// order, which matches the textual order for identifiers with different
/// timestamps.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PikaIdBinary([u8; BINARY_LENGTH]);

impl PikaIdBinary {
    /// Generates a binary pikaid from the current system time and OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClockBeforeUnixEpoch`], [`Error::ClockOutOfRange`] or
    /// [`Error::EntropySource`].
    pub fn generate() -> Result<Self, Error> {
        Self::generate_at(system_timestamp()?)
    }

    /// Generates a binary pikaid for an explicit Unix timestamp in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampOutOfRange`] for timestamps above
    /// `78_364_164_095` and [`Error::EntropySource`] if the OS CSPRNG fails.
    pub fn generate_at(timestamp: u64) -> Result<Self, Error> {
        Self::generate_at_with(timestamp, &SystemEntropy)
    }

    /// Internal generation entry point with an injectable entropy source.
    pub(crate) fn generate_at_with<E: EntropySource>(
        timestamp: u64,
        entropy: &E,
    ) -> Result<Self, Error> {
        if timestamp > MAX_TIMESTAMP {
            return Err(Error::TimestampOutOfRange { timestamp });
        }
        let mut randomness = [0u8; RANDOMNESS_BYTES];
        entropy.fill(&mut randomness)?;
        Ok(Self::from_valid_parts(timestamp, randomness))
    }

    /// Builds a binary pikaid from a timestamp and exactly 12 randomness bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampOutOfRange`] when `timestamp > 78_364_164_095`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let bytes = pikaid::PikaIdBinary::from_parts(1, [0; 12])?;
    /// assert_eq!(bytes.as_bytes()[..5], [0, 0, 0, 0, 1]);
    /// assert_eq!(bytes.to_pikaid().as_str(), "00000010000000000000000000");
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_parts(timestamp: u64, randomness: [u8; RANDOMNESS_BYTES]) -> Result<Self, Error> {
        if timestamp > MAX_TIMESTAMP {
            return Err(Error::TimestampOutOfRange { timestamp });
        }
        Ok(Self::from_valid_parts(timestamp, randomness))
    }

    /// Builds a binary pikaid from parts that have already been range-checked.
    pub(crate) fn from_valid_parts(timestamp: u64, randomness: [u8; RANDOMNESS_BYTES]) -> Self {
        debug_assert!(timestamp <= MAX_TIMESTAMP);
        let mut bytes = [0u8; BINARY_LENGTH];
        let be = timestamp.to_be_bytes();
        bytes[..TIMESTAMP_BYTES].copy_from_slice(&be[8 - TIMESTAMP_BYTES..]);
        bytes[TIMESTAMP_BYTES..].copy_from_slice(&randomness);
        Self(bytes)
    }

    /// Strictly parses a 17-byte binary pikaid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] unless the slice is exactly 17 bytes
    /// and [`Error::TimestampOutOfRange`] if the five-byte timestamp exceeds
    /// `36^7 - 1`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let bytes = pikaid::PikaIdBinary::parse(&[0; 17])?;
    /// assert_eq!(bytes.timestamp(), 0);
    /// assert!(pikaid::PikaIdBinary::parse(&[0; 16]).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        if input.len() != BINARY_LENGTH {
            return Err(Error::InvalidLength {
                actual: input.len(),
                expected: BINARY_LENGTH,
            });
        }
        let timestamp = decode_timestamp(input);
        if timestamp > MAX_TIMESTAMP {
            return Err(Error::TimestampOutOfRange { timestamp });
        }
        Ok(Self(input.try_into().expect("length checked above")))
    }

    /// Returns the embedded Unix timestamp in whole seconds.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        decode_timestamp(&self.0)
    }

    /// Returns the original 12 randomness bytes, including leading zeros.
    #[must_use]
    pub fn randomness(&self) -> [u8; RANDOMNESS_BYTES] {
        let mut out = [0u8; RANDOMNESS_BYTES];
        out.copy_from_slice(&self.0[TIMESTAMP_BYTES..]);
        out
    }

    /// Returns the 24-character lowercase hexadecimal randomness.
    #[must_use]
    pub fn randomness_hex(&self) -> String {
        let mut out = String::new();
        encode_hex(&self.randomness(), &mut out);
        out
    }

    /// Returns the raw 17 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BINARY_LENGTH] {
        &self.0
    }

    /// Converts this value to its canonical 26-character text form.
    ///
    /// The conversion is lossless and cannot fail because construction and
    /// parsing enforce the timestamp bound.
    #[must_use]
    pub fn to_pikaid(&self) -> PikaId {
        PikaId::from_valid_parts(self.timestamp(), self.randomness())
    }

    /// Returns the 34-character lowercase hexadecimal representation.
    ///
    /// This is a debugging convenience; pikaid itself never uses hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::new();
        encode_hex(&self.0, &mut out);
        out
    }
}

/// Decodes the five-byte big-endian timestamp.
fn decode_timestamp(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() >= 5);
    let mut padded = [0u8; 8];
    padded[3..].copy_from_slice(&bytes[..5]);
    u64::from_be_bytes(padded)
}

impl fmt::Debug for PikaIdBinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PikaIdBinary({})", self.to_hex())
    }
}

impl AsRef<[u8]> for PikaIdBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PikaIdBinary {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<[u8; BINARY_LENGTH]> for PikaIdBinary {
    type Error = Error;

    fn try_from(value: [u8; BINARY_LENGTH]) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PikaIdBinary> for PikaId {
    fn from(binary: PikaIdBinary) -> Self {
        binary.to_pikaid()
    }
}

// Compile-time reminders of the exact widths involved.
const _: () = assert!(TIMESTAMP_BYTES + RANDOMNESS_BYTES == BINARY_LENGTH);

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedEntropy([u8; RANDOMNESS_BYTES]);

    impl EntropySource for FixedEntropy {
        fn fill(&self, dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error> {
            *dest = self.0;
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill(&self, _dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error> {
            Err(Error::EntropySource)
        }
    }

    /// Fails the test if generation touches the entropy source at all.
    struct PanicEntropy;

    impl EntropySource for PanicEntropy {
        fn fill(&self, _dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error> {
            panic!("entropy must not be read for an invalid timestamp");
        }
    }

    #[test]
    fn binary_layout_is_big_endian_timestamp_then_randomness() {
        let bytes = PikaIdBinary::from_parts(0x0102_0304, [0xAA; 12]).expect("valid parts");
        assert_eq!(
            bytes.as_bytes(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA
            ]
        );
    }

    #[test]
    fn parse_rejects_wrong_lengths_and_timestamp_overflow() {
        assert_eq!(
            PikaIdBinary::parse(&[0; 16]),
            Err(Error::InvalidLength {
                actual: 16,
                expected: BINARY_LENGTH
            })
        );
        assert_eq!(
            PikaIdBinary::parse(&[0; 18]),
            Err(Error::InvalidLength {
                actual: 18,
                expected: BINARY_LENGTH
            })
        );
        // 0x123ede4000 is MAX_TIMESTAMP + 1.
        let mut overflow = [0u8; BINARY_LENGTH];
        overflow[..TIMESTAMP_BYTES]
            .copy_from_slice(&(MAX_TIMESTAMP + 1).to_be_bytes()[8 - TIMESTAMP_BYTES..]);
        assert_eq!(
            PikaIdBinary::parse(&overflow),
            Err(Error::TimestampOutOfRange {
                timestamp: MAX_TIMESTAMP + 1
            })
        );
        assert_eq!(
            PikaIdBinary::parse(&[0xFF; BINARY_LENGTH]),
            Err(Error::TimestampOutOfRange {
                timestamp: 0xFF_FFFF_FFFF
            })
        );
    }

    #[test]
    fn generation_fails_closed_when_entropy_fails() {
        assert_eq!(
            PikaIdBinary::generate_at_with(0, &FailingEntropy),
            Err(Error::EntropySource)
        );
    }

    #[test]
    fn invalid_timestamps_are_rejected_before_entropy_is_read() {
        // PanicEntropy proves the ordering: reading entropy first would abort.
        assert_eq!(
            PikaIdBinary::generate_at_with(MAX_TIMESTAMP + 1, &PanicEntropy),
            Err(Error::TimestampOutOfRange {
                timestamp: MAX_TIMESTAMP + 1
            })
        );
    }

    #[test]
    fn generation_preserves_supplied_entropy() {
        let bytes =
            PikaIdBinary::generate_at_with(1, &FixedEntropy([0x5A; 12])).expect("generation works");
        assert_eq!(bytes.timestamp(), 1);
        assert_eq!(bytes.randomness(), [0x5A; 12]);
        assert_eq!(bytes.randomness_hex(), "5a5a5a5a5a5a5a5a5a5a5a5a");
    }

    #[test]
    fn text_conversion_round_trips() {
        let bytes =
            PikaIdBinary::from_parts(1_700_000_000, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
                .expect("valid parts");
        let id = bytes.to_pikaid();
        assert_eq!(id.timestamp(), 1_700_000_000);
        assert_eq!(id.randomness(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(id.to_binary(), bytes);
        assert_eq!(PikaId::from(bytes), id);
    }

    #[test]
    fn debug_and_hex_are_lowercase_34_characters() {
        let bytes = PikaIdBinary::from_parts(1, [0xAB; 12]).expect("valid parts");
        assert_eq!(bytes.to_hex().len(), 34);
        assert!(bytes.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            format!("{bytes:?}"),
            format!("PikaIdBinary({})", bytes.to_hex())
        );
        assert_eq!(
            <PikaIdBinary as AsRef<[u8]>>::as_ref(&bytes),
            bytes.as_bytes()
        );
    }

    #[test]
    fn try_from_impls_validate() {
        let raw = [0u8; BINARY_LENGTH];
        assert_eq!(
            PikaIdBinary::try_from(raw),
            Ok(PikaIdBinary::parse(&raw).unwrap())
        );
        assert!(PikaIdBinary::try_from(&raw[..]).is_ok());
        assert!(PikaIdBinary::try_from(&raw[..15]).is_err());
    }
}
