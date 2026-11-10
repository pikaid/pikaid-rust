//! The 26-character textual pikaid type.

use core::fmt;
use core::str::FromStr;

use crate::base36;
use crate::binary::PikaIdBinary;
use crate::{
    EntropySource, Error, MAX_RANDOMNESS, MAX_TIMESTAMP, RANDOMNESS_BYTES, STRING_LENGTH,
    SystemEntropy, TIMESTAMP_DIGITS, encode_hex, system_timestamp,
};

/// A validated 26-character pikaid.
///
/// A `PikaId` can only be created through generation, [`PikaId::parse`] or
/// [`PikaId::from_parts`], so every value satisfies the pikaid invariants:
///
/// - exactly 26 lowercase Base36 characters;
/// - timestamp in `0..=36^7 - 1`;
/// - randomness in `0..=2^96 - 1`.
///
/// `PikaId` implements `Ord` using the canonical bytewise order, which sorts
/// chronologically for identifiers with different timestamps.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PikaId([u8; STRING_LENGTH]);

impl PikaId {
    /// Generates a pikaid from the current system time and OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClockBeforeUnixEpoch`], [`Error::ClockOutOfRange`] or
    /// [`Error::EntropySource`] when the clock is unusable or the operating
    /// system random number generator fails. No identifier is returned on
    /// failure.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let id = pikaid::PikaId::generate()?;
    /// assert_eq!(id.as_str().len(), 26);
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate() -> Result<Self, Error> {
        Self::generate_at(system_timestamp()?)
    }

    /// Generates a pikaid for an explicit Unix timestamp in seconds.
    ///
    /// Randomness still comes from the OS CSPRNG. This is useful for migrations,
    /// deterministic fixtures and backfilling historical data.
    ///
    /// Negative timestamps are not representable because the parameter is
    /// `u64`; callers holding signed values must reject negatives before
    /// conversion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampOutOfRange`] when `timestamp > 78_364_164_095`
    /// and [`Error::EntropySource`] when the OS CSPRNG fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let id = pikaid::PikaId::generate_at(1_700_000_000)?;
    /// assert_eq!(id.timestamp(), 1_700_000_000);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Builds a pikaid from a timestamp and exactly 12 randomness bytes.
    ///
    /// This is the deterministic counterpart of [`PikaId::generate_at`]. The
    /// randomness is used verbatim, including leading zero bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimestampOutOfRange`] when `timestamp > 78_364_164_095`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let id = pikaid::PikaId::from_parts(1, [0; 12])?;
    /// assert_eq!(id.as_str(), "00000010000000000000000000");
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_parts(timestamp: u64, randomness: [u8; RANDOMNESS_BYTES]) -> Result<Self, Error> {
        if timestamp > MAX_TIMESTAMP {
            return Err(Error::TimestampOutOfRange { timestamp });
        }
        Ok(Self::from_valid_parts(timestamp, randomness))
    }

    /// Builds a pikaid from parts that have already been range-checked.
    pub(crate) fn from_valid_parts(timestamp: u64, randomness: [u8; RANDOMNESS_BYTES]) -> Self {
        debug_assert!(timestamp <= MAX_TIMESTAMP);
        let mut bytes = [b'0'; STRING_LENGTH];
        base36::encode_fixed(u128::from(timestamp), &mut bytes[..TIMESTAMP_DIGITS]);
        base36::encode_fixed(
            u128::from_be_bytes(padded_randomness(randomness)),
            &mut bytes[TIMESTAMP_DIGITS..],
        );
        Self(bytes)
    }

    /// Strictly parses a textual pikaid.
    ///
    /// # Errors
    ///
    /// The input must be exactly 26 bytes of lowercase ASCII Base36 and its
    /// randomness must fit in 96 bits. Otherwise the corresponding
    /// [`Error`] is returned:
    /// [`Error::InvalidLength`], [`Error::InvalidCharacter`] or
    /// [`Error::RandomnessOverflow`]. Input is never normalized or truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), pikaid::Error> {
    /// let id = pikaid::PikaId::parse("00000010000000000000000001")?;
    /// assert_eq!(id.timestamp(), 1);
    /// assert!(pikaid::PikaId::parse("0000001000000000000000000A").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(input: &str) -> Result<Self, Error> {
        let bytes = input.as_bytes();
        if bytes.len() != STRING_LENGTH {
            return Err(Error::InvalidLength {
                actual: bytes.len(),
                expected: STRING_LENGTH,
            });
        }
        for (index, &byte) in bytes.iter().enumerate() {
            if base36::decode_digit(byte).is_none() {
                return Err(Error::InvalidCharacter { byte, index });
            }
        }
        let canonical: [u8; STRING_LENGTH] = bytes.try_into().expect("length checked above");
        decode_validated(&canonical)?;
        Ok(Self(canonical))
    }

    /// Returns `true` if `input` is a fully valid pikaid.
    ///
    /// This performs full semantic validation, including the 96-bit randomness
    /// bound. Use [`PikaId::is_well_formed`] for the cheaper shape check.
    #[must_use]
    pub fn is_valid(input: &str) -> bool {
        Self::parse(input).is_ok()
    }

    /// Returns `true` if `input` has pikaid *shape*: 26 bytes from `[0-9a-z]`.
    ///
    /// A well-formed string is not necessarily a valid pikaid: its randomness
    /// may still exceed 96 bits. This helper must not be used as a validity
    /// check.
    #[must_use]
    pub fn is_well_formed(input: &str) -> bool {
        let bytes = input.as_bytes();
        bytes.len() == STRING_LENGTH
            && bytes
                .iter()
                .all(|&byte| base36::decode_digit(byte).is_some())
    }

    /// Returns the embedded Unix timestamp in whole seconds.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        decode_validated(&self.0)
            .expect("PikaId invariant guarantees a valid timestamp")
            .0
    }

    /// Returns the original 12 randomness bytes, including leading zeros.
    #[must_use]
    pub fn randomness(&self) -> [u8; RANDOMNESS_BYTES] {
        decode_validated(&self.0)
            .expect("PikaId invariant guarantees valid randomness")
            .1
    }

    /// Returns the 24-character lowercase hexadecimal randomness.
    ///
    /// This allocates a `String`; use [`PikaId::randomness`] for a copy of the
    /// raw bytes.
    #[must_use]
    pub fn randomness_hex(&self) -> String {
        let mut out = String::new();
        encode_hex(&self.randomness(), &mut out);
        out
    }

    /// Returns the canonical textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("pikaid text is ASCII")
    }

    /// Returns the canonical textual representation as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; STRING_LENGTH] {
        &self.0
    }

    /// Converts this value to its 17-byte binary representation.
    #[must_use]
    pub fn to_binary(&self) -> PikaIdBinary {
        let (timestamp, randomness) = decode_validated(&self.0).expect("PikaId invariant holds");
        PikaIdBinary::from_valid_parts(timestamp, randomness)
    }

    /// Parses a 17-byte binary pikaid and returns its textual form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] for buffers that are not exactly 17
    /// bytes and [`Error::TimestampOutOfRange`] when the five-byte timestamp
    /// exceeds `36^7 - 1`.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PikaIdBinary::parse(bytes)?.to_pikaid())
    }
}

/// Decodes the two Base36 fields of an already length- and alphabet-checked
/// pikaid.
fn decode_validated(bytes: &[u8; STRING_LENGTH]) -> Result<(u64, [u8; RANDOMNESS_BYTES]), Error> {
    let timestamp =
        base36::decode_digits(&bytes[..TIMESTAMP_DIGITS]).expect("alphabet checked by caller");
    // Seven Base36 digits can never exceed 36^7 - 1, so this cast and check
    // are both total. The check documents the invariant explicitly.
    let timestamp = u64::try_from(timestamp).expect("timestamp fits in u64");
    if timestamp > MAX_TIMESTAMP {
        return Err(Error::TimestampOutOfRange { timestamp });
    }

    let randomness =
        base36::decode_digits(&bytes[TIMESTAMP_DIGITS..]).expect("alphabet checked by caller");
    if randomness > MAX_RANDOMNESS {
        return Err(Error::RandomnessOverflow);
    }

    Ok((timestamp, randomness_from_u128(randomness)))
}

/// Places a 96-bit value in the low bytes of a 128-bit big-endian buffer.
fn padded_randomness(randomness: [u8; RANDOMNESS_BYTES]) -> [u8; 16] {
    let mut padded = [0u8; 16];
    padded[16 - RANDOMNESS_BYTES..].copy_from_slice(&randomness);
    padded
}

/// Converts a 96-bit value to exactly 12 big-endian bytes.
fn randomness_from_u128(value: u128) -> [u8; RANDOMNESS_BYTES] {
    let bytes = value.to_be_bytes();
    let mut out = [0u8; RANDOMNESS_BYTES];
    out.copy_from_slice(&bytes[16 - RANDOMNESS_BYTES..]);
    out
}

impl fmt::Display for PikaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for PikaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PikaId({})", self.as_str())
    }
}

impl FromStr for PikaId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for PikaId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for PikaId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<PikaId> for PikaIdBinary {
    fn from(id: PikaId) -> Self {
        id.to_binary()
    }
}

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
        fn fill(&self, dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error> {
            dest.fill(0xAA);
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
    fn generation_fails_closed_without_returning_partial_entropy() {
        let result = PikaId::generate_at_with(1, &FailingEntropy);
        assert_eq!(result, Err(Error::EntropySource));
    }

    #[test]
    fn generation_uses_the_supplied_entropy_verbatim() {
        let id = PikaId::generate_at_with(0, &FixedEntropy([0xFF; RANDOMNESS_BYTES]))
            .expect("generation succeeds");
        assert_eq!(id.as_str(), "00000007oiylpimjg5u2ca1ypr");
        assert_eq!(id.randomness(), [0xFF; RANDOMNESS_BYTES]);
    }

    #[test]
    fn invalid_timestamps_are_rejected_before_entropy_is_read() {
        // PanicEntropy proves the ordering: reading entropy first would abort.
        let result = PikaId::generate_at_with(MAX_TIMESTAMP + 1, &PanicEntropy);
        assert_eq!(
            result,
            Err(Error::TimestampOutOfRange {
                timestamp: MAX_TIMESTAMP + 1
            })
        );
    }

    #[test]
    fn from_parts_rejects_timestamp_overflow() {
        assert_eq!(
            PikaId::from_parts(MAX_TIMESTAMP + 1, [0; 12]),
            Err(Error::TimestampOutOfRange {
                timestamp: MAX_TIMESTAMP + 1
            })
        );
    }

    #[test]
    fn timestamp_and_randomness_round_trip_through_text() {
        let id = PikaId::from_parts(
            1_700_000_000,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            ],
        )
        .expect("valid parts");
        assert_eq!(id.timestamp(), 1_700_000_000);
        assert_eq!(
            id.randomness(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB
            ]
        );
        assert_eq!(id.randomness_hex(), "00112233445566778899aabb");
        assert_eq!(PikaId::parse(id.as_str()), Ok(id));
    }

    #[test]
    fn parse_reports_the_exact_error() {
        assert_eq!(
            PikaId::parse(""),
            Err(Error::InvalidLength {
                actual: 0,
                expected: STRING_LENGTH
            })
        );
        assert_eq!(
            PikaId::parse("0000001000000000000000000"),
            Err(Error::InvalidLength {
                actual: 25,
                expected: STRING_LENGTH
            })
        );
        assert_eq!(
            PikaId::parse("000000A0000000000000000000"),
            Err(Error::InvalidCharacter {
                byte: b'A',
                index: 6
            })
        );
        assert_eq!(
            PikaId::parse("0000000zzzzzzzzzzzzzzzzzzz"),
            Err(Error::RandomnessOverflow)
        );
    }

    #[test]
    fn well_formed_is_weaker_than_valid() {
        let overflow = "0000000zzzzzzzzzzzzzzzzzzz";
        assert!(PikaId::is_well_formed(overflow));
        assert!(!PikaId::is_valid(overflow));
    }

    #[test]
    fn display_debug_and_as_ref_agree() {
        let id = PikaId::from_parts(1, [1; 12]).expect("valid parts");
        assert_eq!(id.to_string(), id.as_str());
        assert_eq!(format!("{id:?}"), format!("PikaId({})", id.as_str()));
        assert_eq!(<PikaId as AsRef<str>>::as_ref(&id), id.as_str());
        assert_eq!(id.as_bytes().len(), STRING_LENGTH);
    }

    #[test]
    fn from_str_and_try_from_match_parse() {
        let text = "00000010000000000000000001";
        let expected = PikaId::parse(text).expect("valid");
        assert_eq!(text.parse::<PikaId>(), Ok(expected));
        assert_eq!(PikaId::try_from(text), Ok(expected));
    }
}
