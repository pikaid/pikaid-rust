//! Error type shared by parsing, conversion and generation.

use core::fmt;

use crate::MAX_TIMESTAMP;

/// Every way a pikaid operation can fail.
///
/// The variants are intentionally granular so callers can react to the exact
/// cause instead of parsing an error message. Invalid input is always reported
/// as an error; pikaid never truncates, wraps or silently normalizes values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input had the wrong number of bytes.
    InvalidLength {
        /// Number of bytes that were supplied.
        actual: usize,
        /// Number of bytes that were required (26 for text, 17 for binary).
        expected: usize,
    },

    /// The input contained a byte outside the lowercase Base36 alphabet.
    InvalidCharacter {
        /// The offending byte.
        byte: u8,
        /// Byte offset of the offending byte.
        index: usize,
    },

    /// The nineteen-character randomness field decoded to a value above
    /// `2^96 - 1`.
    RandomnessOverflow,

    /// A timestamp was outside `0..=78_364_164_095` (`36^7 - 1`).
    TimestampOutOfRange {
        /// The rejected timestamp.
        timestamp: u64,
    },

    /// The system clock reported a time before the Unix epoch.
    ClockBeforeUnixEpoch,

    /// The system clock reported a time beyond [`MAX_TIMESTAMP`].
    ClockOutOfRange,

    /// The operating system cryptographic random number generator failed.
    ///
    /// Generation fails closed: no identifier is produced from partial or
    /// uninitialized entropy.
    EntropySource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::InvalidCharacter { byte, index } => {
                if byte.is_ascii_graphic() {
                    write!(
                        f,
                        "invalid character {:?} at byte {index}; only lowercase Base36 [0-9a-z] is allowed",
                        char::from(*byte)
                    )
                } else {
                    write!(
                        f,
                        "invalid non-ASCII or control byte {byte:#04x} at byte {index}; only lowercase Base36 [0-9a-z] is allowed"
                    )
                }
            }
            Self::RandomnessOverflow => write!(
                f,
                "randomness exceeds 96 bits (2^96 - 1); the value is not a valid pikaid"
            ),
            Self::TimestampOutOfRange { timestamp } => write!(
                f,
                "timestamp {timestamp} is outside the valid range 0..={MAX_TIMESTAMP}"
            ),
            Self::ClockBeforeUnixEpoch => {
                write!(
                    f,
                    "system clock is before the Unix epoch (1970-01-01T00:00:00Z)"
                )
            }
            Self::ClockOutOfRange => write!(
                f,
                "system clock is beyond the maximum pikaid timestamp {MAX_TIMESTAMP}"
            ),
            Self::EntropySource => {
                write!(
                    f,
                    "the operating system cryptographic random number generator failed"
                )
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_specific() {
        assert_eq!(
            Error::InvalidLength {
                actual: 25,
                expected: 26
            }
            .to_string(),
            "expected 26 bytes, got 25"
        );
        assert!(
            Error::InvalidCharacter {
                byte: b'A',
                index: 6
            }
            .to_string()
            .contains("'A' at byte 6")
        );
        assert!(
            Error::InvalidCharacter {
                byte: 0xC3,
                index: 0
            }
            .to_string()
            .contains("non-ASCII")
        );
        assert!(
            Error::TimestampOutOfRange {
                timestamp: MAX_TIMESTAMP + 1
            }
            .to_string()
            .contains("78364164095")
        );
        assert!(Error::RandomnessOverflow.to_string().contains("96 bits"));
        assert!(
            Error::ClockBeforeUnixEpoch
                .to_string()
                .contains("before the Unix epoch")
        );
        assert!(Error::ClockOutOfRange.to_string().contains("78364164095"));
        assert!(
            Error::EntropySource
                .to_string()
                .contains("random number generator failed")
        );
    }

    #[test]
    fn error_is_a_std_error() {
        fn assert_error<E: core::error::Error>() {}
        assert_error::<Error>();
    }
}
