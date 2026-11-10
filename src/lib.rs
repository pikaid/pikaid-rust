//! Official Rust implementation of [pikaid](https://github.com/pikaid).
//!
//! pikaid is a compact, chronologically sortable identifier. Every value is
//! exactly 26 lowercase ASCII Base36 characters:
//!
//! ```text
//! 0s44we8 002loz3po6mcf6vsn23
//! └──┬──┘ └─────────┬────────┘
//! 7-char          19-char randomness
//! timestamp       (96 bits, Base36)
//! ```
//!
//! An equivalent 17-byte binary form stores the timestamp as five big-endian
//! bytes followed by the twelve randomness bytes unchanged. Both forms sort in
//! chronological order for identifiers with different timestamps.
//!
//! # Quick start
//!
//! ```
//! use pikaid::PikaId;
//!
//! # fn main() -> Result<(), pikaid::Error> {
//! let id = PikaId::generate()?;
//! assert!(PikaId::is_valid(id.as_str()));
//!
//! let parsed = PikaId::parse(id.as_str())?;
//! let bytes = id.to_binary();
//! assert_eq!(parsed.timestamp(), bytes.timestamp());
//! assert_eq!(PikaId::from_binary(bytes.as_bytes())?, id);
//! # Ok(())
//! # }
//! ```
//!
//! # Security and ordering
//!
//! - Randomness comes from the operating system CSPRNG (`getrandom`).
//!   Generation fails closed if the CSPRNG fails.
//! - pikaid is **not** a secret, password, or authentication token. The
//!   timestamp is readable and the identifiers should be treated as public.
//! - Identifiers created in the same second are ordered by their random
//!   suffix, **not** by creation order. pikaid is not a monotonic sequence and
//!   its timestamp has one-second precision.
//! - Uniqueness is probabilistic, not guaranteed. Use a primary key or unique
//!   constraint where uniqueness matters.
//!
//! # Specification
//!
//! The identifier format is immutable and unversioned. This crate implements
//! [pikaid specification revision 1.0.4](https://github.com/pikaid/pikaid-specs/tree/v1.0.4).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod base36;
mod binary;
mod error;
mod id;

pub use binary::PikaIdBinary;
pub use error::Error;
pub use id::PikaId;

use std::time::{SystemTime, UNIX_EPOCH};

/// Number of characters in the textual representation.
pub const STRING_LENGTH: usize = 26;

/// Number of bytes in the binary representation.
pub const BINARY_LENGTH: usize = 17;

/// Number of Base36 characters used for the timestamp.
pub const TIMESTAMP_DIGITS: usize = 7;

/// Number of bytes used for the timestamp in binary form.
pub const TIMESTAMP_BYTES: usize = 5;

/// Number of Base36 characters used for the randomness.
pub const RANDOMNESS_DIGITS: usize = 19;

/// Number of random bytes stored in a pikaid (96 bits).
pub const RANDOMNESS_BYTES: usize = 12;

/// Largest representable timestamp: `36^7 - 1` (`4453-04-05T15:21:35Z`).
pub const MAX_TIMESTAMP: u64 = 78_364_164_095;

/// Largest representable randomness value: `2^96 - 1`.
pub(crate) const MAX_RANDOMNESS: u128 = (1 << 96) - 1;

/// Abstraction over the cryptographic entropy source.
///
/// Production generation uses [`SystemEntropy`]; the trait exists so tests can
/// inject a deterministic or failing source without weakening the public API.
pub(crate) trait EntropySource {
    fn fill(&self, dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error>;
}

/// Operating-system CSPRNG backed by `getrandom`.
pub(crate) struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill(&self, dest: &mut [u8; RANDOMNESS_BYTES]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::EntropySource)
    }
}

/// Returns the current Unix time in whole seconds, range-checked.
pub(crate) fn system_timestamp() -> Result<u64, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::ClockBeforeUnixEpoch)?;
    let seconds = elapsed.as_secs();
    if seconds > MAX_TIMESTAMP {
        return Err(Error::ClockOutOfRange);
    }
    Ok(seconds)
}

/// Formats bytes as lowercase hexadecimal.
pub(crate) fn encode_hex(bytes: &[u8], out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_specification() {
        assert_eq!(STRING_LENGTH, TIMESTAMP_DIGITS + RANDOMNESS_DIGITS);
        assert_eq!(BINARY_LENGTH, TIMESTAMP_BYTES + RANDOMNESS_BYTES);
        assert_eq!(MAX_TIMESTAMP, 36u64.pow(7) - 1);
        assert_eq!(MAX_RANDOMNESS, (1u128 << 96) - 1);
        // 36^19 is larger than 2^96, which is why the suffix needs a range check.
        assert!(36u128.pow(19) > MAX_RANDOMNESS);
        // 36^7 - 1 fits in 36 bits and therefore in five bytes.
        const { assert!(MAX_TIMESTAMP < (1 << 40)) };
    }

    #[test]
    fn hex_helper_handles_nibbles() {
        let mut out = String::new();
        encode_hex(&[0x00, 0x0f, 0xa5, 0xff], &mut out);
        assert_eq!(out, "000fa5ff");
    }
}
