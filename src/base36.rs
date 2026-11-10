//! Minimal, allocation-free Base36 encoding helpers.
//!
//! pikaid only ever encodes and decodes fixed-width Base36 fields whose values
//! fit in `u128` (the largest field is 96 bits), so a general-purpose
//! big-integer dependency is unnecessary.

/// Lowercase Base36 alphabet, in ascending digit order.
const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Decodes a single ASCII Base36 digit to its value.
///
/// Uppercase letters, whitespace, punctuation and non-ASCII bytes all return
/// `None`; no normalization is performed.
#[inline]
pub(crate) const fn decode_digit(byte: u8) -> Option<u8> {
    let value = match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'z' => byte - b'a' + 10,
        _ => return None,
    };
    Some(value)
}

/// Decodes a sequence of ASCII Base36 digits into an unsigned integer.
///
/// Returns `None` if any byte is not a lowercase Base36 digit. Callers that
/// need a value bound (for example, 96 bits of randomness) must check the
/// returned integer themselves.
pub(crate) fn decode_digits(digits: &[u8]) -> Option<u128> {
    let mut value: u128 = 0;
    for &digit in digits {
        let digit = u128::from(decode_digit(digit)?);
        // Every pikaid field is narrower than 36^19, and 36^19 fits in u128,
        // so neither this multiply nor the addition can overflow.
        value = value.checked_mul(36)?.checked_add(digit)?;
    }
    Some(value)
}

/// Encodes `value` as lowercase Base36, left-padded with `0` to fill `out`.
///
/// # Panics
///
/// Panics in debug builds if `value` does not fit in `out.len()` Base36 digits.
/// Callers guarantee the bound: the timestamp fits in 7 digits and 96-bit
/// randomness fits in 19 digits.
pub(crate) fn encode_fixed(mut value: u128, out: &mut [u8]) {
    debug_assert!(
        out.len() < 32,
        "fixed-width Base36 fields are at most 19 digits"
    );
    for slot in out.iter_mut().rev() {
        let digit = (value % 36) as usize;
        *slot = ALPHABET[digit];
        value /= 36;
    }
    debug_assert_eq!(value, 0, "value does not fit in the output width");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_is_lowercase_base36() {
        assert_eq!(ALPHABET.len(), 36);
        assert_eq!(decode_digit(b'0'), Some(0));
        assert_eq!(decode_digit(b'9'), Some(9));
        assert_eq!(decode_digit(b'a'), Some(10));
        assert_eq!(decode_digit(b'z'), Some(35));
    }

    #[test]
    fn rejects_everything_outside_the_alphabet() {
        for byte in u8::MIN..=u8::MAX {
            let expected = matches!(byte, b'0'..=b'9' | b'a'..=b'z');
            assert_eq!(
                decode_digit(byte).is_some(),
                expected,
                "byte {byte:#04x} decoding mismatch"
            );
        }
    }

    #[test]
    fn round_trips_known_values() {
        let cases: &[(u128, &[u8])] = &[
            (0, b"0"),
            (1, b"1"),
            (35, b"z"),
            (36, b"10"),
            (36 * 36 * 36 - 1, b"zzz"),
            (u128::from(u32::MAX), b"1z141z3"),
            ((1u128 << 96) - 1, b"7oiylpimjg5u2ca1ypr"),
        ];
        for &(value, encoded) in cases {
            let mut out = vec![0u8; encoded.len()];
            encode_fixed(value, &mut out);
            assert_eq!(out, encoded, "encoding {value}");
            assert_eq!(decode_digits(encoded), Some(value), "decoding {encoded:?}");
        }
    }

    #[test]
    fn fixed_width_padding_preserves_leading_zeros() {
        let mut out = [0u8; 7];
        encode_fixed(0, &mut out);
        assert_eq!(&out, b"0000000");
        encode_fixed(1, &mut out);
        assert_eq!(&out, b"0000001");
        encode_fixed(u128::from(crate::MAX_TIMESTAMP), &mut out);
        assert_eq!(&out, b"zzzzzzz");
    }

    #[test]
    fn decode_rejects_uppercase_and_punctuation() {
        assert_eq!(decode_digits(b"00A"), None);
        assert_eq!(decode_digits(b"00-"), None);
        assert_eq!(decode_digits(b"00 "), None);
        assert_eq!(decode_digits(b""), Some(0));
    }
}
