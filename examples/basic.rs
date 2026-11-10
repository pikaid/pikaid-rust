//! The example from the README, kept compilable as a regression check.

use pikaid::{PikaId, PikaIdBinary};

fn main() -> Result<(), pikaid::Error> {
    // Current time + operating-system CSPRNG.
    let id = PikaId::generate()?;
    println!("{id}"); // 26 lowercase Base36 characters
    println!("{}", id.timestamp()); // Unix seconds
    println!("{}", id.randomness_hex()); // 24 lowercase hex characters

    // Binary form for compact storage.
    let bytes: PikaIdBinary = id.to_binary();
    assert_eq!(bytes.as_bytes().len(), 17);
    assert_eq!(PikaId::from_binary(bytes.as_bytes())?, id);

    // Strict parsing: no trimming, normalizing or truncating.
    let parsed = PikaId::parse(id.as_str())?;
    assert_eq!(parsed, id);
    assert!(PikaId::parse("000000A0000000000000000000").is_err());
    assert!(PikaId::parse("0000000zzzzzzzzzzzzzzzzzzz").is_err());

    // Deterministic construction for fixtures and migrations.
    let fixed = PikaId::from_parts(1_700_000_000, [0u8; 12])?;
    assert_eq!(fixed.as_str(), "0s44we80000000000000000000");

    // Explicit timestamps for backfills.
    let historical = PikaId::generate_at(1_700_000_000)?;
    assert_eq!(historical.timestamp(), 1_700_000_000);

    Ok(())
}
