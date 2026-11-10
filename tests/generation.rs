//! End-to-end generation tests using the real operating-system CSPRNG.
//!
//! Failure injection for the entropy source lives in the crate's unit tests
//! (`src/id.rs`, `src/binary.rs`) because the injectable trait is private; the
//! public API can only be observed through these system-backed paths.

use std::time::{SystemTime, UNIX_EPOCH};

use pikaid::{MAX_TIMESTAMP, PikaId, PikaIdBinary, RANDOMNESS_BYTES};

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

#[test]
fn generated_id_is_canonical_and_internally_consistent() {
    let before = now_seconds();
    let id = PikaId::generate().expect("OS CSPRNG and clock are available");
    let after = now_seconds();

    assert_eq!(id.as_str().len(), 26);
    assert!(
        id.as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
    );
    assert!(PikaId::is_well_formed(id.as_str()));
    assert!(PikaId::is_valid(id.as_str()));
    assert_eq!(PikaId::parse(id.as_str()), Ok(id));
    assert!(id.timestamp() >= before && id.timestamp() <= after);

    // Generation must be lossless through both representations.
    assert_eq!(id.to_binary().to_pikaid(), id);
    assert_eq!(PikaId::from_binary(id.to_binary().as_bytes()), Ok(id));
    assert_eq!(id.randomness().len(), RANDOMNESS_BYTES);
}

#[test]
fn generated_binary_id_round_trips_to_text() {
    let before = now_seconds();
    let bytes = PikaIdBinary::generate().expect("OS CSPRNG and clock are available");
    let after = now_seconds();

    assert_eq!(bytes.as_bytes().len(), 17);
    assert!(bytes.timestamp() >= before && bytes.timestamp() <= after);
    assert_eq!(bytes.to_hex().len(), 34);

    let id = bytes.to_pikaid();
    assert!(PikaId::is_valid(id.as_str()));
    assert_eq!(id.to_binary(), bytes);
    assert_eq!(PikaId::from(bytes), id);
    assert_eq!(PikaIdBinary::parse(bytes.as_bytes()), Ok(bytes));
}

#[test]
fn generate_at_preserves_every_requested_timestamp() {
    for timestamp in [0u64, 1, 1_000_000_000, 1_700_000_000, MAX_TIMESTAMP] {
        let id = PikaId::generate_at(timestamp).expect("timestamp is in range");
        assert_eq!(id.timestamp(), timestamp);
        assert!(PikaId::is_valid(id.as_str()));

        let bytes = PikaIdBinary::generate_at(timestamp).expect("timestamp is in range");
        assert_eq!(bytes.timestamp(), timestamp);
        assert_eq!(
            bytes.to_pikaid(),
            PikaId::parse(bytes.to_pikaid().as_str()).unwrap()
        );
    }
}

#[test]
fn generate_at_rejects_out_of_range_timestamps_before_generating() {
    for timestamp in [MAX_TIMESTAMP + 1, u64::MAX] {
        let text_result = PikaId::generate_at(timestamp);
        let binary_result = PikaIdBinary::generate_at(timestamp);
        assert!(text_result.is_err());
        assert!(binary_result.is_err());
        // Distinct calls both fail closed with the same range error.
        assert_eq!(
            text_result.map_err(|e| e.to_string()),
            Err(format!(
                "timestamp {timestamp} is outside the valid range 0..={MAX_TIMESTAMP}"
            ))
        );
    }
}

#[test]
fn independently_generated_ids_are_distinct_samples() {
    // A 96-bit entropy source makes collisions among 128 values vanishingly
    // unlikely; a failure here means generation stopped using fresh entropy.
    // This is a sanity check, not a uniqueness guarantee of the format.
    let ids: Vec<PikaId> = (0..128)
        .map(|_| PikaId::generate_at(1_700_000_000).expect("generation works"))
        .collect();
    let mut unique: Vec<&str> = ids.iter().map(PikaId::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "entropy source appears to repeat");
    assert!(ids.iter().all(|id| id.timestamp() == 1_700_000_000));
}

#[test]
fn generated_values_sort_within_a_second_by_suffix() {
    let ids: Vec<PikaId> = (0..64)
        .map(|_| PikaId::generate_at(1_700_000_000).expect("generation works"))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert!(pair[0].as_str().as_bytes() <= pair[1].as_str().as_bytes());
        assert!(pair[0].to_binary() <= pair[1].to_binary());
    }
    // Sorting by the random suffix is not the same as creation order, and the
    // implementation makes no monotonicity claim.
    assert_eq!(sorted.len(), ids.len());
}
