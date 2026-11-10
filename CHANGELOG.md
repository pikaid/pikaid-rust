# Changelog

All notable changes to the official Rust implementation of pikaid are
documented here. This project adheres to [Semantic Versioning](https://semver.org/).

The pikaid identifier format is immutable and unversioned. Crate versions track
this implementation, not the identifier format, which is defined by
[pikaid-specs](https://github.com/pikaid/pikaid-specs) revision 1.0.4.

## [1.0.0] — 2026-11-07

First stable release of the official Rust implementation, targeting pikaid
specification revision 1.0.4.

### Added

- `PikaId`, the validated 26-character lowercase Base36 identifier.
- `PikaIdBinary`, the validated 17-byte binary representation
  (5-byte big-endian timestamp + 12 randomness bytes).
- `PikaId::generate`, `PikaIdBinary::generate`, and `generate_at` variants that
  read the current UTC time and 96 bits from the operating-system CSPRNG.
- `from_parts` constructors for deterministic fixtures and migrations.
- Strict `parse`, `is_well_formed`, and `is_valid` validation with no trimming,
  normalization, coercion, or truncation.
- Typed `Error` enum covering invalid length, alphabet, timestamp overflow,
  randomness overflow, clock errors, and entropy failures.
- Text and binary round trips, bytewise `Ord`, `Copy`, and `Hash`.
- Official cross-language conformance verification: `ci/official/run.sh` runs
  the pinned `pikaid-specs` suite (commit `059780c`, package revision `1.0.0`,
  spec revision `1.0.4`) through a test-only JSON-Lines bridge, and
  `ci/official/mutation_controls.sh` proves the runner rejects deliberate
  defects.
- A push-triggered CI job runs the official suite and the mutation controls with
  read-only permissions.
- A documented six-month support and security-fix policy, including the tested
  MSRV and platform matrix.

### Guarantees

- `#![forbid(unsafe_code)]`.
- Entropy acquisition fails closed: a CSPRNG failure returns `Error` and never
  produces a partial identifier.
- Official interoperability vectors from pikaid-php v1.2.0 pass unchanged.
- Minimum supported Rust version: 1.85 (edition 2024).

### Release status

This version is prepared in the repository but **not yet published to
crates.io**, and no git tag has been created. See the README for the current
release status.

[1.0.0]: https://github.com/pikaid/pikaid-rust
