<p align="center">
  <a href="https://github.com/pikaid/pikaid-specs">
    <img src="https://raw.githubusercontent.com/pikaid/pikaid-specs/v1.0.4/logo.png" alt="pikaid" width="300">
  </a>
</p>

<p align="center">
  <strong>Small · Sortable · Secure ID generator</strong>
</p>

<div align="center">

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-DEA584.svg)](https://github.com/pikaid/pikaid-rust)
[![CI](https://github.com/pikaid/pikaid-rust/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pikaid/pikaid-rust/actions/workflows/ci.yml)
[![Official implementation](https://img.shields.io/badge/official-implementation-2e7d32.svg)](https://github.com/pikaid/pikaid-specs)
[![Specification 1.0.4](https://img.shields.io/badge/spec-1.0.4-4b56a6.svg)](https://github.com/pikaid/pikaid-specs/tree/v1.0.4)

</div>

**pikaid** is the **official Rust implementation** of a compact, chronologically sortable, collision-resistant identifier format for databases, APIs, and distributed systems.

This is the immutable, unversioned [pikaid format](https://github.com/pikaid/pikaid-specs/tree/v1.0.4), documented in specification revision **1.0.4**.

## ✨ Why pikaid?

- **Short:** Compact, readable IDs for URLs, logs, and API resources.
- **Sortable:** Lexicographically ordered by timestamp, with **one-second precision**.
- **Collision-resistant:** 96 bits of cryptographic randomness make collisions extremely unlikely, never impossible.
- **Storage-friendly:** Use `BINARY(17)` or readable `CHAR(26)`.
- **Distributed-friendly:** No central sequence generator or coordination required.

## 🧬 Identifier format

A pikaid contains **26 lowercase Base36 characters**: a **7-character Unix-seconds timestamp** followed by **19 characters encoding 96 bits of cryptographic randomness**. Its binary form is **17 bytes**: 5 unsigned big-endian timestamp bytes followed by 12 randomness bytes.

![Identifier structure](https://raw.githubusercontent.com/pikaid/pikaid-specs/v1.0.4/structure.svg)

> **Ordering:** Different seconds sort chronologically. Within the same second, randomness—not issuance order—decides the order.

> **Security:** These are identifiers, **not secrets**, session credentials, authentication tokens, or API keys.

## ⚙️ Requirements

Rust 1.85+ (edition 2024).

## 📦 Installation

The crate is not yet on crates.io. Make a Rust binary project and use the public Git dependency:

```sh
cargo new pikaid-demo
cd pikaid-demo
```

Add this under `[dependencies]` in `Cargo.toml`:

```toml
pikaid = { git = "https://github.com/pikaid/pikaid-rust" }
```

Save the code below as `src/main.rs`, then run `cargo run`.

## 🚀 Basic Usage

```rust
use pikaid::{PikaId, PikaIdBinary};

fn main() -> Result<(), pikaid::Error> {
    // Current time + operating-system CSPRNG.
    let id = PikaId::generate()?;
    println!("{id}");                       // 26 lowercase Base36 characters
    println!("{}", id.timestamp());         // Unix seconds
    println!("{}", id.randomness_hex());    // 24 lowercase hex characters

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
```

## 💡 Example Use Case

Use pikaid to identify **users, orders, invoices, uploads, events, and API resources**. Independent services can generate compact IDs without a shared counter, while timestamp-based ordering helps with indexing, sorting, and logs.

## 📚 Canonical specification

- [Canonical specification](https://github.com/pikaid/pikaid-specs)
- [Revision 1.0.4](https://github.com/pikaid/pikaid-specs/tree/v1.0.4)

Specification revisions describe the format; they do not change the encoded identifiers.

## 🧩 API Reference

| Operation                    | `PikaId`                        | `PikaIdBinary`                  |
| ---------------------------- | ------------------------------- | ------------------------------- |
| Generate now                 | `generate()`                    | `generate()`                    |
| Generate at a timestamp      | `generate_at(u64)`              | `generate_at(u64)`              |
| Build from known parts       | `from_parts(u64, [u8; 12])`     | `from_parts(u64, [u8; 12])`     |
| Strict parse                 | `parse(&str)`                   | `parse(&[u8])`                  |
| Convert                      | `to_binary()` / `from_binary()` | `to_pikaid()`                   |
| Access fields                | `timestamp()`, `randomness()`   | `timestamp()`, `randomness()`   |
| Compare / sort               | `Ord`, `PartialOrd`, `Eq`       | `Ord`, `PartialOrd`, `Eq`       |

Both types are `Copy`, `Hash` and ordered by their canonical bytes. Invalid
input produces a typed [`pikaid::Error`]; the enum is `#[non_exhaustive]` so new
failure modes can be added without a breaking change.

`PikaId::is_well_formed` is a cheap shape check (length and alphabet only).
`PikaId::is_valid` performs full validation, including the 96-bit randomness
bound. Use `is_valid` unless you specifically need the weaker check.

## 🔄 Order Guarantee

- Randomness comes from the OS CSPRNG through [`getrandom`](https://crates.io/crates/getrandom).
  Generation **fails closed**: if the entropy source fails, an error is
  returned and no partial identifier is produced.
- pikaid is **not** a secret, password, capability, or authentication token.
  The timestamp is readable and identifiers should be treated as public.
- Uniqueness is **probabilistic**, not guaranteed. Use a primary key or unique
  constraint where uniqueness matters.
- Different seconds sort chronologically in both text and binary form.
  Identifiers generated **within the same second are not monotonic**; they sort
  by their random suffix, not by creation order. pikaid has one-second
  precision and no sub-second component.
- This crate is `std` only. `no_std` support is not implemented or tested.

## 🛢 Storage Recommendations

| Representation | Size | Recommended for |
| --- | ---: | --- |
| **BINARY(17)** | 17 bytes | Compact primary keys and indexes |
| **CHAR(26)** | 26 characters | Readable SQL, debugging, URLs, and logs |

Use an **ASCII bytewise/binary collation** for text columns (for example, `ascii_bin` on MariaDB/MySQL). Case-insensitive or locale-aware sorting is not a substitute for canonical bytewise comparison.

## ✅ Verification and release status

The [CI workflow](https://github.com/pikaid/pikaid-rust/actions/workflows/ci.yml) runs native tests, pinned automated conformance checks, and language-specific quality gates. To run the native checks locally from a checkout, use `cargo test`.

**Automated passing tests are not a security certification.** The independent CSPRNG source and failure-path audits (`P-GENERATE-RNG-SOURCE` and `P-GENERATE-RNG-FAILURE`) still require separate human evidence.

<details>
<summary>Platform, tooling, and conformance details</summary>

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo run --example basic --locked
python3 scripts/generate_oracle_cases.py --check
cargo package --locked
cargo test --manifest-path "target/package/pikaid-$(cargo pkgid | sed 's/.*@//')/Cargo.toml" --all-targets --locked
sh ci/consumer/run.sh
# Official cross-language suite (needs git, node and Python 3.11+).
ci/official/run.sh --suite <pinned pikaid-specs checkout>
ci/official/mutation_controls.sh --suite <pinned pikaid-specs checkout>
```

### Official conformance suite

`ci/official/run.sh` runs the official PikaID conformance suite pinned to
commit `059780cc0e5b113443812720d95c630649bf3aa3` (package revision `1.0.0`,
spec revision `1.0.4`). It verifies the suite's `SHA256SUMS`, schemas and
mathematical consistency, runs the suite's own self-tests and its independent
Node.js BigInt oracle, then drives this crate through a test-only JSON-Lines
bridge (`ci/adapter/`, excluded from the published archive).

All 1,100 automated cases pass. The suite records two manual CSPRNG audit
obligations and marks three property entries `not_applicable`: the two CSPRNG
entries that can only be discharged by reviewed human evidence, and
`parse_datetime`, which this crate does not expose (it provides integer Unix
seconds, not a calendar type). A run is reported as
`AUTOMATED_PASS_AUDIT_NOT_PERFORMED` — never as a conformance certification.
The repository's `ci/CONFORMANCE.md` documents the capability mapping and
exactly what a pass does and does not mean.

`ci/official/mutation_controls.sh` is the negative control: a permissive
decoder, a wrong encoder alphabet and a doctored bridge must each make the
official runner exit `1`.

### Verification in CI

CI enforces, on every push and pull request:

- **Independent oracle.** `scripts/generate_oracle_cases.py` recomputes the
  pikaid 1.0.4 arithmetic in Python from first principles (it never imports or
  runs this crate). CI re-runs it with `--check`, so
  `tests/vectors/oracle-cases.json` cannot be edited by hand, and
  `tests/oracle.rs` pins the table's SHA-256 and pushes all 334 valid cases
  through every public entry point.
- **Independent fixtures.** The unmodified pikaid-php v1.2.0 vectors are pinned
  by SHA-256 and vendored with `.gitattributes` line-ending protection.
- **Expanded negative corpus.** 22 invalid text inputs and 8 invalid binary
  layouts must report the exact error variant and details.
- **Packaged artifact.** CI runs the tests from the unpacked `.crate`, checks
  the archive contains no repository-only paths, builds an external consumer
  crate against the archive, and verifies that packaging twice produces a
  byte-identical archive.
- **Coverage.** Line coverage must stay at or above 98%.
- **Official conformance.** The pinned official cross-language suite
  (commit `059780c`, package revision 1.0.0) must pass all 1,100 automated
  cases, and mutation controls must prove that a permissive decoder, a wrong
  encoder alphabet and a doctored test bridge each make the runner fail. The
  job also asserts that the suite's default mode still returns `3` without
  reviewed CSPRNG evidence, so missing security evidence can never be
  misreported as a pass.

The conformance suite covers every official pikaid interoperability vector
(vendored from pikaid-php v1.2.0, commit `e3f843e`), independently computed
known answers, boundary and malformed-input cases, randomized round trips,
ordering properties, and generation sanity checks. Expected values never come
from round-tripping the implementation against itself.

Version 1.0.0 is the first stable release of this crate and is prepared in the
repository:

- Source, documentation, tests, and the packaged archive are complete for
  version 1.0.0 and validated on the final commit; the CI workflow encodes the
  same checks. A workflow run that never starts (for example because Actions
  billing is inactive) is not a pass.
- The crate is **not published to crates.io**. Publication is blocked until
  ownership of the `pikaid` crate name is verified and registry credentials are
  configured.
- No release tag exists yet.
- The GitHub repository is currently private.

Until publication, depend on this repository directly as shown under
[Usage](#usage). Nothing from this repository is distributed through any other
registry.

- **Tested toolchains.** Rust **1.85.0** is the minimum supported version and is
  tested on every CI run. Current stable Rust is tested on Linux, macOS and
  Windows; the MSRV is tested on Linux.
- **Six-month window.** From 2026-11-09 through 2027-05-09 the `1.0.x` line
  accepts and ships fixes for critical security defects in identifier parsing,
  validation, binary conversion and entropy-failure handling. This is a
  maintenance target, not a promise that no update will ever be needed.
- **Bounded changes.** Security fixes ship as patch releases. A change that
  requires a new minimum Rust version or an API break is a minor release and is
  not forced into the support window.
- **Reporting.** Report suspected vulnerabilities privately through this
  repository's GitHub Security Advisories rather than a public issue.
- **Not an attestation.** This policy does not claim that an independent
  security review has occurred. The official conformance suite's two manual
  CSPRNG audits remain outstanding until reviewed evidence is published.

</details>

Registry publication is not implied by a green CI: use the installation method documented above.

## 🤝 Contributing

Contributions are always welcome! 💙

Whether you're fixing a typo, improving documentation, adding tests, or making pikaid even better, every contribution is appreciated.

**Want to help? Here's how:**

- 🐛 **Found a bug?** [Open an issue](https://github.com/pikaid/pikaid-rust/issues) with clear reproduction steps.
- 💡 **Have an idea?** Start with an issue before making major changes.
- 🛠️ **Ready to contribute?** Open a pull request explaining your changes.
- 🧪 **Keep it tested.** Add meaningful regression tests for behavior changes and follow the existing conventions.
- ✅ **Make sure CI passes.** All required checks must be green before a pull request is merged. No shortcuts!

**One important rule:** pikaid's identifier format is immutable. Contributions must preserve the [canonical specification (revision 1.0.4)](https://github.com/pikaid/pikaid-specs/tree/v1.0.4).

🔐 **Found a security vulnerability?** Report it privately using GitHub's security reporting (when available), or [contact the maintainer](mailto:larananas.dev@proton.me)—not through a public issue.

**Every improvement matters, big or small. Thanks for helping make pikaid better!** 🐇

## 📄 License

The implementation is available under the [MIT License](LICENSE).

## ✉️ Contact

For licensing or project-related questions: [larananas.dev@proton.me](mailto:larananas.dev@proton.me).

