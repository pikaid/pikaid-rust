# Official PikaID conformance suite

This crate is verified against the official cross-language conformance suite at
an immutable revision:

| Item              | Value                                      |
| ----------------- | ------------------------------------------ |
| Repository        | `https://github.com/pikaid/pikaid-specs`   |
| Commit            | `059780cc0e5b113443812720d95c630649bf3aa3` |
| Package revision  | `1.0.0`                                    |
| Spec revision     | `1.0.4`                                    |
| Fixture cases     | 1,100 (596 valid, 258 invalid-string, 33 invalid-binary, 186 ordering, 12 generation, 15 properties) |

The suite is **never vendored** into this repository and is **not** a runtime
dependency. `ci/official/run.sh` clones (or reuses) the pinned commit, verifies
`SHA256SUMS`, the manifest/schema/semantic checks and the suite's own
self-tests, and then drives this crate through a test-only bridge.

## What is in `ci/`

| Path                        | Purpose |
| --------------------------- | ------- |
| `ci/adapter/`               | Test-only JSON-Lines bridge (`publish = false`, path dependency on the crate) |
| `ci/official/run.sh`        | End-to-end pinned-suite run, including the default-mode audit gate |
| `ci/official/mutation_controls.sh` | Proves the runner rejects deliberate defects |
| `ci/consumer/`              | External consumer built against the packaged archive |

Neither `ci/` nor `ci/adapter/` is part of the published crate; `Cargo.toml`
lists the archive contents explicitly and CI rejects archives that contain
repository-only paths.

## Capability mapping

The bridge advertises exactly the capabilities that map to real, public
operations of this crate. Every PikaID answer comes from the library; the bridge
only transports JSON and hexadecimal text.

| Capability                     | Public API used |
| ------------------------------ | --------------- |
| `generate_string`              | `PikaId::generate()` |
| `text_to_binary`               | `PikaId::parse()` + `PikaId::to_binary().to_hex()` |
| `binary_to_text`               | `PikaId::from_binary()` + `PikaId::as_str()` |
| `boolean_validation`           | `PikaId::is_valid()` |
| `format_only_validation`       | `PikaId::is_well_formed()` |
| `parse_components`             | `PikaId::parse()` + `timestamp()` / `randomness_hex()` |
| `generate_with_timestamp`      | `PikaId::generate_at()` |
| `generate_binary`              | `PikaIdBinary::generate()` + `to_hex()` |
| `generate_binary_with_timestamp` | `PikaIdBinary::generate_at()` + `to_hex()` |
| `public_compare`               | `PikaId::parse()` + `Ord` |

### Capabilities deliberately not advertised

- **`parse_datetime`** — the crate has no calendar or date type. It exposes
  integer Unix seconds only, so advertising a datetime operation would require
  inventing one in the adapter. The bridge answers with an error instead of
  synthesizing a value.
- **`csprng_failure_injection`** — the entropy seam (`EntropySource`) is
  `pub(crate)`, and production code is `#![forbid(unsafe_code)]`. Injecting
  failures through a public API would add a hostile capability to the shipped
  crate purely for a test. Entropy failure is instead covered by the crate's own
  unit tests through the crate-private seam.

Because of these gaps the suite records **3 `not_applicable` property
entries** (`P-GENERATE-RNG-SOURCE`, `P-GENERATE-RNG-FAILURE`, `P-PARSE-UTC`).
The run is reported as `AUTOMATED_PASS_AUDIT_NOT_PERFORMED`, never as a
certification.

## Running locally

```sh
# 1. Fetch the pinned suite once (any directory works).
git clone https://github.com/pikaid/pikaid-specs.git .ai/reference/pikaid-specs-conformance
git -C .ai/reference/pikaid-specs-conformance checkout \
  059780cc0e5b113443812720d95c630649bf3aa3

# 2. Run the official automated checks + default-mode gate.
ci/official/run.sh --suite .ai/reference/pikaid-specs-conformance \
  --report .ai/run/conformance-report.json

# 3. Prove the runner rejects deliberate defects.
ci/official/mutation_controls.sh --suite .ai/reference/pikaid-specs-conformance
```

Requirements: `git`, `cargo`, `node` and Python 3.11+. `run.sh` creates its
virtual environment **outside** the suite checkout, because the suite's checksum
coverage hashes every file under `conformance/`.

`--pikaid-path DIR` points the bridge at an unpacked `.crate` instead of the
worktree, so the published artifact can be tested with the same suite.

## What a pass means

`run.sh` exits 0 only when:

1. the suite's fixture integrity, schemas and mathematical consistency pass;
2. the suite's own validator and runner self-tests pass;
3. the independent Node.js BigInt oracle passes;
4. all 1,100 automated cases pass through this crate;
5. a second default-mode run still exits `3` with
   `certification: NOT_A_CONFORMANCE_CERTIFICATION` and the two CSPRNG audits
   outstanding.

It is **not** a conformance certification and **not** security evidence. The
suite requires a reviewed, implementation-specific CSPRNG document for
`P-GENERATE-RNG-SOURCE` and `P-GENERATE-RNG-FAILURE`; that document does not
exist for this repository, so those obligations stay outstanding.
