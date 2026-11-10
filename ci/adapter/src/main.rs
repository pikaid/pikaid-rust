//! Test-only JSON-Lines bridge for the official PikaID conformance suite.
//!
//! This binary is **not** part of the published crate and is **not** a second
//! PikaID implementation. Every PikaID answer is produced by the real public
//! API of the `pikaid` crate; the adapter only performs transport work
//! (JSON envelopes, hexadecimal rendering and request dispatch).
//!
//! See `ci/CONFORMANCE.md` for the capability-to-entry-point mapping and for
//! the capabilities this crate deliberately does not advertise.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use pikaid::{Error, PikaId, PikaIdBinary};
use serde_json::{Map, Value, json};

/// Capabilities mapped to real public operations of this crate.
///
/// `parse_datetime` is not advertised: the crate intentionally exposes integer
/// Unix seconds only and has no calendar/date type. `csprng_failure_injection`
/// is not advertised either: the entropy seam is `pub(crate)` and the suite
/// must not create a public RNG-injection API.
const CAPABILITIES: &[&str] = &[
    "generate_string",
    "text_to_binary",
    "binary_to_text",
    "boolean_validation",
    "format_only_validation",
    "parse_components",
    "generate_with_timestamp",
    "generate_binary",
    "generate_binary_with_timestamp",
    "public_compare",
];

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("adapter: cannot read stdin: {error}");
                std::process::exit(2);
            }
        };
        if line.trim().is_empty() {
            // The protocol sends exactly one JSON object per line; an empty
            // line is a transport violation rather than a PikaID request.
            eprintln!("adapter: empty request line");
            std::process::exit(2);
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("adapter: malformed JSON request: {error}");
                std::process::exit(2);
            }
        };

        let response = catch_unwind(AssertUnwindSafe(|| handle(&request)))
            .unwrap_or_else(|_| envelope(None, Err(Failure::Internal("adapter panicked".into()))));

        match serde_json::to_string(&response) {
            Ok(text) => {
                if writeln!(out, "{text}").and_then(|()| out.flush()).is_err() {
                    std::process::exit(2);
                }
            }
            Err(error) => {
                eprintln!("adapter: cannot serialize response: {error}");
                std::process::exit(2);
            }
        }
    }
}

/// A categorized failure matching the protocol's stable error vocabulary.
enum Failure {
    Invalid(String),
    Entropy(String),
    Internal(String),
    Unsupported(String),
}

impl Failure {
    const fn category(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_input",
            Self::Entropy(_) => "entropy_unavailable",
            Self::Internal(_) => "internal_error",
            Self::Unsupported(_) => "unsupported_operation",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Invalid(message)
            | Self::Entropy(message)
            | Self::Internal(message)
            | Self::Unsupported(message) => message,
        }
    }
}

fn envelope(request_id: Option<i64>, result: Result<Value, Failure>) -> Value {
    match (request_id, result) {
        (Some(request_id), Ok(value)) => json!({
            "request_id": request_id,
            "ok": true,
            "value": value,
        }),
        (Some(request_id), Err(failure)) => json!({
            "request_id": request_id,
            "ok": false,
            "error": {
                "category": failure.category(),
                "message": failure.message(),
            },
        }),
        // Without a usable integer request_id the bridge cannot form a valid
        // success envelope. Emitting an error with `null` makes the runner
        // reject the reply as a protocol error instead of believing it.
        (None, _) => json!({
            "request_id": null,
            "ok": false,
            "error": {
                "category": "internal_error",
                "message": "request is missing an integer request_id",
            },
        }),
    }
}

fn handle(request: &Value) -> Value {
    let request_id = request.get("request_id").and_then(Value::as_i64);
    let result = if request_id.is_none() {
        Err(Failure::Internal(
            "request is missing an integer request_id".into(),
        ))
    } else {
        (|| {
            let operation = request
                .get("operation")
                .and_then(Value::as_str)
                .ok_or_else(|| Failure::Internal("request is missing an operation".into()))?;
            let arguments = request
                .get("arguments")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Failure::Internal("request is missing an arguments object".into())
                })?;
            dispatch(operation, arguments)
        })()
    };

    envelope(request_id, result)
}

fn dispatch(operation: &str, arguments: &Map<String, Value>) -> Result<Value, Failure> {
    match operation {
        "hello" => Ok(json!({
            "protocol_version": 1,
            "capabilities": CAPABILITIES,
        })),
        "generate_string" => PikaId::generate().map(id_value).map_err(map_error),
        "text_to_binary" => {
            let text = argument_str(arguments, "text")?;
            PikaId::parse(text)
                .map(|id| Value::String(id.to_binary().to_hex()))
                .map_err(map_error)
        }
        "binary_to_text" => {
            let hex = argument_str(arguments, "binary_hex")?;
            let bytes = decode_lower_hex(hex, 17)?;
            PikaId::from_binary(&bytes).map(id_value).map_err(map_error)
        }
        "boolean_validation" => {
            let text = argument_str(arguments, "text")?;
            Ok(Value::Bool(PikaId::is_valid(text)))
        }
        "format_only_validation" => {
            let text = argument_str(arguments, "text")?;
            Ok(Value::Bool(PikaId::is_well_formed(text)))
        }
        "parse_components" => {
            let text = argument_str(arguments, "text")?;
            PikaId::parse(text)
                .map(|id| {
                    json!({
                        "timestamp_seconds": id.timestamp(),
                        "randomness_hex": id.randomness_hex(),
                    })
                })
                .map_err(map_error)
        }
        "generate_with_timestamp" => {
            let timestamp = argument_timestamp(arguments)?;
            PikaId::generate_at(timestamp)
                .map(id_value)
                .map_err(map_error)
        }
        "generate_binary" => PikaIdBinary::generate()
            .map(binary_value)
            .map_err(map_error),
        "generate_binary_with_timestamp" => {
            let timestamp = argument_timestamp(arguments)?;
            PikaIdBinary::generate_at(timestamp)
                .map(binary_value)
                .map_err(map_error)
        }
        "public_compare" => {
            let a = PikaId::parse(argument_str(arguments, "a")?).map_err(map_error)?;
            let b = PikaId::parse(argument_str(arguments, "b")?).map_err(map_error)?;
            let ordering = match a.cmp(&b) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            Ok(json!(ordering))
        }
        other => Err(Failure::Unsupported(format!(
            "operation {other:?} is not mapped by this adapter"
        ))),
    }
}

/// Renders a validated identifier as the protocol's JSON string value.
fn id_value(id: PikaId) -> Value {
    Value::String(id.as_str().to_owned())
}

/// Renders a validated binary identifier as 34 lowercase hexadecimal digits.
fn binary_value(bytes: PikaIdBinary) -> Value {
    Value::String(bytes.to_hex())
}

/// Maps the crate's documented error variants to protocol categories.
///
/// Only genuine input-validation errors become `invalid_input`; entropy
/// failures stay distinguishable and clock failures are reported as internal
/// environment failures rather than as bad user input.
fn map_error(error: Error) -> Failure {
    match error {
        Error::InvalidLength { .. }
        | Error::InvalidCharacter { .. }
        | Error::RandomnessOverflow
        | Error::TimestampOutOfRange { .. } => Failure::Invalid(error.to_string()),
        Error::EntropySource => Failure::Entropy(error.to_string()),
        Error::ClockBeforeUnixEpoch | Error::ClockOutOfRange => {
            Failure::Internal(error.to_string())
        }
        // `Error` is `#[non_exhaustive]`: never fold an unknown variant into
        // `invalid_input`, because that would hide a real defect.
        other => Failure::Internal(other.to_string()),
    }
}

fn argument_str<'a>(arguments: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::Invalid(format!("argument {key:?} must be a string")))
}

fn argument_timestamp(arguments: &Map<String, Value>) -> Result<u64, Failure> {
    arguments
        .get("timestamp_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Failure::Invalid("argument \"timestamp_seconds\" must be a non-negative integer".into())
        })
}

/// Decodes exactly `expected_bytes` lowercase hexadecimal digits.
///
/// Uppercase digits, whitespace and wrong lengths are rejected rather than
/// normalized, mirroring the crate's strict textual parsing.
fn decode_lower_hex(text: &str, expected_bytes: usize) -> Result<Vec<u8>, Failure> {
    if text.len() != expected_bytes * 2 {
        return Err(Failure::Invalid(format!(
            "expected {} hexadecimal digits, got {}",
            expected_bytes * 2,
            text.len()
        )));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(expected_bytes);
    for pair in bytes.chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, Failure> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Failure::Invalid(format!(
            "invalid lowercase hexadecimal digit {:?}",
            char::from(byte)
        ))),
    }
}
