#!/bin/sh
# Prove the official runner actually detects defects in this crate.
#
# A conformance run that always passes is worthless, so this script introduces
# deliberate defects into throwaway copies of the library and of the test-only
# bridge and asserts that the pinned runner rejects each one with exit status 1.
#
# Everything happens under --work (default: target/mutation-controls). The real
# worktree is never modified; the script verifies that at the end.
#
# Usage:
#   ci/official/mutation_controls.sh [--suite DIR] [--work DIR]
#
#   --suite DIR   Existing pinned checkout of pikaid-specs (recommended;
#                 otherwise the suite is cloned again for every mutant).
#   --work DIR    Scratch directory (default: target/mutation-controls).
#   -h, --help    Show this help.
#
# Exit status 0 means every mutant was rejected by the official runner.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
suite=
work="$root/target/mutation-controls"

usage() {
    sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --suite) [ "$#" -ge 2 ] || fail "--suite needs a value"; suite=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || fail "--work needs a value"; work=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1 (use --help)" ;;
    esac
done

case "$work" in
    /*) ;;
    *) work="$root/$work" ;;
esac

rm -rf "$work"
mkdir -p "$work"

before_status=$(git -C "$root" status --porcelain)
before_head=$(git -C "$root" rev-parse HEAD)

# Copy only the source of the crate under test. Build output, Git metadata and
# the local agent workspace are irrelevant to the mutants.
copy_crate() {
    target=$1
    mkdir -p "$target"
    for entry in Cargo.toml Cargo.lock README.md LICENSE src; do
        [ -e "$root/$entry" ] || fail "crate entry $entry is missing"
        cp -R "$root/$entry" "$target/$entry"
    done
}

# Run the official automated checks against an already-prepared crate copy and
# require the "defect found" result. `ci/official/run.sh` exits 1 for that case.
expect_rejected() {
    name=$1
    run_log=$2
    run_dir=$3
    shift 3

    printf '\n== mutant %s ==\n' "$name" >&2
    set +e
    "$root/ci/official/run.sh" "$@" >"$run_log" 2>&1
    status=$?
    set -e
    printf 'runner exit: %s (1 expected)\n' "$status" >&2
    if [ "$status" -ne 1 ]; then
        tail -40 "$run_log" >&2 || true
        fail "mutant $name was not rejected (exit $status)"
    fi
    # A rejection only counts when it comes from the runner, not from a broken
    # setup step: the report must exist and record at least one failure.
    python3 - "$run_dir/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
failed = sum(bucket["failed"] for bucket in report["counts"].values())
if report["automated_passed"] is not False or failed < 1:
    raise SystemExit(f"mutant not detected by the fixture checks (failed={failed})")
print(f"mutant detected by the fixture checks ({failed} failed cases)")
PY
    printf 'mutant %s rejected as expected\n' "$name" >&2
}

suite_args=
if [ -n "$suite" ]; then
    case "$suite" in
        /*) ;;
        *) suite="$root/$suite" ;;
    esac
    suite_args="--suite $suite"
fi

# --- Mutant 1: the decoder silently accepts uppercase Base36 -----------------
# Uppercase input must be rejected; a permissive decoder is exactly the class of
# defect the invalid-string corpus exists to catch.
crate1="$work/crate-uppercase"
copy_crate "$crate1"
python3 - "$crate1/src/base36.rs" <<'PY'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = "        b'a'..=b'z' => byte - b'a' + 10,"
replacement = "        b'a'..=b'z' | b'A'..=b'Z' => (byte | 0x20) - b'a' + 10,"
if needle not in text:
    raise SystemExit("mutant 1 anchor not found")
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement, 1))
PY
# shellcheck disable=SC2086
expect_rejected uppercase-decoder "$work/run-uppercase.log" "$work/run-uppercase" \
    --no-selftests --skip-default-gate --pikaid-path "$crate1" \
    --work "$work/run-uppercase" --report "$work/run-uppercase/report.json" $suite_args

# --- Mutant 2: the encoder emits a wrong alphabet character ------------------
# Every valid fixture differs, so this proves the valid corpus is really compared
# character for character instead of being regenerated from the same code.
crate2="$work/crate-alphabet"
copy_crate "$crate2"
python3 - "$crate2/src/base36.rs" <<'PY'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = 'b"0123456789abcdefghijklmnopqrstuvwxyz"'
replacement = 'b"0123456789abcdefghijklmnopqrstuvwxy0"'
if needle not in text:
    raise SystemExit("mutant 2 anchor not found")
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement, 1))
PY
# shellcheck disable=SC2086
expect_rejected alphabet-encoder "$work/run-alphabet.log" "$work/run-alphabet" \
    --no-selftests --skip-default-gate --pikaid-path "$crate2" \
    --work "$work/run-alphabet" --report "$work/run-alphabet/report.json" $suite_args

# --- Mutant 3: the bridge fabricates an answer instead of asking the library -
# The protocol forbids the adapter from computing alternate PikaID results. A
# bridge that rewrites text is not "the library under test", so the runner must
# still fail rather than report a pass for a doctored bridge.
crate3="$work/crate-pristine"
copy_crate "$crate3"
adapter_mutant="$work/adapter-mutant"
mkdir -p "$adapter_mutant"
cp -R "$root/ci/adapter/." "$adapter_mutant/"
python3 - "$adapter_mutant/src/main.rs" <<'PY'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = "fn id_value(id: PikaId) -> Value {\n    Value::String(id.as_str().to_owned())\n}"
replacement = (
    "fn id_value(id: PikaId) -> Value {\n"
    "    // deliberate defect: the bridge rewrites the library's answer\n"
    "    Value::String(id.as_str().to_uppercase())\n"
    "}"
)
if needle not in text:
    raise SystemExit("adapter mutant anchor not found")
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement, 1))
PY
# shellcheck disable=SC2086
expect_rejected doctored-bridge "$work/run-bridge.log" "$work/run-bridge" \
    --no-selftests --skip-default-gate --pikaid-path "$crate3" \
    --adapter-source "$adapter_mutant" \
    --work "$work/run-bridge" --report "$work/run-bridge/report.json" $suite_args

# --- The real worktree must be untouched ------------------------------------
after_status=$(git -C "$root" status --porcelain)
after_head=$(git -C "$root" rev-parse HEAD)
[ "$before_head" = "$after_head" ] || fail "HEAD changed during mutation controls"
[ "$before_status" = "$after_status" ] || fail "the worktree changed during mutation controls"

printf '\nPASS: %s\n' "all 3 mutants were rejected by the official runner (exit 1)"
printf 'PASS: %s\n' "the real worktree is unchanged (HEAD $after_head)"
