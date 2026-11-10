#!/bin/sh
# Run the official PikaID conformance suite against this crate's real public API.
#
# The suite is fetched at an exact immutable commit, its checksums/schemas are
# verified, its own validators are self-tested, and a test-only JSON-Lines
# bridge (ci/adapter) is driven by the official runner.
#
# Usage:
#   ci/official/run.sh [options]
#
# Options:
#   --suite DIR         Existing pinned checkout of pikaid-specs (validated).
#   --work DIR          Scratch directory (default: target/conformance).
#   --report PATH       Canonical automated report JSON path.
#   --pikaid-path DIR   Crate directory the adapter links against
#                       (default: repository root; pass an unpacked package to
#                       test the distributable instead of the worktree).
#   --adapter-source DIR  Adapter source directory (default: ci/adapter).
#                       Only used by the mutation controls.
#   --no-selftests      Skip the suite's own validator/runner self-tests.
#   --skip-default-gate Skip the extra default-mode run that must exit 3.
#   -h, --help          Show this help.
#
# Exit status is 0 only when every automated official check passes. Missing
# manual security evidence is reported separately by the official runner and is
# never turned into a conformance certification by this script.
set -eu

SUITE_REPO=${PIKAID_SPECS_REPO:-https://github.com/pikaid/pikaid-specs.git}
SUITE_SHA=059780cc0e5b113443812720d95c630649bf3aa3
SUITE_REVISION=1.0.0
SPEC_REVISION=1.0.4

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
suite=
work="$root/target/conformance"
report=
pikaid_path="$root"
adapter_source="$root/ci/adapter"
selftests=1
default_gate=1

usage() {
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --suite) [ "$#" -ge 2 ] || fail "--suite needs a value"; suite=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || fail "--work needs a value"; work=$2; shift 2 ;;
        --report) [ "$#" -ge 2 ] || fail "--report needs a value"; report=$2; shift 2 ;;
        --pikaid-path) [ "$#" -ge 2 ] || fail "--pikaid-path needs a value"; pikaid_path=$2; shift 2 ;;
        --adapter-source) [ "$#" -ge 2 ] || fail "--adapter-source needs a value"; adapter_source=$2; shift 2 ;;
        --no-selftests) selftests=0; shift ;;
        --skip-default-gate) default_gate=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1 (use --help)" ;;
    esac
done

case "$work" in
    /*) ;;
    *) work="$root/$work" ;;
esac
case "$pikaid_path" in
    /*) ;;
    *) pikaid_path="$root/$pikaid_path" ;;
esac
case "$adapter_source" in
    /*) ;;
    *) adapter_source="$root/$adapter_source" ;;
esac

[ -f "$pikaid_path/Cargo.toml" ] || fail "no Cargo.toml under --pikaid-path $pikaid_path"
grep -q '^name = "pikaid"$' "$pikaid_path/Cargo.toml" ||
    fail "$pikaid_path/Cargo.toml is not the pikaid crate"

command -v git >/dev/null 2>&1 || fail "git is required"
command -v node >/dev/null 2>&1 || fail "node is required for the independent BigInt oracle"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

# Pick a Python interpreter that satisfies the suite's 3.11+ requirement
# without ever making Python a production dependency of the crate.
pick_python() {
    for candidate in ${PYTHON:-} python3 python3.14 python3.13 python3.12 python3.11; do
        [ -n "$candidate" ] || continue
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}
python=$(pick_python) || fail "Python 3.11+ is required to run the official suite"

mkdir -p "$work"

if [ -z "$suite" ]; then
    suite="$work/pikaid-specs"
    rm -rf "$suite"
    echo "Cloning pinned suite $SUITE_SHA"
    git clone --quiet --no-checkout "$SUITE_REPO" "$suite" ||
        fail "cannot clone the official suite repository"
fi

[ -d "$suite/.git" ] || fail "$suite is not a Git checkout"
git -C "$suite" cat-file -e "$SUITE_SHA^{commit}" 2>/dev/null ||
    fail "pinned suite commit $SUITE_SHA is not present in $suite"
git -C "$suite" -c core.autocrlf=false checkout --quiet --force "$SUITE_SHA" ||
    fail "cannot check out pinned suite commit $SUITE_SHA"
resolved=$(git -C "$suite" rev-parse HEAD)
[ "$resolved" = "$SUITE_SHA" ] ||
    fail "suite resolved to $resolved, expected $SUITE_SHA"
git -C "$suite" diff --quiet -- . || fail "suite checkout has local modifications"

conformance="$suite/conformance"
[ -f "$conformance/manifest.json" ] || fail "missing $conformance/manifest.json"

# The virtual environment lives outside the suite so the suite's checksum
# coverage (which hashes every file under conformance/) stays exact.
venv="$work/venv"
if [ ! -x "$venv/bin/python" ] || ! "$venv/bin/python" -c 'import jsonschema' 2>/dev/null; then
    rm -rf "$venv"
    "$python" -m venv "$venv" || fail "cannot create virtual environment"
    "$venv/bin/python" -m pip install --quiet --disable-pip-version-check \
        --only-binary :all: -r "$conformance/tools/requirements.txt" ||
        fail "cannot install pinned suite test requirements"
fi
python_version=$("$venv/bin/python" -c 'import platform; print(platform.python_version())')
node_version=$(node --version)

echo "Pinned suite:     $SUITE_SHA (revision $SUITE_REVISION, spec $SPEC_REVISION)"
echo "Python:           $python_version"
echo "Node:             $node_version"
echo "Crate under test: $pikaid_path"

(
    cd "$conformance"
    "$venv/bin/python" tools/verify_vectors.py \
        --expect-status OFFICIAL \
        --expect-package-revision "$SUITE_REVISION" \
        --expect-spec-revision "$SPEC_REVISION"
) || fail "official fixture integrity verification failed"

if [ "$selftests" -eq 1 ]; then
    echo "Running the suite's own validator and runner self-tests"
    (cd "$conformance" && "$venv/bin/python" -m unittest discover -s tools/tests -v) ||
        fail "official suite self-tests failed"
    (cd "$conformance" && node tools/verify_oracle_node.mjs) ||
        fail "independent Node.js BigInt oracle failed"
fi

# Build the test-only bridge against the requested crate (worktree by default,
# an unpacked package when --pikaid-path points at one).
adapter="$work/adapter"
rm -rf "$adapter"
cp -R "$adapter_source" "$adapter"
sed "s|pikaid = { path = \"../..\" }|pikaid = { path = \"$pikaid_path\" }|" \
    "$adapter_source/Cargo.toml" >"$adapter/Cargo.toml"
grep -F "pikaid = { path = \"$pikaid_path\" }" "$adapter/Cargo.toml" >/dev/null ||
    fail "could not point the adapter at $pikaid_path"

CARGO_TARGET_DIR="$work/target" cargo build --quiet --locked --manifest-path "$adapter/Cargo.toml" ||
    fail "cannot build the conformance adapter"
adapter_bin="$work/target/debug/pikaid-jsonl-adapter"
[ -x "$adapter_bin" ] || fail "adapter binary missing at $adapter_bin"

if [ -z "$report" ]; then
    report="$work/conformance-report.json"
fi
case "$report" in
    /*) ;;
    *) report="$root/$report" ;;
esac
mkdir -p "$(dirname -- "$report")"

echo "Running the official automated conformance checks"
set +e
(
    cd "$conformance"
    "$venv/bin/python" tools/run_adapter.py \
        --automated-only \
        --report-json "$report" \
        -- "$adapter_bin"
)
automated_exit=$?
set -e
echo "Automated runner exit: $automated_exit (0 required)"
[ "$automated_exit" -eq 0 ] || fail "official automated conformance checks failed"

if [ "$default_gate" -eq 1 ]; then
    echo "Confirming the default gate still demands manual security evidence"
    set +e
    (
        cd "$conformance"
        "$venv/bin/python" tools/run_adapter.py \
            --report-json "$work/default-report.json" \
            -- "$adapter_bin"
    )
    default_exit=$?
    set -e
    echo "Default runner exit: $default_exit (3 expected without reviewed evidence)"
    [ "$default_exit" -eq 3 ] ||
        fail "default runner exit $default_exit, expected 3 (audit required) without security evidence"
    "$venv/bin/python" - "$work/default-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["automated_passed"] is True, report["automated_passed"]
assert report["certification"] == "NOT_A_CONFORMANCE_CERTIFICATION", report["certification"]
assert report["outstanding_audits"], "the pinned suite registers no audit obligation"
print("Default gate: automated checks passed, audits outstanding: "
      + ", ".join(report["outstanding_audits"]))
PY
fi

"$venv/bin/python" - "$report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
counts = report["counts"]
total = sum(sum(bucket.values()) for bucket in counts.values())
failed = sum(bucket["failed"] for bucket in counts.values())
print()
print(f"Official status:        {report['status']}")
print(f"Certification:          {report['certification']}")
print(f"Automated cases:        {total} executed, {failed} failed")
for name in ("valid", "invalid-string", "invalid-binary", "ordering", "generation", "properties"):
    bucket = counts[name]
    print(
        f"  {name:<15} passed={bucket['passed']:<5} "
        f"failed={bucket['failed']:<3} not_applicable={bucket['not_applicable']}"
    )
print(f"Outstanding audits:     {', '.join(report['outstanding_audits']) or 'none'}")
print(f"Adapter capabilities:   {', '.join(report['capabilities'])}")
print(f"Report:                 {sys.argv[1]}")
PY

echo
echo "PASS: official automated conformance checks and suite integrity verified."
echo "This is not a conformance certification and not a substitute for independent"
echo "human security review of the generation paths."
