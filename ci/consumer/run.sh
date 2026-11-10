#!/bin/sh
# Build the packaged pikaid crate as an external consumer would.
#
# Usage: ci/consumer/run.sh
#
# Requires `cargo package` to have produced target/package/pikaid-<version>/.
# The consumer is copied to a temporary directory so no repository file can
# satisfy the dependency, and its manifest is generated with the absolute path
# of the unpacked archive.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
package_id=$(cargo pkgid --manifest-path "$root/Cargo.toml" --package pikaid)
version=${package_id##*@}
package_dir="$root/target/package/pikaid-$version"

if [ -z "$version" ] || [ "$version" = "$package_id" ]; then
    echo "could not determine the crate version from: $package_id" >&2
    exit 1
fi
if [ ! -d "$package_dir" ]; then
    echo "missing unpacked package at $package_dir (run: cargo package --allow-dirty)" >&2
    exit 1
fi

table="$package_dir/tests/vectors/oracle-cases.json"
if [ ! -f "$table" ]; then
    echo "packaged archive is missing tests/vectors/oracle-cases.json" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp -R "$root/ci/consumer/tests" "$work/tests"
sed "s|@PIKAID_PACKAGE_DIR@|$package_dir|g" "$root/ci/consumer/Cargo.toml.in" >"$work/Cargo.toml"

cd "$work"
echo "consumer workspace: $work"
echo "package under test: $package_dir"
PIKAID_ORACLE_TABLE="$table" cargo test --quiet
