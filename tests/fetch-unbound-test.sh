#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fetch_script="$root_dir/build/fetch-unbound.sh"
key_file="$root_dir/build/keys/nlnetlabs-releases-g2.asc"
fixture_dir="$root_dir/tests/fixtures"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_equal() {
  label=$1
  expected=$2
  actual=$3
  [ "$actual" = "$expected" ] || fail "$label: expected '$expected', got '$actual'"
}

FETCH_UNBOUND_SOURCE_ONLY=1 . "$fetch_script"
unset FETCH_UNBOUND_SOURCE_ONLY

latest=$(select_latest_version "$fixture_dir/unbound-index.html")
assert_equal "stable release selection" "1.26.2" "$latest"

latest=$(select_latest_version "$fixture_dir/unbound-index-multidigit.html")
assert_equal "numeric multi-digit selection" "1.100.0" "$latest"

for malformed in 1.26 1.26.2rc1 v1.26.2 1.26.2.1 1.26.x '' latest-now; do
  if validate_explicit_version "$malformed"; then
    fail "malformed explicit version accepted: '$malformed'"
  fi
done

validate_explicit_version "1.26.2" || fail "valid explicit version rejected"
if download_https "http://nlnetlabs.example/unbound.tar.gz" "/tmp/should-not-exist" >/dev/null 2>&1; then
  fail "non-HTTPS download URL accepted"
fi
version_is_at_least "1.26.2" "1.26.2" || fail "equal floor rejected"
version_is_at_least "1.100.0" "1.99.9" || fail "numeric higher version rejected"
if version_is_at_least "1.26.1" "1.26.2"; then
  fail "version below floor accepted"
fi
enforce_version_floor "1.26.2" "1.26.2" || fail "floor equality rejected"
if enforce_version_floor "1.26.1" "1.26.2" >/dev/null 2>&1; then
  fail "anti-downgrade floor did not reject 1.26.1"
fi

key_test_tmp=$(mktemp -d)
cleanup() {
  rm -rf "$key_test_tmp"
}
trap cleanup EXIT HUP INT TERM
trusted_keyring=$(build_verified_keyring "$key_file" "$key_test_tmp/trusted-home")
[ -s "$trusted_keyring" ] || fail "pinned G2 key did not produce a keyring"
if build_verified_keyring "$fixture_dir/wrong-release-key.asc" "$key_test_tmp/verify-home" >/dev/null 2>&1; then
  fail "fingerprint assertion accepted a different valid OpenPGP key"
fi

printf 'checksum fixture\n' > "$key_test_tmp/checksum-payload"
fixture_sha=$(sha256sum "$key_test_tmp/checksum-payload" | awk '{ print $1 }')
printf '%s  checksum-payload\n' "$fixture_sha" > "$key_test_tmp/checksum-payload.sha256"
verify_checksums "$key_test_tmp/checksum-payload" "$key_test_tmp/checksum-payload.sha256" "" || \
  fail "matching published checksum rejected"
if verify_checksums "$key_test_tmp/checksum-payload" "$key_test_tmp/checksum-payload.sha256" \
  '0000000000000000000000000000000000000000000000000000000000000000' >/dev/null 2>&1; then
  fail "incorrect optional UNBOUND_SHA256 accepted"
fi

if UNBOUND_VERSION=1.26.1 UNBOUND_MIN_VERSION=1.26.2 \
  UNBOUND_TARGET_DIR="$key_test_tmp/floor-src" \
  UNBOUND_VERSION_FILE="$key_test_tmp/floor-version" \
  sh "$fetch_script" >/dev/null 2>&1; then
  fail "main fetch path did not enforce the anti-downgrade floor before download"
fi

if [ "${OFFLINE_ONLY:-0}" = "1" ]; then
  echo "fetch-unbound offline tests passed"
  exit 0
fi

online_tmp=$(mktemp -d)
trap 'rm -rf "$key_test_tmp" "$online_tmp"' EXIT HUP INT TERM

UNBOUND_VERSION=latest \
UNBOUND_MIN_VERSION=1.26.2 \
UNBOUND_KEY_FILE="$key_file" \
UNBOUND_INDEX_FILE="$online_tmp/index.html" \
UNBOUND_TARGET_DIR="$online_tmp/source" \
UNBOUND_VERSION_FILE="$online_tmp/version" \
sh "$fetch_script"

resolved=$(cat "$online_tmp/version")
validate_explicit_version "$resolved" || fail "online latest returned malformed version '$resolved'"

base_url=${UNBOUND_BASE_URL:-https://nlnetlabs.nl/downloads/unbound}
base_url=${base_url%/}
tarball="$online_tmp/unbound-$resolved.tar.gz"
signature="$tarball.asc"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
  -o "$tarball" "$base_url/unbound-$resolved.tar.gz"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
  -o "$signature" "$base_url/unbound-$resolved.tar.gz.asc"
keyring=$(build_verified_keyring "$key_file" "$online_tmp/gnupg")
verify_signature "$tarball" "$signature" "$keyring" || fail "valid online signature rejected"
cp "$tarball" "$online_tmp/tampered.tar.gz"
printf '\ncorruption\n' >> "$online_tmp/tampered.tar.gz"
if verify_signature "$online_tmp/tampered.tar.gz" "$signature" "$keyring" >/dev/null 2>&1; then
  fail "tampered tarball passed OpenPGP verification"
fi

echo "fetch-unbound offline and online tests passed (latest: $resolved)"
