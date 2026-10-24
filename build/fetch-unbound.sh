#!/bin/sh
set -eu

PINNED_UNBOUND_FINGERPRINT=231018690C4D903EF419146AA144323DEAACDF45

validate_explicit_version() {
  printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
}

version_is_at_least() {
  _via_version=$1
  _via_floor=$2
  validate_explicit_version "$_via_version" || return 1
  validate_explicit_version "$_via_floor" || return 1

  _via_old_ifs=$IFS
  IFS=.
  set -- $_via_version
  _via_major=$1
  _via_minor=$2
  _via_patch=$3
  set -- $_via_floor
  _via_floor_major=$1
  _via_floor_minor=$2
  _via_floor_patch=$3
  IFS=$_via_old_ifs

  [ "$_via_major" -gt "$_via_floor_major" ] && return 0
  [ "$_via_major" -lt "$_via_floor_major" ] && return 1
  [ "$_via_minor" -gt "$_via_floor_minor" ] && return 0
  [ "$_via_minor" -lt "$_via_floor_minor" ] && return 1
  [ "$_via_patch" -ge "$_via_floor_patch" ]
}

enforce_version_floor() {
  _evf_version=$1
  _evf_floor=$2
  if ! validate_explicit_version "$_evf_floor"; then
    echo "invalid UNBOUND_MIN_VERSION: $_evf_floor" >&2
    return 1
  fi
  if ! version_is_at_least "$_evf_version" "$_evf_floor"; then
    echo "resolved Unbound $_evf_version is below minimum allowed version $_evf_floor" >&2
    return 1
  fi
}

select_latest_version() {
  _slv_index=$1
  [ -r "$_slv_index" ] || {
    echo "cannot read Unbound index: $_slv_index" >&2
    return 1
  }
  _slv_latest=$(
    awk -F '"' '
      {
        for (i = 2; i <= NF; i += 2) {
          filename = $i
          if (filename ~ /^unbound-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz$/) {
            version = filename
            sub(/^unbound-/, "", version)
            sub(/\.tar\.gz$/, "", version)
            split(version, part, ".")
            if (!found || part[1] + 0 > major ||
                (part[1] + 0 == major && part[2] + 0 > minor) ||
                (part[1] + 0 == major && part[2] + 0 == minor && part[3] + 0 > patch)) {
              found = 1
              major = part[1] + 0
              minor = part[2] + 0
              patch = part[3] + 0
              latest = version
            }
          }
        }
      }
      END {
        if (found) print latest
      }
    ' "$_slv_index"
  )
  if [ -z "$_slv_latest" ]; then
    echo "no stable Unbound release found in $_slv_index" >&2
    return 1
  fi
  printf '%s\n' "$_slv_latest"
}

resolve_unbound_version() {
  _ruv_requested=$1
  _ruv_index=$2
  if [ "$_ruv_requested" = latest ]; then
    select_latest_version "$_ruv_index"
    return
  fi
  if ! validate_explicit_version "$_ruv_requested"; then
    echo "invalid UNBOUND_VERSION: $_ruv_requested" >&2
    return 1
  fi
  printf '%s\n' "$_ruv_requested"
}

download_https() {
  _dh_url=$1
  _dh_destination=$2
  case "$_dh_url" in
    https://?*) ;;
    *)
      echo "refusing non-HTTPS URL: $_dh_url" >&2
      return 1
      ;;
  esac
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
    -o "$_dh_destination" "$_dh_url"
}

build_verified_keyring() {
  _bvk_key_file=$1
  _bvk_home=$2
  [ -r "$_bvk_key_file" ] || {
    echo "cannot read Unbound release key: $_bvk_key_file" >&2
    return 1
  }
  mkdir -p "$_bvk_home"
  chmod 700 "$_bvk_home"
  _bvk_keyring="$_bvk_home/releases.gpg"
  GNUPGHOME="$_bvk_home" gpg --batch --yes --dearmor \
    --output "$_bvk_keyring" "$_bvk_key_file"
  _bvk_fingerprints=$(
    GNUPGHOME="$_bvk_home" gpg --batch --no-default-keyring \
      --keyring "$_bvk_keyring" --with-colons --fingerprint 2>/dev/null |
      awk -F: '
        $1 == "pub" { want_primary = 1; next }
        want_primary && $1 == "fpr" { print $10; want_primary = 0 }
      '
  )
  if [ "$_bvk_fingerprints" != "$PINNED_UNBOUND_FINGERPRINT" ]; then
    echo "Unbound release key fingerprint mismatch" >&2
    echo "expected exactly: $PINNED_UNBOUND_FINGERPRINT" >&2
    echo "found: ${_bvk_fingerprints:-none}" >&2
    return 1
  fi
  printf '%s\n' "$_bvk_keyring"
}

verify_signature() {
  _vs_tarball=$1
  _vs_signature=$2
  _vs_keyring=$3
  gpgv --keyring "$_vs_keyring" "$_vs_signature" "$_vs_tarball"
}

published_sha256() {
  _ps_file=$1
  tr -cs '0123456789abcdefABCDEF' '\n' < "$_ps_file" |
    awk 'length($0) == 64 { print tolower($0); exit }'
}

verify_checksums() {
  _vc_tarball=$1
  _vc_checksum_file=$2
  _vc_optional=$3
  _vc_published=$(published_sha256 "$_vc_checksum_file")
  if [ -z "$_vc_published" ]; then
    echo "published checksum file contains no SHA-256 digest" >&2
    return 1
  fi
  _vc_actual=$(sha256sum "$_vc_tarball" | awk '{ print tolower($1) }')
  if [ "$_vc_actual" != "$_vc_published" ]; then
    echo "published SHA-256 does not match the Unbound tarball" >&2
    return 1
  fi
  if [ -n "$_vc_optional" ]; then
    if [ "${#_vc_optional}" -ne 64 ]; then
      echo "UNBOUND_SHA256 must be exactly 64 hexadecimal characters" >&2
      return 1
    fi
    case "$_vc_optional" in
      *[!0123456789abcdefABCDEF]*)
        echo "UNBOUND_SHA256 must be exactly 64 hexadecimal characters" >&2
        return 1
        ;;
    esac
    _vc_optional=$(printf '%s' "$_vc_optional" | tr 'ABCDEF' 'abcdef')
    if [ "$_vc_actual" != "$_vc_optional" ]; then
      echo "UNBOUND_SHA256 does not match the Unbound tarball" >&2
      return 1
    fi
  fi
}

fetch_unbound_main() {
  _fum_requested=${UNBOUND_VERSION-latest}
  _fum_floor=${UNBOUND_MIN_VERSION-1.26.2}
  _fum_optional_sha=${UNBOUND_SHA256-}
  _fum_base=${UNBOUND_BASE_URL-https://nlnetlabs.nl/downloads/unbound}
  _fum_index=${UNBOUND_INDEX_FILE-/build/unbound-index.html}
  _fum_target=${UNBOUND_TARGET_DIR-/build/unbound-src}
  _fum_version_file=${UNBOUND_VERSION_FILE-/build/UNBOUND_VERSION}
  _fum_script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
  _fum_key=${UNBOUND_KEY_FILE-$_fum_script_dir/keys/nlnetlabs-releases-g2.asc}

  case "$_fum_base" in
    https://?*) ;;
    *)
      echo "UNBOUND_BASE_URL must use https://" >&2
      return 1
      ;;
  esac
  _fum_base=${_fum_base%/}
  if ! validate_explicit_version "$_fum_floor"; then
    echo "invalid UNBOUND_MIN_VERSION: $_fum_floor" >&2
    return 1
  fi

  if [ "$_fum_requested" = latest ] && [ ! -s "$_fum_index" ]; then
    mkdir -p "$(dirname "$_fum_index")"
    download_https "$_fum_base/" "$_fum_index"
  fi
  _fum_resolved=$(resolve_unbound_version "$_fum_requested" "$_fum_index")
  enforce_version_floor "$_fum_resolved" "$_fum_floor"

  if [ -e "$_fum_target" ]; then
    echo "UNBOUND_TARGET_DIR already exists: $_fum_target" >&2
    return 1
  fi

  _fum_tmp=$(mktemp -d)
  trap 'rm -rf "$_fum_tmp"' EXIT HUP INT TERM
  _fum_name="unbound-$_fum_resolved.tar.gz"
  _fum_tarball="$_fum_tmp/$_fum_name"
  _fum_signature="$_fum_tarball.asc"
  _fum_checksum="$_fum_tarball.sha256"

  download_https "$_fum_base/$_fum_name" "$_fum_tarball"
  download_https "$_fum_base/$_fum_name.asc" "$_fum_signature"
  download_https "$_fum_base/$_fum_name.sha256" "$_fum_checksum"

  _fum_keyring=$(build_verified_keyring "$_fum_key" "$_fum_tmp/gnupg")
  verify_signature "$_fum_tarball" "$_fum_signature" "$_fum_keyring"
  verify_checksums "$_fum_tarball" "$_fum_checksum" "$_fum_optional_sha"

  mkdir -p "$_fum_target"
  tar -xzf "$_fum_tarball" -C "$_fum_target" --strip-components=1
  mkdir -p "$(dirname "$_fum_version_file")"
  printf '%s\n' "$_fum_resolved" > "$_fum_version_file"
  printf 'Building Unbound %s (signature verified: G2 %s)\n' \
    "$_fum_resolved" "$PINNED_UNBOUND_FINGERPRINT"
}

if [ "${FETCH_UNBOUND_SOURCE_ONLY:-0}" != 1 ]; then
  fetch_unbound_main "$@"
fi
