#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 TESTING_REPOSITORY OUTPUT_REPOSITORY" >&2
  exit 2
fi

source_dir=$1
output_dir=$2

for tool in rpm createrepo_c gpg; do
  command -v "$tool" >/dev/null || {
    echo "Required promotion tool not found: $tool" >&2
    exit 1
  }
done
[[ -n "${GNUPGHOME:-}" && -d "$GNUPGHOME" ]] || {
  echo 'GNUPGHOME must point to a directory containing the RPM signing key.' >&2
  exit 1
}
[[ -n "${VEYRA_RPM_GPG_FINGERPRINT:-}" ]] || {
  echo 'VEYRA_RPM_GPG_FINGERPRINT must contain the signing key fingerprint.' >&2
  exit 1
}
[[ -d "$source_dir" ]] || {
  echo "Testing repository not found: $source_dir" >&2
  exit 1
}

shopt -s nullglob
packages=("$source_dir"/*.rpm)
(( ${#packages[@]} > 0 )) || {
  echo "No signed RPMs found in $source_dir" >&2
  exit 1
}

mkdir -p "$output_dir"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "Output directory must be empty: $output_dir" >&2
  exit 1
fi
for package in "${packages[@]}"; do
  install -m 0644 "$package" "$output_dir/"
done

gpg --batch --armor --export "$VEYRA_RPM_GPG_FINGERPRINT" > "$output_dir/RPM-GPG-KEY-VEYRA"
test -s "$output_dir/RPM-GPG-KEY-VEYRA"

verify_root=$(mktemp -d "${TMPDIR:-/tmp}/veyra-rpm-promote.XXXXXX")
trap 'rm -rf "$verify_root"' EXIT
install -d "$verify_root/rpmdb"
rpm --dbpath "$verify_root/rpmdb" --initdb
rpm --dbpath "$verify_root/rpmdb" --import "$output_dir/RPM-GPG-KEY-VEYRA"
for package in "$output_dir"/*.rpm; do
  rpm --dbpath "$verify_root/rpmdb" --checksig --verbose "$package"
done

createrepo_c --database --checksum sha256 "$output_dir"
gpg --batch --yes --local-user "$VEYRA_RPM_GPG_FINGERPRINT" \
  --armor --detach-sign \
  --output "$output_dir/repodata/repomd.xml.asc" \
  "$output_dir/repodata/repomd.xml"
gpg --batch --verify \
  "$output_dir/repodata/repomd.xml.asc" \
  "$output_dir/repodata/repomd.xml"

echo "Promoted ${#packages[@]} tested RPM package(s) into $output_dir"
