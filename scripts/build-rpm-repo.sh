#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${1:-"$repo_root/repo/testing/x86_64"}
if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi

for tool in rpmbuild rpmspec rpmsign rpm createrepo_c gpg; do
  command -v "$tool" >/dev/null || {
    echo "Required build tool not found: $tool" >&2
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

mkdir -p "$output_dir"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "Output directory must be empty: $output_dir" >&2
  exit 1
fi

build_root=$(mktemp -d "${TMPDIR:-/tmp}/veyra-rpm-build.XXXXXX")
trap 'rm -rf "$build_root"' EXIT

shopt -s nullglob
specs=("$repo_root"/rpms/*/*.spec)
(( ${#specs[@]} > 0 )) || {
  echo 'No RPM specs found under rpms/.' >&2
  exit 1
}

rpm_count=0
for spec in "${specs[@]}"; do
  package_dir=$(dirname "$spec")
  package_name=$(rpmspec -q --qf '%{NAME}\n' "$spec" | head -n 1)
  [[ -n "$package_name" ]] || {
    echo "Could not read package name from $spec" >&2
    exit 1
  }
  topdir="$build_root/$package_name"
  install -d "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  cp "$spec" "$topdir/SPECS/"
  if [[ -d "$package_dir/SOURCES" ]]; then
    cp -a "$package_dir/SOURCES/." "$topdir/SOURCES/"
  fi

  rpmbuild -bb \
    --define "_topdir $topdir" \
    --define 'dist .veyra' \
    "$topdir/SPECS/$(basename "$spec")"

  built_rpms=("$topdir"/RPMS/*/*.rpm)
  (( ${#built_rpms[@]} > 0 )) || {
    echo "No binary RPM was produced for $package_name" >&2
    exit 1
  }
  for rpm_file in "${built_rpms[@]}"; do
    install -m 0644 "$rpm_file" "$output_dir/"
    rpm_count=$((rpm_count + 1))
  done
done

gpg --batch --armor --export "$VEYRA_RPM_GPG_FINGERPRINT" > "$output_dir/RPM-GPG-KEY-VEYRA"
test -s "$output_dir/RPM-GPG-KEY-VEYRA"

for rpm_file in "$output_dir"/*.rpm; do
  rpmsign \
    --define "_gpg_name $VEYRA_RPM_GPG_FINGERPRINT" \
    --define "_gpg_path $GNUPGHOME" \
    --addsign "$rpm_file"
done

verify_db="$build_root/verify-rpmdb"
install -d "$verify_db"
rpm --dbpath "$verify_db" --initdb
rpm --dbpath "$verify_db" --import "$output_dir/RPM-GPG-KEY-VEYRA"
for rpm_file in "$output_dir"/*.rpm; do
  rpm --dbpath "$verify_db" --checksig --verbose "$rpm_file"
done

createrepo_c --database --checksum sha256 "$output_dir"
gpg --batch --yes --local-user "$VEYRA_RPM_GPG_FINGERPRINT" \
  --armor --detach-sign \
  --output "$output_dir/repodata/repomd.xml.asc" \
  "$output_dir/repodata/repomd.xml"
gpg --batch --verify \
  "$output_dir/repodata/repomd.xml.asc" \
  "$output_dir/repodata/repomd.xml"

echo "Built and signed $rpm_count Veyra RPM package(s) in $output_dir"
