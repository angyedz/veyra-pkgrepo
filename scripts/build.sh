#!/bin/sh
set -eu
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
command -v abuild >/dev/null || { echo 'Missing abuild' >&2; exit 1; }
command -v abuild-sign >/dev/null || { echo 'Missing abuild-sign' >&2; exit 1; }
[ -f "$root/distro-source/vpkg/go.mod" ] || {
    echo 'Missing Veyra-Linux checkout in distro-source/' >&2
    exit 1
}
: "${PACKAGER_PRIVKEY:=$(sed -n 's/^PACKAGER_PRIVKEY=//p' "$HOME/.abuild/abuild.conf")}"
[ -r "$PACKAGER_PRIVKEY" ] || { echo 'Signing key missing' >&2; exit 1; }
for dir in "$root"/src/*; do
    [ -f "$dir/APKBUILD" ] || continue
    case "${dir##*/}" in veyra-meta) continue ;; esac
    (cd "$dir" && abuild -r)
done
(cd "$root/src/veyra-meta" && abuild -r)
out="$root/packages/repo/x86_64"
mkdir -p "$out"
find "$out" -maxdepth 1 -name '*.apk' -delete
repository="${REPODEST:-$HOME/packages}"
find "$repository" -type f -name '*.apk' -exec cp -f '{}' "$out/" \;
test -n "$(find "$out" -maxdepth 1 -name '*.apk' -print -quit)"
apk index -o "$out/APKINDEX.tar.gz" "$out"/*.apk
abuild-sign "$out/APKINDEX.tar.gz"
test -s "$out/APKINDEX.tar.gz"
echo "Signed APK snapshot at $out"
