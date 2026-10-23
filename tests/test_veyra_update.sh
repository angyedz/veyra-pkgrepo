#!/bin/sh
set -eu

repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/bin"
log=$tmp/commands
mode_file=$tmp/deployment-mode
helper=$tmp/veyra-atomic-update

cat > "$tmp/bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] || exit 2
echo "${VEYRA_UPDATE_TEST_UID:-0}"
EOF
cat > "$tmp/bin/apk" <<'EOF'
#!/bin/sh
printf 'apk %s\n' "$*" >> "$VEYRA_UPDATE_TEST_LOG"
EOF
cat > "$helper" <<'EOF'
#!/bin/sh
printf 'atomic %s\n' "$*" >> "$VEYRA_UPDATE_TEST_LOG"
EOF
chmod 0755 "$tmp/bin/id" "$tmp/bin/apk" "$helper"

run_update() {
  PATH="$tmp/bin:$PATH" \
    VEYRA_UPDATE_TEST_LOG="$log" \
    VEYRA_UPDATE_TEST_UID="${VEYRA_UPDATE_TEST_UID:-0}" \
    VEYRA_UPDATE_MODE_FILE="$mode_file" \
    VEYRA_UPDATE_ATOMIC_HELPER="$helper" \
    sh "$repo/src/veyra-update/veyra-update" "$@"
}

printf '%s\n' atomic-v1 > "$mode_file"
rm -f "$helper"
if VEYRA_UPDATE_TEST_UID=1000 run_update >"$tmp/not-root.out" 2>&1; then
  echo 'non-root atomic update unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'Run sudo veyra-update' "$tmp/not-root.out"
if run_update >"$tmp/no-helper.out" 2>&1; then
  echo 'atomic update without its updater unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'refusing in-place APK upgrade' "$tmp/no-helper.out"
[ ! -s "$log" ] || { echo 'atomic update called apk without an A/B helper' >&2; exit 1; }

cat > "$helper" <<'EOF'
#!/bin/sh
printf 'atomic %s\n' "$*" >> "$VEYRA_UPDATE_TEST_LOG"
EOF
chmod 0755 "$helper"
run_update --check
run_update
grep -Fqx 'atomic --check' "$log"
grep -Fqx 'atomic ' "$log"
if grep -q '^apk ' "$log"; then
  echo 'atomic update fell through to in-place apk' >&2
  exit 1
fi

rm -f "$log" "$mode_file"
run_update --check
run_update
grep -Fqx 'apk update' "$log"
grep -Fqx 'apk list -u' "$log"
grep -Fqx 'apk upgrade' "$log"

printf '%s\n' 'unknown-mode' > "$mode_file"
if run_update >"$tmp/unknown.out" 2>&1; then
  echo 'unknown deployment mode unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'unsupported deployment mode' "$tmp/unknown.out"

rm -f "$mode_file"
ln -s "$tmp/missing-mode" "$mode_file"
if run_update --check >"$tmp/symlink.out" 2>&1; then
  echo 'symlinked deployment mode unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'deployment mode path is unsafe' "$tmp/symlink.out"

echo 'veyra-update routes A/B installs safely and retains the legacy APK path'
