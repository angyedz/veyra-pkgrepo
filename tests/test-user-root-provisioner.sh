#!/bin/sh
set -eu

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
source_file=$root/src/veyra-user-root-provisioner/veyra-user-root-provisioner
tmp=$(mktemp -d)
store=$tmp/store
template=$tmp/template
registry=$tmp/bin/veyra-account-registry
script=$tmp/bin/veyra-user-root-provisioner
lock_dir=$tmp/run/veyra-user-root-provisioner

cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT
fail() { echo "user root provisioner test failed: $*" >&2; exit 1; }
expect_fail() {
    if "$@" >"$tmp/failure.out" 2>&1; then fail "command unexpectedly succeeded: $*"; fi
}

[ "$(id -u)" -eq 0 ] || fail "must run as root to verify mapped ownership"
command -v flock >/dev/null || fail "flock is required"
mkdir -p "$tmp/bin" "$tmp/run" "$template/sbin" "$template/usr/bin" \
    "$template/etc/sudoers.d" "$template/home/veyrauser" "$template/var/lib"
mkdir -p "$store"
cat >"$registry" <<'EOF'
#!/bin/sh
[ "$1" = resolve ] || exit 2
case "$2" in
    alice) printf 'resolved\talice\t23101\t23101\t300000\n' ;;
    bob) printf 'resolved\tbob\t23102\t23102\t400000\n' ;;
    retired) exit 1 ;;
    *) exit 1 ;;
esac
EOF
chmod 0755 "$registry"
cp "$source_file" "$script"
sed -i \
    -e "s|^store=/var/lib/veyra-user-store$|store=$store|" \
    -e "s|^template=/usr/share/veyra/user-root-template$|template=$template|" \
    -e "s|^registry=/usr/sbin/veyra-account-registry$|registry=$registry|" \
    -e "s|^lock_dir=/run/veyra-user-root-provisioner$|lock_dir=$lock_dir|" \
    "$script"
chmod 0755 "$script"

printf '%s\n' 'VEYRA-USER-ROOT-TEMPLATE 1' >"$template/.veyra-user-template"
chmod 0644 "$template/.veyra-user-template"
printf '%s\n' '#!/bin/sh' 'exec /bin/sh' >"$template/sbin/init"
chmod 0755 "$template/sbin/init"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$template/usr/bin/sudo"
chmod 0755 "$template/usr/bin/sudo"
cat >"$template/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
veyrauser:x:1000:1000:Veyra User:/home/veyrauser:/bin/sh
EOF
cat >"$template/etc/shadow" <<'EOF'
root:!:1:0:99999:7:::
veyrauser:$6$template-only-hash:1:0:99999:7:::
EOF
cat >"$template/etc/group" <<'EOF'
root:x:0:
veyrauser:x:1000:
wheel:x:10:veyrauser
EOF
cat >"$template/etc/gshadow" <<'EOF'
root:!::
veyrauser:!::
wheel:!::veyrauser
EOF
printf '%s\n' '# %wheel ALL=(ALL:ALL) NOPASSWD: ALL' 'root ALL=(ALL:ALL) ALL' >"$template/etc/sudoers"
printf '%s\n' 'export VEYRA_TEMPLATE_HOME=present' >"$template/home/veyrauser/.profile"

output=$("$script" provision alice)
[ "$output" = "provisioned$(printf '\t')alice$(printf '\t')300000" ] ||
    fail "first provision did not publish the expected account"
output=$("$script" verify alice)
[ "$output" = "verified$(printf '\t')alice$(printf '\t')300000" ] ||
    fail "provisioned account did not verify"
account_dir=$store/users/alice
[ "$(stat -c '%u:%g:%a' "$account_dir")" = '0:0:700' ] || fail "account parent is not system-root-only"
[ "$(stat -c '%u:%g:%a' "$account_dir/rootfs")" = '300000:301000:710' ] ||
    fail "rootfs did not receive the mapped root and user identity"
[ "$(stat -c '%u:%g:%a' "$account_dir/home")" = '301000:301000:700' ] ||
    fail "home did not receive the mapped user identity"
grep -q '^alice:x:1000:1000:Veyra User:/home/alice:/bin/sh$' "$account_dir/rootfs/etc/passwd" ||
    fail "inner passwd identity was not renamed"
grep -q '^alice:x:1000:$' "$account_dir/rootfs/etc/group" ||
    fail "inner primary group was not renamed"
grep -q '^wheel:x:10:alice$' "$account_dir/rootfs/etc/group" ||
    fail "supplementary group membership was not renamed"
grep -q '^alice:!::$' "$account_dir/rootfs/etc/gshadow" ||
    fail "inner group shadow identity was not renamed"
grep -q '^wheel:!::alice$' "$account_dir/rootfs/etc/gshadow" ||
    fail "inner group shadow membership was not renamed"
grep -q '^alice:!:1:0:' "$account_dir/rootfs/etc/shadow" ||
    fail "inner password verifier was not discarded and locked"
[ -f "$account_dir/home/.profile" ] || fail "home skeleton was not copied to separate persistent storage"
[ -d "$account_dir/rootfs/home/alice" ] || fail "rootfs home mountpoint was not created"
[ ! -e "$account_dir/rootfs/home/veyrauser" ] || fail "template home was left inside the user root"
[ "$(stat -c '%a' "$account_dir/rootfs/usr/bin/sudo")" = '4755' ] || fail "inner sudo lost its namespace-local setuid mode"

printf '%s\n' 'persistent-state' >"$account_dir/home/state"
output=$("$script" provision alice)
[ "$output" = "already-provisioned$(printf '\t')alice$(printf '\t')300000" ] ||
    fail "repeat provision was not idempotent"
[ "$(cat "$account_dir/home/state")" = 'persistent-state' ] || fail "repeat provision changed existing home data"
expect_fail "$script" provision retired
expect_fail "$script" provision ../alice
[ ! -e "$store/users/bob" ] || fail "failed provisioning published another account"

cp "$account_dir/account.v1" "$tmp/account.v1.saved"
printf '%s\n' 'forged' >"$account_dir/account.v1"
expect_fail "$script" verify alice
mv "$tmp/account.v1.saved" "$account_dir/account.v1"

printf '%s\n' 'alice ALL=(ALL:ALL) NOPASSWD: ALL' >"$template/etc/sudoers.d/fixture"
expect_fail "$script" provision bob
[ ! -e "$store/users/bob" ] || fail "fixture NOPASSWD policy was published"

echo 'Veyra user-root provisioning, mapping, isolation paths and idempotence passed'
