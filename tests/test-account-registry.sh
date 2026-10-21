#!/bin/sh
set -eu

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
source_file=$root/src/veyra-account-registry/veyra-account-registry.c
tmp=$(mktemp -d)
store=$tmp/store
binary=$tmp/veyra-account-registry
created_wheel=0
created_sudo=0
created_policy=0
policy_file=/etc/sudoers.d/veyra-account-registry-test
tab=$(printf '\t')

cleanup() {
    if [ "$created_policy" -eq 1 ]; then rm -f "$policy_file"; fi
    for name in veyratestalpha veyratestbeta veyratestgamma veyratestdelta \
                veyratestepsilon veyratestwheel veyratestsudo veyratestshell \
                veyratestlocked veyratestdirect; do
        userdel "$name" >/dev/null 2>&1 || :
    done
    for gid in 23101 23102 23103 23104 23105 23106 23107 23108 23109 23110; do
        groupdel "veyra-test-$gid" >/dev/null 2>&1 || :
    done
    if [ "$created_wheel" -eq 1 ]; then groupdel wheel >/dev/null 2>&1 || :; fi
    if [ "$created_sudo" -eq 1 ]; then groupdel sudo >/dev/null 2>&1 || :; fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

fail() { echo "account registry test failed: $*" >&2; exit 1; }
expect_fail() {
    if "$@" >"$tmp/expected-failure.log" 2>&1; then
        fail "command unexpectedly succeeded: $*"
    fi
}

[ "$(id -u)" -eq 0 ] || fail "must run as root to exercise system-account checks"
for command_name in useradd userdel groupadd groupdel usermod chpasswd passwd \
                   sudo visudo; do
    command -v "$command_name" >/dev/null || fail "$command_name is required"
done

cc -std=c11 -D_FORTIFY_SOURCE=2 -DVEYRA_REGISTRY_TESTING -O2 \
    -Wall -Wextra -Werror -Wl,-z,relro,-z,now \
    -o "$binary" "$source_file"
mkdir -m 0700 "$store"

create_user() {
    name=$1
    uid=$2
    gid=$3
    shell=$4
    groupadd -g "$gid" "veyra-test-$gid"
    useradd -M -u "$uid" -g "$gid" -s "$shell" "$name"
    printf '%s:%s\n' "$name" 'Veyra-Test-Only-Password-97' | chpasswd
}

create_user veyratestalpha 23101 23101 /sbin/nologin
create_user veyratestbeta 23102 23102 /sbin/nologin
create_user veyratestgamma 23103 23103 /sbin/nologin
create_user veyratestdelta 23104 23104 /sbin/nologin
create_user veyratestepsilon 23105 23105 /sbin/nologin
create_user veyratestwheel 23106 23106 /sbin/nologin
create_user veyratestshell 23107 23107 /bin/sh
create_user veyratestlocked 23108 23108 /sbin/nologin
create_user veyratestsudo 23109 23109 /sbin/nologin
create_user veyratestdirect 23110 23110 /sbin/nologin
passwd -l veyratestlocked >/dev/null

if ! grep -q '^wheel:' /etc/group; then
    groupadd wheel
    created_wheel=1
fi
usermod -a -G wheel veyratestwheel
if ! grep -q '^sudo:' /etc/group; then
    groupadd sudo
    created_sudo=1
fi
usermod -a -G sudo veyratestsudo
export VEYRA_TEST_STORE=$store

output=$("$binary" enroll veyratestalpha)
[ "$output" = "enrolled${tab}veyratestalpha${tab}23101:23101${tab}300000" ] || \
    fail "first enrollment did not receive the initial range"
output=$("$binary" enroll veyratestalpha)
[ "$output" = "already-enrolled${tab}veyratestalpha${tab}300000" ] || \
    fail "repeat enrollment was not idempotent"
output=$("$binary" resolve veyratestalpha)
[ "$output" = "resolved${tab}veyratestalpha${tab}23101${tab}23101${tab}300000" ] || \
    fail "active account did not resolve to its stored identity and range"
output=$("$binary" enroll veyratestbeta)
[ "$output" = "enrolled${tab}veyratestbeta${tab}23102:23102${tab}400000" ] || \
    fail "second enrollment did not receive the next range"

"$binary" enroll veyratestgamma >"$tmp/gamma.out" 2>&1 & gamma_pid=$!
"$binary" enroll veyratestdelta >"$tmp/delta.out" 2>&1 & delta_pid=$!
wait "$gamma_pid" || fail "concurrent gamma enrollment failed"
wait "$delta_pid" || fail "concurrent delta enrollment failed"
gamma_base=$(awk -F '\t' '{ print $4 }' "$tmp/gamma.out")
delta_base=$(awk -F '\t' '{ print $4 }' "$tmp/delta.out")
[ "$gamma_base" != "$delta_base" ] || fail "concurrent enrollments reused a range"
concurrent_bases=$(printf '%s\n%s\n' "$gamma_base" "$delta_base" | sort -n | tr '\n' ' ')
[ "$concurrent_bases" = "500000 600000 " ] || \
    fail "concurrent enrollments skipped or reused a range"

output=$("$binary" retire veyratestbeta)
[ "$output" = "retired${tab}veyratestbeta${tab}400000" ] || \
    fail "retirement did not preserve the reservation"
expect_fail "$binary" resolve veyratestbeta
output=$("$binary" enroll veyratestepsilon)
[ "$output" = "enrolled${tab}veyratestepsilon${tab}23105:23105${tab}700000" ] || \
    fail "retired range was reused"

expect_fail "$binary" enroll veyratestwheel
expect_fail "$binary" enroll veyratestsudo
expect_fail "$binary" enroll veyratestshell
expect_fail "$binary" enroll veyratestlocked
expect_fail "$binary" enroll ../veyra-test
expect_fail "$binary" retire veyratestwheel

usermod -a -G wheel veyratestalpha
expect_fail "$binary" resolve veyratestalpha
usermod -G '' veyratestalpha
output=$("$binary" resolve veyratestalpha)
[ "$output" = "resolved${tab}veyratestalpha${tab}23101${tab}23101${tab}300000" ] || \
    fail "account did not resolve after its host privilege group was removed"
usermod -u 23111 veyratestalpha
expect_fail "$binary" resolve veyratestalpha
usermod -u 23101 veyratestalpha
output=$("$binary" resolve veyratestalpha)
[ "$output" = "resolved${tab}veyratestalpha${tab}23101${tab}23101${tab}300000" ] || \
    fail "account did not resolve after its original system UID was restored"

[ ! -e "$policy_file" ] || fail "sudo policy test path already exists"
created_policy=1
printf '%s ALL=(ALL:ALL) ALL\n' veyratestdirect >"$policy_file"
chown root:root "$policy_file"
chmod 0440 "$policy_file"
visudo -c >/dev/null 2>&1 || fail "test sudoers entry is invalid"
expect_fail "$binary" enroll veyratestdirect
rm "$policy_file"
created_policy=0
visudo -c >/dev/null 2>&1 || fail "sudoers policy was not restored"
output=$("$binary" enroll veyratestdirect)
[ "$output" = "enrolled${tab}veyratestdirect${tab}23110:23110${tab}800000" ] || \
    fail "direct-policy test account did not enroll before privilege grant"
created_policy=1
printf '%s ALL=(ALL:ALL) ALL\n' veyratestdirect >"$policy_file"
chown root:root "$policy_file"
chmod 0440 "$policy_file"
visudo -c >/dev/null 2>&1 || fail "second sudoers entry is invalid"
expect_fail "$binary" resolve veyratestdirect
rm "$policy_file"
created_policy=0
visudo -c >/dev/null 2>&1 || fail "sudoers policy was not restored after resolution check"

registry=$store/registry/accounts.v1
grep -Fq "retired${tab}veyratestbeta${tab}23102${tab}23102${tab}400000" \
    "$registry" || fail "retired account or its range was not retained"
grep -q 'Veyra-Test-Only-Password-97' "$registry" && \
    fail "plaintext test credential leaked into registry"
alpha_hash=$(awk -F: '$1 == "veyratestalpha" { print $2 }' /etc/shadow)
[ -n "$alpha_hash" ] || fail "test account password verifier was not created"
grep -Fq "$alpha_hash" "$registry" && \
    fail "system password verifier leaked into registry"

chmod 0644 "$registry"
expect_fail "$binary" list
chmod 0600 "$registry"
mv "$registry" "$tmp/accounts.saved"
ln -s /etc/passwd "$registry"
expect_fail "$binary" list
rm "$registry"
mv "$tmp/accounts.saved" "$registry"

printf 'VEYRA-USER-REGISTRY\t1\t800000\nactive\tvey ratatestalpha\t23101\t23101\t300000\n' \
    >"$tmp/corrupt"
chmod 0600 "$tmp/corrupt"
mv "$tmp/corrupt" "$registry"
expect_fail "$binary" list

printf 'VEYRA-USER-REGISTRY\t1\t700000\nactive\tveyratestalpha\t23101\t23101\t300000\nactive\tveyratestbeta\t23102\t23102\t300000\n' \
    >"$tmp/corrupt"
chmod 0600 "$tmp/corrupt"
mv "$tmp/corrupt" "$registry"
expect_fail "$binary" list

printf 'VEYRA-USER-REGISTRY\t1\t800000\nactive\tveyratestalpha\000ignored\t23101\t23101\t300000\n' \
    >"$tmp/corrupt"
chmod 0600 "$tmp/corrupt"
mv "$tmp/corrupt" "$registry"
expect_fail "$binary" list

echo 'Veyra account registry allocation, locking, retirement and fail-closed checks passed'
