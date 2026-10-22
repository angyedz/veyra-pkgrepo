#!/bin/sh
set -eu
umask 077

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
source_dir=$root/src/veyra-root-bridge
tmp=$(mktemp -d)
created_pam_dir=0
created_veyra_dir=0
created_pam_service=0
created_policy=0
created_admin_group=0
created_admin_user=0
created_denied_group=0
created_denied_user=0
pam_service=/etc/pam.d/veyra-root-bridge
policy_file=/etc/veyra/root-admins
admin_user=veyra-rootbridge-admin
denied_user=veyra-rootbridge-denied
admin_password='Veyra-Root-Bridge-Test-2026!'

cleanup() {
	if [ "$created_pam_service" -eq 1 ]; then
		rm -f -- "$pam_service"
	fi
	if [ "$created_policy" -eq 1 ]; then
		rm -f -- "$policy_file"
	fi
	if [ "$created_pam_dir" -eq 1 ]; then
		rmdir /etc/pam.d 2>/dev/null || :
	fi
	if [ "$created_veyra_dir" -eq 1 ]; then
		rmdir /etc/veyra 2>/dev/null || :
	fi
	if [ "$created_admin_user" -eq 1 ]; then
		userdel "$admin_user" 2>/dev/null || :
	fi
	if [ "$created_admin_group" -eq 1 ]; then
		groupdel "$admin_user" 2>/dev/null || :
	fi
	if [ "$created_denied_user" -eq 1 ]; then
		userdel "$denied_user" 2>/dev/null || :
	fi
	if [ "$created_denied_group" -eq 1 ]; then
		groupdel "$denied_user" 2>/dev/null || :
	fi
	rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

fail() { echo "root bridge test failed: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v cc >/dev/null || fail "cc is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v useradd >/dev/null || fail "useradd is required"
command -v groupadd >/dev/null || fail "groupadd is required"
command -v chpasswd >/dev/null || fail "chpasswd is required"
[ ! -L /etc/pam.d ] || fail "/etc/pam.d must not be a symlink"
if [ ! -d /etc/pam.d ]; then
	mkdir -m 0755 /etc/pam.d
	created_pam_dir=1
fi
[ ! -e "$pam_service" ] && [ ! -L "$pam_service" ] ||
	fail "PAM service already exists; run before installing the package"
[ ! -e "$policy_file" ] && [ ! -L "$policy_file" ] ||
	fail "root-admin policy already exists; refusing to replace it"
if [ ! -d /etc/veyra ]; then
	[ ! -e /etc/veyra ] && [ ! -L /etc/veyra ] ||
		fail "/etc/veyra exists but is not a real directory"
	mkdir -m 0755 /etc/veyra
	created_veyra_dir=1
fi
[ "$(stat -c '%u:%g' /etc/veyra)" = "0:0" ] ||
	fail "/etc/veyra must be owned by root"
python3 -c 'import os,sys; sys.exit(1 if os.stat("/etc/veyra").st_mode & 0o022 else 0)' ||
	fail "/etc/veyra must not be group/world writable"

if getent passwd "$admin_user" >/dev/null ||
	getent group "$admin_user" >/dev/null ||
	getent passwd "$denied_user" >/dev/null ||
	getent group "$denied_user" >/dev/null; then
	fail "test account name is already allocated"
fi
test_uid=$((23000 + $$ % 1000))
if getent passwd "$test_uid" >/dev/null ||
	getent group "$test_uid" >/dev/null ||
	getent passwd "$((test_uid + 1))" >/dev/null ||
	getent group "$((test_uid + 1))" >/dev/null; then
	fail "test account UID/GID is already allocated"
fi

groupadd -g "$test_uid" "$admin_user"
created_admin_group=1
useradd -M -u "$test_uid" -g "$test_uid" -s /bin/sh "$admin_user"
created_admin_user=1
groupadd -g "$((test_uid + 1))" "$denied_user"
created_denied_group=1
useradd -M -u "$((test_uid + 1))" -g "$((test_uid + 1))" -s /bin/sh "$denied_user"
created_denied_user=1
printf '%s:%s\n%s:%s\n' "$admin_user" "$admin_password" \
	"$denied_user" "$admin_password" | chpasswd

cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -fPIC -shared -Wall -Wextra -Werror \
	-Wl,-z,relro,-z,now -o "$tmp/pam_veyra_root_admin.so" \
	"$source_dir/pam_veyra_root_admin.c" -lpam
cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -Wall -Wextra -Werror \
	-Wl,-z,relro,-z,now -o "$tmp/veyra-root-console" \
	"$source_dir/veyra-root-console.c" -lpam
cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra -Werror -fPIE -pie \
	-Wl,-z,relro,-z,now -o "$tmp/root-bridge-pam-test-driver" \
	"$root/tests/root-bridge-pam-test-driver.c" -lpam

if "$tmp/veyra-root-console" >"$tmp/console-output" 2>&1; then
	fail "console accepted a process without the dedicated system TTY"
fi
grep -q "trusted system console" "$tmp/console-output" ||
	fail "console did not explain rejection of an untrusted terminal"

created_pam_service=1
cat >"$pam_service" <<EOF
auth requisite pam_unix.so
account required pam_unix.so
account required $tmp/pam_veyra_root_admin.so
session required pam_unix.so
EOF
chmod 0644 "$pam_service"
created_policy=1
printf '%s\n' "$admin_user" > "$policy_file"
chown root:root "$policy_file"
chmod 0600 "$policy_file"

check_result() {
	expected=$1
	username=$2
	password=$3
	tty=$4
	actual=$(VEYRA_ROOT_BRIDGE_TEST_PASSWORD="$password" \
		"$tmp/root-bridge-pam-test-driver" "$username" "$tty")
	[ "$actual" = "$expected" ] ||
		fail "$username on $tty: expected $expected, got $actual"
}

check_result AUTH_REJECTED "$admin_user" 'incorrect-password' /dev/tty9
check_result AUTHENTICATED_AND_AUTHORIZED "$admin_user" "$admin_password" /dev/tty9
check_result AUTHENTICATED_BUT_DENIED "$denied_user" "$admin_password" /dev/tty9
check_result AUTHENTICATED_BUT_DENIED "$admin_user" "$admin_password" /dev/tty8

printf '%s\nroot\n' "$admin_user" > "$policy_file"
chown root:root "$policy_file"
chmod 0600 "$policy_file"
account_result=$("$tmp/root-bridge-pam-test-driver" account root /dev/tty9)
[ "$account_result" = "ACCOUNT_DENIED" ] ||
	fail "UID 0 was permitted as a direct administrator account"
printf '%s\n' "$admin_user" > "$policy_file"
chown root:root "$policy_file"

chmod 0644 "$policy_file"
check_result AUTHENTICATED_BUT_DENIED "$admin_user" "$admin_password" /dev/tty9
chmod 0600 "$policy_file"

cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -fPIC -shared -Wall -Wextra -Werror \
	-DVEYRA_ROOT_BRIDGE_TEST_TTY -Wl,-z,relro,-z,now \
	-o "$tmp/pam_veyra_root_admin-test.so" \
	"$source_dir/pam_veyra_root_admin.c" -lpam
cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -Wall -Wextra -Werror \
	-DVEYRA_ROOT_BRIDGE_TEST_TTY -DVEYRA_ROOT_BRIDGE_TEST_AUDIT_DIR \
	-DVEYRA_ROOT_BRIDGE_TEST_IDLE_TIMEOUT_SECONDS=5 \
	-Wl,-z,relro,-z,now -o "$tmp/veyra-root-console-e2e" \
	"$source_dir/veyra-root-console.c" -lpam
mkdir -m 0700 "$tmp/audit"
: > "$tmp/audit/root-bridge.log"
chmod 0600 "$tmp/audit/root-bridge.log"
cat >"$pam_service" <<EOF
auth requisite pam_unix.so
account required pam_unix.so
account required $tmp/pam_veyra_root_admin-test.so
session required pam_unix.so
EOF
chmod 0644 "$pam_service"
python3 "$root/tests/test-root-bridge-console.py" \
	"$tmp/veyra-root-console-e2e" "$tmp/audit" \
	"$admin_user" "$admin_password"

printf 'root bridge PAM rejects wrong passwords, non-admin and UID 0 accounts, untrusted TTYs, and writable policy files; the console authenticates, launches a clean root shell, audits, and expires idle sessions\n'
