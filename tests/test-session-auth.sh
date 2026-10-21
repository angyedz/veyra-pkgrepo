#!/bin/sh
set -eu
umask 077

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
source_dir=$root/src/veyra-session-auth
runtime_dir=/run/veyra-session-auth-test
tmp=$(mktemp -d)
created_runtime_dir=0

cleanup() {
    if [ "$created_runtime_dir" -eq 1 ]; then
        rm -rf -- "$runtime_dir"
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

fail() { echo "session auth test failed: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v cc >/dev/null || fail "cc is required"
command -v python3 >/dev/null || fail "python3 is required"
grep -q '^nobody:[^:]*:65534:65534:' /etc/passwd ||
    fail "the nobody account with UID/GID 65534 is required"
[ ! -e "$runtime_dir" ] && [ ! -L "$runtime_dir" ] ||
    fail "test runtime directory already exists"
mkdir -m 0700 "$runtime_dir"
created_runtime_dir=1

registry=$tmp/veyra-account-registry
cat >"$registry" <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = resolve ] && [ "$2" = nobody ] || exit 2
base=300000
if [ -f /run/veyra-session-auth-test/mapping ]; then
    IFS= read -r base < /run/veyra-session-auth-test/mapping
fi
case "$base" in 300000|400000) ;; *) exit 1 ;; esac
printf 'resolved\tnobody\t65534\t65534\t%s\n' "$base"
EOF
chmod 0700 "$registry"

cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra -Werror -fPIE -pie \
    "-DREGISTRY_PATH=\"$registry\"" \
    '-DVEYRA_SESSION_GRANT_SUBDIR="veyra-session-auth-test"' \
    -DVEYRA_SESSION_GRANT_TTL_SECONDS=1 -I "$source_dir" \
    -o "$tmp/session-auth-test-driver" \
    "$root/tests/session-auth-test-driver.c" "$source_dir/session-grant.c"
cc -std=c11 -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra -Werror -fPIE -pie \
    "-DREGISTRY_PATH=\"$registry\"" \
    '-DVEYRA_SESSION_GRANT_SUBDIR="veyra-session-auth-test"' \
    -DVEYRA_SESSION_GRANT_TTL_SECONDS=1 -DVEYRA_SESSION_AUTH_DEBUG \
    -Wl,-z,relro,-z,now \
    -o "$tmp/veyra-session-grant" \
    "$source_dir/veyra-session-grant.c" "$source_dir/session-grant.c"

python3 "$root/tests/test-session-auth.py" \
    "$tmp/session-auth-test-driver" "$tmp/veyra-session-grant" \
    "$runtime_dir/mapping"
