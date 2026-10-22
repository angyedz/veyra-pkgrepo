#!/bin/sh
set -eu

root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
source_file=$root/src/veyra-session-manager/veyra-session-manager.c
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:-} -O2 -std=c11 -D_FORTIFY_SOURCE=2 \
    -fPIE -pie -Wall -Wextra -Werror \
    -Wl,-z,relro,-z,now -o "$tmp/veyra-session-manager" "$source_file" -lpam

"$tmp/veyra-session-manager" self-test
cp "$tmp/veyra-session-manager" "$tmp/veyra-session-login"
if env -u VEYRA_SESSION_TOKEN "$tmp/veyra-session-login" >"$tmp/output" 2>&1; then
    echo "session manager test failed: login without a PAM grant was accepted" >&2
    exit 1
fi
grep -q 'no valid PAM session grant' "$tmp/output"
echo "session manager missing-grant check passed"
cp "$tmp/veyra-session-manager" "$tmp/veyra-login"
if "$tmp/veyra-login" </dev/null >"$tmp/output" 2>&1; then
    echo "session manager test failed: login frontend accepted a non-interactive session" >&2
    exit 1
fi
grep -q 'interactive terminal is required' "$tmp/output"
echo "PAM login frontend terminal check passed"
