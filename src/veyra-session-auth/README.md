# Veyra session authentication gate

This package adds a PAM account check and a one-use grant for a future system
TTY session broker. It is a system-side package in the mixed `veyra-pkgrepo`.

The dedicated `/etc/pam.d/veyra-login` profile first asks `pam_unix` to
authenticate against the system account database. Only after PAM reaches
account/session processing does `pam_veyra_session.so` call
`veyra-account-registry resolve USER` again. It requires the service name
`veyra-login`, a current eligible registry record, and a controlling terminal
whose session ID matches the PAM process. It does not read, copy, or export the
system password verifier.

When PAM opens the session, the module creates a random 256-bit token under
`/run/veyra-session-auth`, owned by root with mode `0600`. The grant records the
authenticated account and UID/GID mapping, PAM process ID and start time,
terminal device, login session ID, and a 120-second monotonic expiry. The token
is added to the PAM environment for the login program. PAM close/cleanup removes
an unused grant.

The future root-owned session manager must obtain the connecting process ID
from `SO_PEERCRED`, then invoke:

```text
veyra-session-grant consume TOKEN PEER_PID
```

The root-only consumer checks the unguessable one-use token, expiry, a live
pidfd-pinned process identity, process start time, real system UID/GID, session
ID, and terminal device; re-resolves the account and mapping through the
registry; atomically removes the grant; and emits one tab-separated
`authorized` record. It accepts no command, shell, mount path, mapping, or
username from the login process. A different PID or a second consumption fails.
The process checks require Linux `pidfd_open` and `close_range`; Veyra's current
6.12 LTS kernel provides both. Registry lookups run with only standard input,
the captured output pipe, and standard error open; inability to close inherited
descriptors fails closed.

The package build is checked against Alpine 3.22 with warnings treated as
errors. `tests/test-session-auth.sh` runs the PAM account and session hooks
through a real PTY, using `pam_permit` only as a test authentication backend.
It checks wrong-PID rejection, mapping revalidation, one-use consumption, and
monotonic expiry. These tests cover the PAM grant primitive only; they do not
prove an installed login broker or user-root session manager.

The PAM service is deliberately separate. This package does not change the
global `login`, SSH, or SDDM PAM stacks, change account shells, launch a user
root, provide the OpenRC session manager, or enable the Dual Environment
installer profile. The session manager and its TTY/QEMU integration must be
implemented and reviewed before wiring this profile into an installed login
path. The system-root password bridge and its separate trusted prompt remain a
different, disabled feature.
