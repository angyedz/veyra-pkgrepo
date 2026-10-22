# Veyra system-root console prototype

This package provides an experimental, password-gated system-root shell on
the dedicated **initial-system VT9**. The system-side TTY session manager
exposes one fixed request action to each managed user session through a private
descriptor. The user environment cannot choose the account, TTY, command,
path, environment, or descriptors for the system shell; it never sees the
root-console TTY or a privileged broker socket.

The console asks for an ordinary system account name and password. PAM checks
the system password and account state, then the root-owned
`/etc/veyra/root-admins` allowlist must authorize the account. The allowlist
contains one system account name per line; blank lines and lines beginning
with `#` are ignored. `root` and accounts with UID 0 are never eligible.
The policy file must remain owned by `root:root` with mode `0600`.

When the user session asks, the system manager verifies that its outer account
passes the same root-owned PAM allowlist, confirms the request came from the
active local virtual terminal, and switches to VT9. It starts this launcher
itself, then returns to the original VT after the console exits. The package
does not run a getty on VT9; keep that VT reserved for the broker.

After fresh PAM authentication, the console starts `/bin/sh` as system UID/GID
0 in a private PTY and clean environment. It audits attempts to syslog and the
root-owned `/var/log/veyra/root-bridge.log`. Successful access fails closed if
the audit file cannot be safely written. The shell ends after 15 minutes
without keyboard input; the relay signals the shell process group on timeout or
logout, closes the PAM session, and deletes its PAM credentials. Full cleanup of
detached descendants through a system-owned cgroup/supervisor remains required
before the bridge satisfies its security contract.

## Deliberately not enabled by installation

The package does not alter `/etc/inittab`, enable the session-manager service,
change a global PAM stack, or expose this login on SSH/SDDM. The session manager
owns VT9 only while processing an authorized local-session request. Do not add
a getty or another service to VT9. The launcher independently checks root
identity, the initial UID/GID maps, and the exact `/dev/tty9` controlling
terminal; it rejects serial consoles and nested user namespaces.

The current request path serves managed local TTY sessions. A Plasma/Wayland
desktop control surface, installed-image qualification, adversarial QEMU
coverage, hardware-console qualification, cgroup cleanup and independent
security review remain open. The service stays disabled by default and is not
ready for a release security claim.
