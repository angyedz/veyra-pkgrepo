# Veyra system-root console prototype

This package provides an experimental, password-gated system-root shell on
one dedicated **initial-system TTY**. It is not the user-environment request
broker described in Veyra's roadmap; no shell, terminal, PTY,
credential or control socket is exposed to the user environment. The trusted
console is the only path in this prototype, so a desktop-side bridge request
is still unfinished.

The console asks for an ordinary system account name and password. PAM checks
the system password and account state, then the root-owned
`/etc/veyra/root-admins` allowlist must authorize the account. The allowlist
contains one system account name per line; blank lines and lines beginning
with `#` are ignored. `root` and accounts with UID 0 are never eligible.
The policy file must remain owned by `root:root` with mode `0600`.

After authorization, the console starts `/bin/sh` as system UID/GID 0 in a
fresh PTY and clean environment. It audits attempts to syslog and the
root-owned `/var/log/veyra/root-bridge.log`. Successful access fails closed if
the audit file cannot be safely written. The shell ends after 15 minutes
without keyboard input; the relay signals the shell process group on timeout or
logout, closes the PAM session, and deletes its PAM credentials. Full cleanup of
detached descendants requires a system-owned cgroup/supervisor and remains a
required follow-up before the bridge can satisfy the design contract.

## Deliberately not enabled by installation

The package does not alter `/etc/inittab`, enable a service, change a global
PAM stack, or expose this login on SSH/SDDM. The example
`tty9-inittab.example` shows how to attach it to BusyBox getty on `/dev/tty9`.
Only configure that entry after the installed image guarantees that the user
environment cannot access `/dev/tty9`, host input devices, the system root,
or a path to observe or control the system console. The launcher independently
checks root identity, the initial UID/GID maps, and the exact `/dev/tty9`
controlling terminal; it rejects serial consoles and nested user namespaces.

This prototype still lacks a trusted desktop handoff/request flow, real
installed-image qualification, adversarial QEMU coverage, hardware-console
qualification and independent security review. It is not ready for default
enablement or a release security claim.
