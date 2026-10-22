# Veyra TTY session manager

This system-side package connects the PAM one-use grant to a minimal isolated
interactive TTY session. It is built for the mixed `veyra-pkgrepo`; the account
registry and per-account root provisioner remain separate packages.

Accounts remain ordinary system Linux accounts managed with the distribution's
account tools and system `/etc/passwd`/`/etc/shadow`. The registry enrolls an
eligible account and assigns its isolated UID range; PAM checks the system
password. The user's isolated root gets a separate locked account record and
never receives the system password verifier.

The flow is:

1. `/usr/sbin/veyra-login`, started by a root-owned terminal login service,
   authenticates the normal system account with the separate `veyra-login`
   PAM profile. PAM checks the system password and issues a one-use token.
2. The same login process changes to the authenticated account's real UID/GID
   while retaining the root effective ID needed for PAM cleanup. It sends the
   token over the local manager socket, preserving the PID, session ID, and
   controlling terminal to which PAM bound the grant.
3. The root-owned manager obtains the caller PID from `SO_PEERCRED`, consumes
   the grant against that PID, rechecks the terminal, provisions and verifies
   the account root, then starts the account's configured login shell in new
   user, mount, network, IPC, UTS, and PID namespaces. The persistent home is
   mounted separately. A private PTY relays terminal input and output.
4. The namespace launcher gives the inner session only one private
   `SOCK_SEQPACKET` descriptor for the fixed `ROOTREQ1` action. The bundled
   `veyra-root-request` client uses that descriptor; no host socket path,
   password, PAM token, TTY descriptor or command channel enters the user root.
5. The manager maps the request to the already authenticated outer account,
   checks root-bridge account policy through PAM, and accepts it only while the
   originating system VT is active. It serializes requests, applies a
   system-wide cooldown, switches to reserved VT9, starts the PAM console, and
   restores the original VT when the console exits.

The account name, UID mapping, rootfs path, home path, shell path, and launch
arguments are derived or validated by system-side code. The client cannot
choose another account, a filesystem path, a namespace mapping, or a command.
The system password verifier is never copied into the user root. The manager
clears the PAM token before entering its terminal relay.

The OpenRC service is installed as `/etc/init.d/veyra-session-manager` but is
not enabled by this package. The PAM frontend is installed at
`/usr/sbin/veyra-login`, but no getty is redirected to it automatically. An
administrator can attach it to a dedicated terminal getty after preparing the
dual-environment storage. The PAM profile is not added to global `login`,
SDDM, or SSH stacks here.

This is a TTY-only experimental launch path. It does not start OpenRC inside
the user root, start a graphical desktop, or integrate with a display manager.
The system-root request currently works only from an active local virtual
terminal; serial sessions are denied. The package CI QEMU test
now exercises two ordinary system accounts concurrently in distinct mapped
roots, rejects a wrong password, checks that an unlisted account cannot
request VT9, confirms the host block device and manager socket are hidden and
inner `sudo` is denied, and covers client disconnect, manager restart, logout,
relogin, and persistent per-account homes. This tests
the package launch path; it does not prove an installed Veyra image or real
hardware integration. The OpenRC service remains disabled by default and no
getty is redirected automatically. Independent security review and installed
image/display-manager integration are still required before this can become a
default login path.
